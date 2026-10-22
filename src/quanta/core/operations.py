"""Operations on crypto objects (ruleset v3, round four).

Static detection finds where an algorithm is chosen: ``Ed25519PrivateKey.generate()``,
``ssl.create_default_context()``, ``Cipher(algorithms.AES(k), modes.CBC(iv))``. The code
then *uses* those objects somewhere else: ``key.sign(data)``, ``ctx.wrap_socket(sock)``,
``cipher.decryptor()``. Those operations are where a migration has to touch the code too,
and round three missed them (the pyjwt trace found 10 of 25 executed lines only as method
calls on key objects).

This pass runs after the main visitor, on the same parsed module. It follows crypto
objects through a file, flow-insensitively:

* a variable, ``self`` attribute or module name assigned from a detected crypto call;
* a parameter or attribute annotated with a crypto type (``key: Ed25519PrivateKey``);
* the return value of a function, method or property that returns a crypto object;
* objects derived from one (``priv.public_key()``, ``signing_key.verify_key``,
  ``cipher.encryptor()``).

A call of an operation method (sign, verify, encrypt, decrypt, exchange, derive,
encryptor, decryptor, wrap_socket, wrap_bio) on such an object is reported as an
``operation`` site. It inherits the producer's algorithm and category. Operation sites are
inventory only (``scored=False``): the agility score keeps measuring where algorithms are
chosen, which is what its formulas were validated on.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass

import libcst as cst
from libcst.metadata import PositionProvider, QualifiedNameProvider

from quanta.core.models import CryptoSite
from quanta.core.ruleset_v2 import ALGORITHMS, CRYPTO_MODULE_PREFIXES, RULES

#: Operation method -> the category the site takes (None: inherit the producer's).
OPERATIONS: dict[str, str | None] = {
    "sign": "signature",
    "verify": "signature",
    "verify_signature": "signature",
    "sign_digest": "signature",
    "encrypt": None,
    "decrypt": None,
    "encryptor": "cipher",
    "decryptor": "cipher",
    "exchange": "key_agreement",
    "derive": "kdf",
    "wrap_socket": "tls",
    "wrap_bio": "tls",
    "fingerprint": "hash",
    # Round six: PyJWT's JWKS client fetches the key that verifies a token.
    "get_signing_key_from_jwt": "key_loading",
    "get_signing_key": "key_loading",
    "get_signing_keys": "key_loading",
    # Round six: python-gnupg's keyring operations.
    "gen_key": "key_generation",
    "import_keys": "key_loading",
    "sign_file": "signature",
    "verify_file": "signature",
    "verify_data": "signature",
    "encrypt_file": None,
    "decrypt_file": None,
    # Round eight (PROTOCOL-R8 B2c): settings on a TLS context.
    "load_cert_chain": "tls",
    "load_verify_locations": "tls",
    "load_default_certs": "tls",
    "set_ciphers": "tls",
    # Round eight (PROTOCOL-R8 B2a): exporting a key or deriving its public key. Reported only
    # on objects followed from a crypto call, so the generic names are safe.
    **dict.fromkeys(
        (
            "private_bytes",
            "public_bytes",
            "private_bytes_raw",
            "public_bytes_raw",
            "export_key",
            "exportKey",
            "publickey",
            "to_pem",
            "to_der",
            "to_string",
            "get_verifying_key",
            "as_dict",
            "as_pem",
            "as_der",
            "as_bytes",
            "save_pkcs1",
            # round nine: asyncssh key objects, and the numbers behind a key (H8 misses)
            "export_private_key",
            "export_public_key",
            "write_private_key",
            "write_public_key",
            "public_numbers",
            "private_numbers",
            "parameters",
        ),
        "key_loading",
    ),
    # Round nine: more TLS context settings, a DH parameter object's key generation, and
    # passlib's CryptContext (H8 misses).
    "set_alpn_protocols": "tls",
    "set_ecdh_curve": "tls",
    "load_dh_params": "tls",
    "generate_private_key": "key_generation",
    "hash": None,
    "verify_and_update": None,
    # itsdangerous serializers sign on dumps and verify on loads (coverage gap)
    "dumps": None,
    "loads": None,
    # Round nine (PROTOCOL-R9 B2g): upgrading a protocol client's connection to TLS.
    "starttls": "tls",
    "start_tls": "tls",
    "start_tls_s": "tls",
    "startTLS": "tls",
    "stls": "tls",
}

#: Operations named only by the TLS API, reported even when the object cannot be followed
#: (round six: ``sslcontext.wrap_bio(...)`` on a parameter was the round-three miss).
TLS_ONLY = {
    "wrap_socket",
    "wrap_bio",
    "load_cert_chain",
    "load_verify_locations",
    "load_default_certs",
    "set_ciphers",
    # round nine
    "set_alpn_protocols",
    "set_ecdh_curve",
    "load_dh_params",
    "starttls",
    "start_tls_s",
    "startTLS",
    "stls",
}
# ``start_tls`` is left to followed objects: async networking code often defines its own
# stream class with that method (a dev-set false positive in httpx2).

#: Round nine: builder steps that return the same builder, and what ``sign`` returns, so a
#: certificate built in one chained expression is followed to the certificate.
BUILDER_STEPS = {
    "subject_name",
    "issuer_name",
    "public_key",
    "serial_number",
    "not_valid_before",
    "not_valid_after",
    "add_extension",
    "add_attribute",
    "last_update",
    "next_update",
    "add_revoked_certificate",
}
BUILT = (
    ("CertificateSigningRequestBuilder", "cryptography.x509.CertificateSigningRequest"),
    ("CertificateRevocationListBuilder", "cryptography.x509.CertificateRevocationList"),
    ("CertificateBuilder", "cryptography.x509.Certificate"),
)

#: Methods that turn one key object into another: materialising a key from raw numbers
#: (``RSAPrivateNumbers(...).private_key()``) or, since round eight (PROTOCOL-R8 B2a),
#: deriving a public key from a key object (``priv.public_key()``). Both are reported.
MATERIALISE = {"private_key", "public_key"}

#: Methods and attributes that return another crypto object from one.
DERIVING = {
    "public_key",
    "private_key",
    "verify_key",
    "encryptor",
    "decryptor",
    "signer",
    "verifier",
    # round eight: PyCryptodome and python-ecdsa spell the public half differently
    "publickey",
    "get_verifying_key",
    "verifying_key",
    # round nine: DH parameter numbers -> parameters -> private key
    "parameters",
    "generate_private_key",
}

#: Producer categories whose objects carry operations. Hash objects are left out: their
#: methods (update, digest) are not operations, and the codebook excludes them.
PRODUCERS = {
    "signature",
    "key_generation",
    "key_loading",
    "key_agreement",
    "cipher",
    "aead",
    "tls",
    "mac",
    "kdf",
    "token",
    "pq_kem",
    "pq_signature",
    "certificate",
}


@dataclass(frozen=True)
class Taint:
    qualified_name: str
    category: str | None
    algorithms: tuple[str, ...]


def _annotation_taint(name: str) -> Taint | None:
    """A crypto type named in an annotation, as the object it describes."""
    if not name.startswith(CRYPTO_MODULE_PREFIXES):
        return None
    algorithms: list[str] = []
    category: str | None = None
    prefix = name + "."
    for rule_name, rule in RULES.items():
        if rule_name == name or rule_name.startswith(prefix):
            category = category or rule.category
            if rule.algorithm and rule.algorithm not in algorithms:
                algorithms.append(rule.algorithm)
    if category is None:
        category = "key_loading"
    return Taint(name, category, tuple(algorithms[:1]))


class _Scopes(cst.CSTVisitor):
    """First pass: record every binding, return and operation candidate with its scope."""

    METADATA_DEPENDENCIES = (QualifiedNameProvider, PositionProvider)

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, str]] = []  # ("class"|"def", name)
        #: (scope key, target key, value expression)
        self.assignments: list[tuple[str, str, cst.BaseExpression]] = []
        #: (function key, value expression)
        self.returns: list[tuple[str, cst.BaseExpression]] = []
        #: (scope key, target key, annotation qualified names)
        self.annotated: list[tuple[str, str, set[str]]] = []
        #: (scope key, call node, line, column)
        self.candidates: list[tuple[str, cst.Call, int, int]] = []
        #: node id -> scope key, for evaluating expressions later
        self.scope_of: dict[int, str] = {}
        self.classes_of_scope: dict[str, str | None] = {}

    # scope keys ------------------------------------------------------------------
    def _class(self) -> str | None:
        for kind, name in reversed(self.stack):
            if kind == "class":
                return name
        return None

    def _scope(self) -> str:
        return ".".join(name for _, name in self.stack) or "<module>"

    def visit_ClassDef(self, node: cst.ClassDef) -> bool:
        self.stack.append(("class", node.name.value))
        return True

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        self.stack.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        owner = self._class()
        self.stack.append(("def", node.name.value))
        scope = self._scope()
        self.classes_of_scope[scope] = owner
        for param in [*node.params.params, *node.params.kwonly_params, *node.params.posonly_params]:
            if param.annotation is not None:
                names = self._names(param.annotation.annotation)
                if names:
                    self.annotated.append((scope, f"name:{param.name.value}", names))
        if node.returns is not None:
            names = self._names(node.returns.annotation)
            if names:
                self.annotated.append((scope, "return", names))
        return True

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        self.stack.pop()

    def _names(self, node: cst.CSTNode) -> set[str]:
        found: set[str] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            with contextlib.suppress(KeyError):
                found |= {q.name for q in self.get_metadata(QualifiedNameProvider, current, set())}
            stack.extend(current.children)
        return {n for n in found if n.startswith(CRYPTO_MODULE_PREFIXES)}

    def _target_key(self, target: cst.BaseExpression) -> str | None:
        if isinstance(target, cst.Name):
            return f"name:{target.value}"
        if (
            isinstance(target, cst.Attribute)
            and isinstance(target.value, cst.Name)
            and target.value.value in {"self", "cls", self._class()}
        ):
            # Round nine: ``JwtAuth._jwks_client = PyJWKClient(...)`` inside JwtAuth, read
            # later as ``self._jwks_client`` (an H8 miss), binds the same class attribute.
            return f"self:{target.attr.value}"
        return None

    def _record(self, target: cst.BaseExpression, value: cst.BaseExpression | None) -> None:
        key = self._target_key(target)
        if key is None or value is None:
            return
        self.assignments.append((self._scope(), key, value))

    def visit_Assign(self, node: cst.Assign) -> bool:
        for target in node.targets:
            self._record(target.target, node.value)
        return True

    def visit_AnnAssign(self, node: cst.AnnAssign) -> bool:
        key = self._target_key(node.target)
        if key is not None:
            names = self._names(node.annotation.annotation)
            if names:
                self.annotated.append((self._scope(), key, names))
        self._record(node.target, node.value)
        return True

    def visit_NamedExpr(self, node: cst.NamedExpr) -> bool:
        self._record(node.target, node.value)
        return True

    def visit_Return(self, node: cst.Return) -> bool:
        if node.value is not None and self.stack and self.stack[-1][0] == "def":
            self.returns.append((self._scope(), node.value))
        return True

    def visit_Call(self, node: cst.Call) -> bool:
        self.scope_of[id(node)] = self._scope()
        func = node.func
        if isinstance(func, cst.Attribute) and (
            func.attr.value in OPERATIONS or func.attr.value in MATERIALISE
        ):
            try:
                # Round nine: the operation is reported where its name is written, so the
                # ``.sign(...)`` that ends a chain over several lines gets its own line.
                pos = self.get_metadata(PositionProvider, func.attr).start
                line, col = pos.line, pos.column
            except KeyError:
                line, col = 0, 0
            self.candidates.append((self._scope(), node, line, col))
        return True


class _Taints:
    """Fixed-point evaluation of which expressions hold crypto objects."""

    def __init__(self, scopes: _Scopes, producers: dict[int, CryptoSite]) -> None:
        self.s = scopes
        self.producers = producers
        self.bindings: dict[tuple[str, str], Taint] = {}
        self.returns: dict[str, Taint] = {}

    # keys: locals and parameters live in the function scope, self attributes in the
    # class, module names in "<module>".
    def _binding_scope(self, scope: str, key: str) -> str:
        if key.startswith("self:"):
            owner = self.s.classes_of_scope.get(scope)
            return f"class:{owner}" if owner else scope
        return scope

    def _lookup(self, scope: str, key: str) -> Taint | None:
        if key.startswith("self:"):
            return self.bindings.get((self._binding_scope(scope, key), key)) or self._method(
                scope, key[5:]
            )
        found = self.bindings.get((scope, key))
        if found:
            return found
        parts = scope.split(".")
        while len(parts) > 1:  # enclosing functions, then the module
            parts.pop()
            found = self.bindings.get((".".join(parts), key))
            if found:
                return found
        return self.bindings.get(("<module>", key)) or self.returns.get(key[5:])

    def _method(self, scope: str, name: str) -> Taint | None:
        owner = self.s.classes_of_scope.get(scope)
        if owner is None:
            return None
        return self.returns.get(f"{owner}.{name}")

    def taint(self, scope: str, expr: cst.BaseExpression) -> Taint | None:
        if id(expr) in self.producers:
            site = self.producers[id(expr)]
            if site.category in PRODUCERS:
                return Taint(site.qualified_name, site.category, site.algorithms)
            return None
        if isinstance(expr, cst.Await):
            return self.taint(scope, expr.expression)
        if isinstance(expr, cst.Name):
            return self._lookup(scope, f"name:{expr.value}")
        if isinstance(expr, cst.Attribute):
            if isinstance(expr.value, cst.Name) and expr.value.value == "self":
                return self._lookup(scope, f"self:{expr.attr.value}")
            base = self.taint(scope, expr.value)
            if base and expr.attr.value in DERIVING:
                return Taint(
                    f"{base.qualified_name}.{expr.attr.value}", base.category, base.algorithms
                )
            return None
        if isinstance(expr, cst.Call):
            func = expr.func
            if isinstance(func, cst.Attribute):
                base = self.taint(scope, func.value)
                if base and "Builder" in base.qualified_name:
                    if func.attr.value in BUILDER_STEPS:
                        return base
                    if func.attr.value == "sign":
                        built = next(
                            (name for builder, name in BUILT if builder in base.qualified_name),
                            "cryptography.x509.SignedObject",
                        )
                        return Taint(built, "certificate", base.algorithms)
                if base and func.attr.value in DERIVING:
                    return Taint(
                        f"{base.qualified_name}.{func.attr.value}", base.category, base.algorithms
                    )
                if isinstance(func.value, cst.Name) and func.value.value == "self":
                    return self._method(scope, func.attr.value)
            if isinstance(func, cst.Name):
                return self.returns.get(func.value)
        return None

    def solve(self) -> None:
        for scope, key, names in self.s.annotated:
            for name in sorted(names):
                taint = _annotation_taint(name)
                if taint is None:
                    continue
                if key == "return":
                    self.returns.setdefault(scope, taint)
                else:
                    self.bindings.setdefault((self._binding_scope(scope, key), key), taint)
                break
        for _ in range(12):
            changed = False
            for scope, key, value in self.s.assignments:
                slot = (self._binding_scope(scope, key), key)
                if slot in self.bindings:
                    continue
                taint = self.taint(scope, value)
                if taint:
                    self.bindings[slot] = taint
                    changed = True
            for scope, value in self.s.returns:
                if scope in self.returns:
                    continue
                taint = self.taint(scope, value)
                if taint:
                    self.returns[scope] = taint
                    changed = True
            if not changed:
                break


@dataclass(frozen=True)
class Operation:
    scope: str | None
    line: int
    col: int
    operation: str
    taint: Taint


def find_operations(
    wrapper: cst.metadata.MetadataWrapper, producers: dict[int, CryptoSite]
) -> list[Operation]:
    """Operation calls on crypto objects, in source order."""
    scopes = _Scopes()
    wrapper.visit(scopes)
    taints = _Taints(scopes, producers)
    taints.solve()
    found: list[Operation] = []
    for scope, call, line, col in scopes.candidates:
        if id(call) in producers:
            continue  # the call is itself a detected site (for example ssl.wrap_socket)
        func = call.func
        if not isinstance(func, cst.Attribute):  # candidates are recorded for attribute calls only
            continue
        taint = taints.taint(scope, func.value)
        if (
            taint is not None
            and func.attr.value in MATERIALISE
            and "Builder" in taint.qualified_name
        ):
            continue  # CertificateBuilder.public_key(...) sets a field (PROTOCOL-R8 B2d)
        if taint is None and func.attr.value in TLS_ONLY:
            taint = Taint("ssl.SSLContext", "tls", ())
        if taint is not None:
            found.append(
                Operation(None if scope == "<module>" else scope, line, col, func.attr.value, taint)
            )
    return found


def operation_category(operation: str, taint: Taint) -> str | None:
    if operation in MATERIALISE:
        return "key_loading"
    fixed = OPERATIONS.get(operation)
    return fixed or taint.category


def quantum_flags(algorithms: tuple[str, ...]) -> tuple[bool, bool]:
    infos = [ALGORITHMS[a] for a in algorithms if a in ALGORITHMS]
    return any(i.weak for i in infos), any(i.quantum_vulnerable for i in infos)
