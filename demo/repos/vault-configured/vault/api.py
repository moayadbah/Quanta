"""Public entry points. No cryptography here in any variant."""

from vault import audit, backup, index, models, passwords, sessions, store, tokens


def register(owner: str, password: bytes, salt: bytes) -> bytes:
    return passwords.stretch(password, salt)


def upload(owner: str, doc: models.Document, key: bytes) -> bytes:
    index.add(doc)
    audit.record(owner, "upload", doc)
    return store.seal(key, models.Blob(payload=doc.body))


def open_session(peer_public: bytes) -> tuple[bytes, bytes]:
    private_bytes, public_bytes = sessions.new_keypair()
    shared = sessions.agree(private_bytes, peer_public)
    return public_bytes, tokens.derive(shared, b"session")


def snapshot(key: bytes, manifest: models.Manifest) -> bytes:
    return backup.sign(key, manifest)
