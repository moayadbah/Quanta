# Codebook for the round-eleven annotators

B1. A unit is one call expression in a sampled file (a class instantiation counts as a
call). The annotator reads every line of every sampled file.
B2. Classes:
 - **A**: a call into a cryptographic library or a cryptographic module of the standard
   library that performs, configures or selects cryptography: hashing, MAC, KDF and
   password hashing, encryption and decryption, signing and verification, key generation,
   loading and serialisation, certificate parsing or creation, TLS context creation,
   wrapping and verification settings, JWT/JWS/JWE encoding and decoding, secure
   randomness (`secrets`, `os.urandom`, `random.SystemRandom`), one-time passwords.
 - **B**: a call into a third-party library that is not primarily a cryptography library,
   or into a key or client object such a library returns, whose documented purpose is one
   of the operations above (for example a key object's `verify_signature`, a JWK client's
   `get_signing_key_from_jwt`, a protocol client opened with TLS).
 - Not a unit: imports, constants, comments, strings; calls to functions defined in the
   repository itself (their cryptography is labelled where it happens); method calls on
   the result of an A or B call that only feed or read it (`update`, `digest`,
   `hexdigest`, `finalize`, `copy`); `hmac.compare_digest`; the `random` module other
   than `SystemRandom`; `uuid`, `base64`, `binascii`, `zlib`.
B3. Every unit records file, first and last line of the call, the called name as written,
class (A or B) and kind: `hash`, `mac`, `kdf`, `symmetric`, `public_key`, `key_handling`,
`tls`, `token`, `random`, `other`.

## Clarifications (round eight)

The codebook is R6-B1 to R6-B3, with these clarifications (the round-seven annotators split on
them):
 - B2a. A method on a key object returned by an A or B call is a unit (A, `key_handling`) when its
   documented purpose is to serialise or export the key, or to derive its public key:
   `private_bytes`, `public_bytes`, `public_key()`, `export_key`, `exportKey`, `to_pem`,
   `to_der`, `to_string`, `get_verifying_key`, `as_dict`, `as_pem` and the like.
 - B2b. A method on a cipher, signer or key object that performs the operation (`encrypt`,
   `decrypt`, `sign`, `verify`, `exchange`, `derive`, `encryptor`, `decryptor`) is a unit.
 - B2c. Calls that configure an existing TLS context (`load_cert_chain`, `load_verify_locations`,
   `load_default_certs`, `set_ciphers`, `wrap_socket`, `wrap_bio`) are units (A, `tls`).
 - B2d. Building blocks of a certificate or a name (`x509.Name`, `NameAttribute`,
   `SubjectAlternativeName`, `DNSName`, `random_serial_number`, a builder's setter methods such as
   `subject_name`) are not units. Creating the builder (`CertificateBuilder()`,
   `CertificateSigningRequestBuilder()`) and its `sign(...)` are units (A, `public_key`).
 - B2e. A third-party client is a unit (B, `tls`) only when the call passes a TLS context or
   turns TLS on (`ssl=ctx`, `ssl=True`, `tls_context=ctx`, `use_tls=True`). A plain HTTP call to
   an https URL is not a unit, and neither is a certificate-verification flag on an HTTP call
   (`verify=False`, `verify=path`). (Wording made exact on 2026-10-17, before any H8 label.)

## Clarifications (round nine)

- B2f. Parameter objects are not units of their own: instances of a padding scheme
   (`padding.OAEP(...)`, `padding.PSS(...)`, `padding.MGF1(...)`), of a hash algorithm or cipher
   algorithm or mode passed as a parameter (`hashes.SHA256()` given to another call,
   `algorithms.AES(k)` and `modes.CBC(iv)` given to `Cipher`), and backends
   (`default_backend()`). The call that uses them is the unit. A hash object created to be
   used as a hash (`hashes.Hash(hashes.SHA256())`) is a unit at `hashes.Hash`.
 - B2g. A standard-library client that is not a cryptographic module (`urllib.request.urlopen`,
   `asyncio.open_connection`, `smtplib`, `imaplib`, `poplib`, `ftplib`, `http.client`) is a unit
   (B, `tls`) under the same rule as B2e: when the call passes a TLS context or turns TLS on,
   including `starttls()` and `start_tls()` on such a client. Classes that always speak TLS
   (`http.client.HTTPSConnection`, `smtplib.SMTP_SSL`, `imaplib.IMAP4_SSL`, `poplib.POP3_SSL`,
   `ftplib.FTP_TLS`) are units whatever their arguments.
 - B2h. A call into a library is a unit wherever it is written, including inside a copy of a
   third-party package bundled in the repository (`vendor/`, a copied `urllib3/`). What is
   excluded is a call to a function the repository's files define, not a call written in them.
 - B2i. An assignment is not a call: `ssl._create_default_https_context =
   ssl._create_unverified_context` is not a unit.

## Clarifications (round ten)

 - B2j. Calls that configure a TLS context or a TLS connection object, or run its handshake, are
   units (A, `tls`), in any library including the standard library: for example pyOpenSSL's
   `set_options`, `set_verify`, `set_cipher_list`, `use_certificate_chain_file`,
   `use_privatekey_file`, `set_passwd_cb`, `set_alpn_protos`, `set_tlsext_host_name`,
   `set_connect_state`, and `do_handshake`, `handshakeServer`, `handshakeClientCert`. Reading,
   writing and closing a connection (`recv`, `send`, `read`, `write`, `close`, `shutdown`) are
   not units.
 - B2k. An asyncio event loop's `start_tls(...)` is a unit (B, `tls`), and so are its
   `create_connection(...)`, `create_server(...)` and `create_unix_connection(...)` when they pass
   a TLS context (`ssl=ctx`, `ssl=True`): the B2g rule applied to the event loop.

## Clarification (round eleven)

 - B2l. Helpers that only prepare data or parameters for another call are not units:
   block-padding helpers (`Crypto.Util.Padding.pad`, `unpad`; `padding.PKCS7(...)` and its
   `padder()` / `unpadder()`), and the encryption choice passed to a key serialisation call
   (`serialization.BestAvailableEncryption(...)`, `NoEncryption()`, which are parameter objects
   under B2f). The cipher call and the serialisation call they feed are the units.
