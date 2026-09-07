"""Example content fingerprinting service. Deliberately uses legacy hashes for the sample."""
import hashlib


def document_fingerprint(content: bytes) -> str:
    return hashlib.sha1(content).hexdigest()


def attachment_fingerprint(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()
