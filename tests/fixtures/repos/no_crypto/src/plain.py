"""Ground truth: 0 crypto_call sites.

Deliberately contains near-misses. A detector that matches on substrings rather than on
resolved qualified names will produce false positives here, and precision is reported
separately from recall precisely so that shows up.
"""

import base64
import json
import random


def encode(payload: dict) -> str:
    """Not cryptography, despite the name."""
    return base64.b64encode(json.dumps(payload).encode()).decode()


def make_token() -> str:
    # random is not secrets; this is a security bug but not a detected crypto site.
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


class Cipher:
    """A same-named class from an unrelated module. Must not match the ruleset."""

    def __init__(self, algorithm: str = "SHA256") -> None:
        self.algorithm = algorithm


def sha256(data: bytes) -> str:
    """A locally defined shadow of a crypto name."""
    return data.hex()


def use_shadows() -> str:
    return sha256(b"abc") + Cipher("AES").algorithm
