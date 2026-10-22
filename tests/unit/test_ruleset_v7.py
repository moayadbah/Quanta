"""Round seven: the three causes of the round-six errors (evidence/PROTOCOL-R7.md, R7-A1).

Each case is the shape of a documented API or of a round-six error; none comes from the new
held-out set.
"""

from __future__ import annotations

from pathlib import Path

from quanta.core.detect import detect_repository
from quanta.core.ingest import walk_repository
from quanta.core.models import CryptoSite


def detect(tmp_path: Path, source: str) -> list[CryptoSite]:
    (tmp_path / "pkg").mkdir(exist_ok=True)
    (tmp_path / "pkg" / "mod.py").write_text(source, encoding="utf-8")
    return list(detect_repository(walk_repository(tmp_path).files, tmp_path).sites)


def calls(sites: list[CryptoSite]) -> dict[int, CryptoSite]:
    return {s.line: s for s in sites if s.kind == "crypto_call"}


def test_os_urandom_and_system_random_are_randomness(tmp_path: Path) -> None:
    found = calls(
        detect(
            tmp_path,
            "import os, random\n"
            "seed = int.from_bytes(os.urandom(2), 'big')\n"
            "rng = random.SystemRandom()\n"
            "x = random.random()\n",
        )
    )
    assert found[2].qualified_name == "os.urandom"
    assert found[2].category == "randomness"
    assert not found[2].scored
    assert found[3].qualified_name == "random.SystemRandom"
    assert 4 not in found


def test_a_hash_called_through_a_local_name_is_reported_at_the_call(tmp_path: Path) -> None:
    """The round-six shape (patchwork scm.py): three branches bind the name, one call."""
    sites = detect(
        tmp_path,
        "import hashlib\n"
        "\n"
        "def anchor(kind, path):\n"
        "    if kind == 'github':\n"
        "        anchor_hash = hashlib.sha256\n"
        "    elif kind == 'gitlab':\n"
        "        anchor_hash = hashlib.sha1\n"
        "    else:\n"
        "        anchor_hash = hashlib.md5\n"
        "    return anchor_hash(path.encode()).hexdigest()\n",
    )
    found = calls(sites)
    assert set(found) == {10}
    site = found[10]
    assert site.form == "call"
    assert site.category == "hash"
    assert site.algorithms == ("SHA2-256", "SHA1", "MD5")
    assert site.weak
    selectors = {s.line: s for s in sites if s.kind == "algo_literal"}
    assert set(selectors) == {5, 7, 9}
    assert {s.parent_site_id for s in selectors.values()} == {site.site_id}
    assert selectors[9].weak


def test_a_module_level_alias_defined_after_its_caller(tmp_path: Path) -> None:
    sites = detect(
        tmp_path,
        "import hashlib\n\ndef h(data):\n    return DIGEST(data).hexdigest()\n\n"
        "DIGEST = hashlib.sha256\n",
    )
    found = calls(sites)
    assert set(found) == {4}
    assert found[4].algorithms == ("SHA2-256",)
    assert [s.line for s in sites if s.kind == "algo_literal"] == [6]


def test_an_alias_that_is_never_called_stays_a_reference(tmp_path: Path) -> None:
    found = calls(detect(tmp_path, "import hashlib\nDIGEST = hashlib.md5\n"))
    assert found[2].form == "reference"


def test_a_name_with_any_other_binding_is_not_an_alias(tmp_path: Path) -> None:
    found = calls(
        detect(
            tmp_path,
            "import hashlib\n"
            "\n"
            "def f(h, data):\n"
            "    return h(data)\n"
            "\n"
            "def g(data, fallback):\n"
            "    h = hashlib.sha256\n"
            "    if fallback:\n"
            "        h = make()\n"
            "    return h(data)\n",
        )
    )
    assert 4 not in found
    assert 10 not in found
    assert found[7].form == "reference"


def test_third_party_tls_clients(tmp_path: Path) -> None:
    found = calls(
        detect(
            tmp_path,
            "import imaplib2, urllib3\n"
            "import aioimaplib\n"
            "m = imaplib2.IMAP4_SSL('imap.example.org')\n"
            "a = aioimaplib.IMAP4_SSL('imap.example.org')\n"
            "p = urllib3.HTTPSConnectionPool('example.org')\n"
            "q = urllib3.PoolManager()\n",
        )
    )
    assert found[3].qualified_name == "imaplib2.IMAP4_SSL"
    assert {found[n].category for n in (3, 4, 5)} == {"tls"}
    assert 6 not in found
