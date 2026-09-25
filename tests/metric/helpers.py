"""Small repository builders for metric tests (Master Plan 8.9)."""

from __future__ import annotations

from pathlib import Path

from quanta.core.analyze import AnalysisOutcome, analyze_path
from quanta.core.models import Provenance

PROVENANCE = Provenance(
    repo="owner/metric-fixture",
    commit_sha="b" * 40,
    analyzer_version="test",
    crypto_ruleset_version="test",
)

#: ``BASE``: package ``app/`` with 6 modules. Three each hold one ``hashlib.sha256(data)``
#: call inside a function; ``app/main.py`` imports the other five.
BASE: dict[str, str] = {
    "app/__init__.py": "",
    "app/users.py": (
        "import hashlib\n\n\ndef fingerprint(data: bytes) -> str:\n"
        "    return hashlib.sha256(data).hexdigest()\n"
    ),
    "app/files.py": (
        "import hashlib\n\n\ndef checksum(data: bytes) -> str:\n"
        "    return hashlib.sha256(data).hexdigest()\n"
    ),
    "app/tokens.py": (
        "import hashlib\n\n\ndef token_id(data: bytes) -> str:\n"
        "    return hashlib.sha256(data).hexdigest()\n"
    ),
    "app/views.py": "def render(value: str) -> str:\n    return value.upper()\n",
    "app/main.py": (
        "from app import files, tokens, users, views\n"
        "from app import __init__ as package\n\n\n"
        "def run(data: bytes) -> str:\n"
        "    return views.render(users.fingerprint(data) + files.checksum(data)"
        " + tokens.token_id(data))\n"
    ),
}


def make_repo(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    return root


def analyse(root: Path, files: dict[str, str]) -> AnalysisOutcome:
    return analyze_path(make_repo(root, files), PROVENANCE)
