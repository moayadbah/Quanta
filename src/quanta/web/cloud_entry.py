"""Credential-free commands run inside a disposable Vercel microVM."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from quanta.config import Settings
from quanta.core.analyze import analyze_path, write_artifacts
from quanta.core.ingest import clone_pinned, remove_tree
from quanta.core.models import Provenance
from quanta.errors import Reject
from quanta.version import CRYPTO_RULESET_VERSION, analyzer_version
from quanta.web.sandbox import block_network, prepare


def main() -> None:
    payload = json.loads(Path("quanta-input.json").read_text())
    cfg = Settings.model_validate(payload["settings"]).scanner_settings()
    row = payload["job"]
    root = Path("quanta-work").resolve()
    output = Path("quanta-output").resolve()
    prepare(cfg)
    try:
        if sys.argv[1] == "acquire":
            clone_pinned(row["repo_owner"], row["repo_name"], row["commit_sha"], root, cfg)
        elif sys.argv[1] == "analyze":
            # The external microVM firewall is already deny-all. Defense in depth.
            block_network(required=False)
            outcome = analyze_path(
                root,
                Provenance(
                    repo=f"{row['repo_owner']}/{row['repo_name']}",
                    commit_sha=row["commit_sha"],
                    analyzer_version=analyzer_version(),
                    crypto_ruleset_version=CRYPTO_RULESET_VERSION,
                ),
                cfg,
            )
            write_artifacts(outcome, output)
        else:
            raise Reject("SCHEMA_INVALID")
    except Reject as exc:
        Path("quanta-error.json").write_text(json.dumps({"code": exc.code, "detail": exc.detail}))
        raise SystemExit(1) from None
    finally:
        if sys.argv[1] != "acquire":
            remove_tree(root)


if __name__ == "__main__":
    main()
