"""Vercel entrypoint. Public deployments always require GitHub sign-in."""

import os
from pathlib import Path
from tempfile import gettempdir

os.environ["QUANTA_AUTH__REQUIRED"] = "true"
os.environ["QUANTA_DEPLOYMENT"] = "vercel"
root = Path(gettempdir()) / "quanta"
os.environ.setdefault("QUANTA_DB", str(root / "quanta.db"))
os.environ.setdefault("QUANTA_ARTIFACT_ROOT", str(root / "artifacts"))
os.environ.setdefault("QUANTA_SCRATCH_ROOT", str(root / "scratch"))
hostname = os.environ.get("VERCEL_PROJECT_PRODUCTION_URL") or os.environ.get("VERCEL_URL")
if hostname:
    os.environ.setdefault("QUANTA_AUTH__PUBLIC_URL", "https://" + hostname)
if os.environ.get("QUANTA_CLOUD__DATABASE_URL"):
    os.environ.setdefault("QUANTA_CLOUD__ENABLED", "true")
os.environ.setdefault("QUANTA_INGEST__MAX_REPO_KB", "10000")
os.environ.setdefault("QUANTA_INGEST__MAX_FILES", "1000")
os.environ.setdefault("QUANTA_INGEST__MAX_TOTAL_BYTES", "20000000")
os.environ.setdefault("QUANTA_INGEST__MAX_FILE_BYTES", "200000")
os.environ.setdefault("QUANTA_INGEST__CLONE_TIMEOUT_S", "45")
os.environ.setdefault("QUANTA_ANALYSIS__MAX_JOB_SECONDS", "100")
os.environ.setdefault("QUANTA_WORKER__MAX_ATTEMPTS", "1")

from quanta.web.app import create_app  # noqa: E402

app = create_app()
