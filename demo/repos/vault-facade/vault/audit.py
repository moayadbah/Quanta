"""Append-only audit log."""

from vault import integrity, models

_LOG: list[tuple[str, str]] = []


def record(actor: str, action: str, doc: models.Document) -> None:
    fingerprint = integrity.digest(doc.body).hex()[:16]
    _LOG.append((actor, f"{action}:{doc.doc_id}:{fingerprint}"))


def entries() -> list[tuple[str, str]]:
    return list(_LOG)
