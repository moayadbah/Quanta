"""Document lookup index."""

from vault import errors, models

_BY_ID: dict[str, models.Document] = {}


def add(doc: models.Document) -> None:
    _BY_ID[doc.doc_id] = doc


def find(doc_id: str) -> models.Document:
    if doc_id not in _BY_ID:
        raise errors.NotFound(doc_id)
    return _BY_ID[doc_id]


def owned_by(owner: str) -> list[models.Document]:
    return [d for d in _BY_ID.values() if d.owner == owner]
