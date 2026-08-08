"""Data shapes carried through the vault."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Blob:
    payload: bytes
    aad: bytes | None = None


@dataclass(frozen=True)
class Manifest:
    entries: tuple[str, ...]
    created_at: str

    def to_bytes(self) -> bytes:
        return ("\n".join(self.entries) + self.created_at).encode()


@dataclass(frozen=True)
class Document:
    doc_id: str
    owner: str
    body: bytes
