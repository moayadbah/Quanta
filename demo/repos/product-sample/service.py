from fingerprints import attachment_fingerprint, document_fingerprint


def describe_upload(document: bytes, attachment: bytes) -> dict[str, str]:
    return {"document": document_fingerprint(document),
            "attachment": attachment_fingerprint(attachment)}
