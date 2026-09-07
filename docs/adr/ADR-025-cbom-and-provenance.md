# ADR-025: Located CycloneDX assets and content-addressed CBOM provenance

Status: Accepted. Implements PROC-06 without a second scanner or a new dependency.

The official CycloneDX 1.6 JSON schema defines `components` of type
`cryptographic-asset` and `evidence.occurrences` with `location`, `line` and optional
`symbol`. Its `offset` is a byte offset, not a source column. Source:
https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json

Read a bounded 2 MB JSON input and merge safe, relative Python source locations into the
CDG with `source: cbom`. Existing sites at the same location and matching symbol or
algorithm are retained rather than duplicated. Unlocated or unsafe occurrences are
counted in metadata and reported; absolute paths are never guessed into source paths.
Nested component arrays are supported. Embedded code snippets and cryptographic material
are ignored and never included in artifacts.

This is a source-location importer, not full CycloneDX schema certification. It supports
1.6 occurrence evidence, not arbitrary producer extensions or inferred callstack locations.

A CBOM changes the input even when the repository commit is unchanged. Include its full
SHA-256 in the composite analyzer identifier and metadata so deterministic outputs cannot
share a provenance key with a different CBOM. The web API remains URL-only; CBOM merging
is exposed by the CLI. Version 0.2.0 invalidates live caches for this implementation.
