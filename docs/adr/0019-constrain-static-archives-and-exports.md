# 0019: Constrain static archives and exports

- Status: accepted
- Date: 2026-08-22

## Context

Archive upload is the first deployment interface and therefore the first
tenant-controlled parser and filesystem boundary. Supporting several archive
formats would multiply ambiguous path, link, permission, and resource-limit
behavior before the publication contract is stable.

## Decision

Accept ZIP only for Milestone 3 deployment artifacts. Permit regular files and
directories and require a root-level `index.html`. Normalize path separators and
Unicode before validation. Reject absolute paths, parent traversal, backslash
ambiguity, empty or control-character path components, duplicate normalized
names, case-folding collisions, symlinks, encrypted entries, and every special
file type.

Apply these initial limits before and during root-side extraction:

- at most 100 MiB in the uploaded ZIP;
- at most 100 MiB of extracted regular-file content;
- at most 5,000 regular files;
- at most 25 MiB in one file; and
- at most a 100:1 declared or observed expansion ratio.

Normalize directories to mode `0755` and regular files to `0644`; discard
executable, set-ID, and other archive-supplied permission semantics. Extract
only into a new root-owned non-public temporary directory and fail closed if
actual bytes or entry counts diverge from preflight metadata.

Produce a portable ZIP export containing a format version, canonical tenant
manifest, current static content, and SHA-256 checksums. Export does not change
site state. Archive and restore use this versioned portable bundle; a later Git
integration must produce the same validated internal deployment artifact.

## Consequences

ZIP is familiar to Windows and non-Git users and is available through Python's
standard library, but the platform must implement validation rather than call a
general-purpose extraction helper. Large individual media files and archives
that rely on Unix links or executable bits are deliberately unsupported.

The limits are platform policy and therefore belong in the schema and tests,
not scattered constants. Raising them requires reviewing disk, backup, and
denial-of-service implications.

## Alternatives considered

Supporting TAR and ZIP together was rejected because TAR adds link and special
file semantics with no pilot benefit. Git-only deployment was rejected by ADR
0008. Preserving archive permissions was rejected because static sites do not
need executable or privileged filesystem bits.

## References

- [0008: Support archive upload before Git deployment](0008-archive-upload-first.md)
- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
