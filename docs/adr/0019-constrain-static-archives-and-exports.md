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
- at most 5,000 extracted entries in total, counting both regular files and
  directories;
- at most 25 MiB in one file; and
- at most a 100:1 declared or observed expansion ratio.

Normalize directories to mode `0755` and regular files to `0644`; discard
executable, set-ID, and other archive-supplied permission semantics. Extract
only into a new root-owned non-public temporary directory and fail closed if
actual bytes or entry counts diverge from preflight metadata.

Before constructing an export, acquire the shared tenant-state lock used by
backup. While holding it, resolve the canonical manifest and selected immutable
release, then copy both into a new root-owned, non-writable export snapshot.
Verify that complete snapshot before releasing the lock. Publication, rollback,
rename, suspension, archival, restoration, deletion, and garbage collection
take the lock exclusively, so the snapshot cannot combine metadata from one
tenant generation with content from another or lose its release during capture.
ZIP construction and checksum generation consume only the completed snapshot
and may proceed after the lock is released.

All export and archive bundle construction also takes one exclusive root-owned
host export lock before snapshot admission. The initial host permits exactly
one in-progress snapshot and one completed, unacknowledged downloadable export
in total. The activator accounts actual blocks and inodes already present in
the root-owned export spool before admitting work and enforces aggregate hard
ceilings of 256 MiB and 5,120 inodes as well as the configured host free-space
reserve. A snapshot may contain at most the accepted 100 MiB and 5,000 tenant
entries; encoded bundle output has a separate 105 MiB ceiling and never becomes
visible until complete and verified. Exceeding any limit fails closed.

Incomplete snapshots and outputs are removed on every terminal path and during
startup reconciliation. A completed downloadable export remains for at most 24
hours or until the trusted client acknowledges its verified download, whichever
comes first; admission rejects another export while that slot is occupied.
Retries with the same correlation ID return the established result. Archive
construction uses the same lock, spool, admission accounting, and cleanup, but
moves the verified bundle into durable archive storage before releasing its
transaction. The provisioner cannot create files directly in the spool or
bypass these limits.

Produce a portable ZIP export with this fixed versioned envelope:

```text
lowerduckpond-export-v1/
├── format.json
├── manifest.json
├── checksums.sha256
└── content/
    ├── index.html
    └── ...
```

`format.json` identifies the export format and version, `manifest.json` is the
canonical tenant manifest from the snapshot, and `checksums.sha256` lists those
two files and every regular file below `content/` in normalized bytewise path
order. Tenant files always appear below `content/`; they can therefore use any
otherwise valid path without colliding with envelope metadata. Restore rejects
entries outside the single envelope root, unknown or duplicate metadata,
missing required entries, and checksum or canonicalization failures before it
passes the `content/` subtree through the ordinary deployment validator.

Deployment uploads remain the flat, root-`index.html` ZIP format; a portable
export is not accepted as a deployment archive without the explicit restore
path. Export does not change site state. Archive and restore use this versioned
portable bundle; a later Git integration must produce the same validated
internal deployment artifact.

## Consequences

ZIP is familiar to Windows and non-Git users and is available through Python's
standard library, but the platform must implement validation rather than call a
general-purpose extraction helper. Large individual media files and archives
that rely on Unix links or executable bits are deliberately unsupported.

The limits are platform policy and therefore belong in the schema and tests,
not scattered constants. Raising them requires reviewing disk, backup, and
denial-of-service implications.

Export briefly consumes another bounded copy of the current release. Capturing
that copy under the shared state lock favors a coherent portable artifact over
concurrent mutation; compression proceeds outside the tenant-state lock so the
longer part of export does not block lifecycle changes. Global bundle
construction is intentionally serialized on the small initial host, and an
unacknowledged result can delay later exports until it is downloaded or expires,
in exchange for a strict disk and inode bound.

## Alternatives considered

Supporting TAR and ZIP together was rejected because TAR adds link and special
file semantics with no pilot benefit. Git-only deployment was rejected by ADR
0008. Preserving archive permissions was rejected because static sites do not
need executable or privileged filesystem bits.

## References

- [0008: Support archive upload before Git deployment](0008-archive-upload-first.md)
- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
