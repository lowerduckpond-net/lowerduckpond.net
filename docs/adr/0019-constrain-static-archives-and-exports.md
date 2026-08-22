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

Decode flagged names as strict UTF-8 and require unflagged names to be ASCII.
Normalize paths to Unicode NFC before every comparison. Limit each normalized
component to 255 UTF-8 bytes, each relative path to 1,024 UTF-8 bytes, and depth
to 32 components. Reject `.` and `..`, NUL, leading separators, trailing or
repeated separators except the single directory marker, and any change from
backslash interpretation. Count every distinct implicit parent directory toward
the entry ceiling and reject file/directory or explicit/implicit collisions
after NFC and case folding.

Allow only method `0` (stored) and method `8` (Deflate) in deployment ZIPs.
Reject BZIP2, LZMA, Deflate64, vendor methods, and unknown methods before
initializing any entry decoder. A bounded structural reader examines the end
record and central directory from the root-owned snapshot first, caps their
byte and entry counts, validates offsets and integer arithmetic, and allowlists
flags and methods without materializing attacker-sized metadata. Streaming
validation then requires each local header to agree with its central-directory
record before consuming entry data. Stored entries may set only the UTF-8-name
flag; Deflate entries may additionally set a valid compression-option value.
Reject data descriptors and every other general-purpose flag, and require a
flagged UTF-8 name for any non-ASCII filename. The general ZIP library and
decompressor run only after this structural gate.

Require one single-disk end record at the physical end of the snapshot, no
prepended or trailing data, an at-most-8-MiB central directory, and empty entry
and archive comments. Limit each local and central extra-field area to 1 KiB;
permit only structurally valid extended-timestamp (`0x5455`) and NTFS-timestamp
(`0x000a`) fields and discard their values. Reject ZIP64 and every other extra
field. Central-directory counts must equal parsed records. Local headers and
compressed data regions must lie wholly before the central directory, neither
overlap nor alias one another or metadata, and cover exactly the declared entry
data. Checked arithmetic precedes every offset-plus-length operation.

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

Run each privileged archive parse and extraction in a dedicated constrained
service process whose limits are active before it reads ZIP metadata: initially
`MemoryMax=256M`, `MemorySwapMax=0`, `TasksMax=32`, `LimitNOFILE=1024`,
`LimitCPU=120`, `RuntimeMaxSec=5min`, and at most one CPU through
`CPUQuota=100%`. Termination by any resource limit is a failed activation and
enters the ordinary staging cleanup and audit path. The compressed, expanded,
ratio, count, and per-file checks remain the primary policy; process limits are
a host-availability backstop for parser bugs and adversarial valid Deflate
streams.

All export and archive bundle construction first takes one exclusive root-owned
host export lock before snapshot admission. An ordinary export then acquires the
shared tenant-state lock used by backup. While holding it, resolve the canonical
manifest and selected immutable release, then copy both into a new root-owned,
non-writable export snapshot. Verify that complete snapshot before releasing the
tenant-state lock. Publication, rollback, rename, suspension, archival,
restoration, deletion, and garbage collection take that lock exclusively, so
the snapshot cannot combine metadata from one tenant generation with content
from another or lose its release during capture. ZIP construction and checksum
generation consume only the completed snapshot and may proceed while holding
only the export lock.

The initial host permits exactly
one in-progress snapshot and one completed, unacknowledged downloadable export
in total. The activator accounts actual blocks and inodes already present in
the root-owned export spool before admitting work and enforces aggregate hard
ceilings of 256 MiB and 5,120 inodes as well as the configured host free-space
reserve. A snapshot may contain at most the accepted 100 MiB and 5,000 tenant
entries; encoded bundle output has a separate 120 MiB ceiling and never becomes
visible until complete and verified. Exceeding any limit fails closed.

Incomplete snapshots and outputs are removed on every terminal path and during
startup reconciliation. A completed downloadable export remains for at most 24
hours or until the trusted client acknowledges its verified download, whichever
comes first; admission rejects another export while that slot is occupied.
Retries with the same correlation ID return the established result. Archive
construction uses the same lock, spool, admission accounting, and cleanup. It
captures the source manifest, its canonical digest, and the selected release
under shared tenant-state. While still holding that lock, root derives the
proposed canonical `archived` manifest by changing only the allowed lifecycle
fields and stores both manifests separately in the non-writable snapshot. The
source manifest is private compare-and-swap evidence and never becomes the
archive bundle's `manifest.json`; the proposed archived manifest is the bundle
manifest.

Archive releases tenant-state to build and move the verified bundle into
durable archive storage, then—without releasing the export lock—acquires
publication followed by exclusive tenant-state. It revalidates the exact source
manifest, deployment, and release digests before committing that already
bundled proposed archived manifest and its archive record. The archive record
binds the proposed archived-manifest digest, selected deployment and content
digests, portable-bundle digest and size, and durable object identity. The
bundle alone grants no deletion authority before this transaction commits the
record.

If any source changed, archive records an aborted result and retains no
authorizing archive record; it never applies a stale snapshot. It immediately
removes the unreferenced durable object, or records it in a root-owned
quarantine ledger for bounded retry and garbage collection if object deletion
fails. Quarantined objects grant no restore or deletion authority; archive
admission remains closed while the quarantine ledger is nonempty, so repeated
aborts cannot grow it without bound. The provisioner cannot create files
directly in the spool or bypass these limits.

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

`format.json` identifies the export format and version. For an ordinary export,
`manifest.json` is the current canonical manifest captured in the snapshot. For
archive, it is the separately snapshotted proposed canonical `archived`
manifest, never the active or suspended source manifest retained for
compare-and-swap. `checksums.sha256` lists those two files and every regular
file below `content/` in normalized bytewise path order. Tenant files always
appear below `content/`; they can therefore use any otherwise valid path
without colliding with envelope metadata. Restore rejects entries outside the
single envelope root, unknown or duplicate metadata, missing required entries,
and checksum or canonicalization failures before it passes the `content/`
subtree through the ordinary deployment validator.

Deployment uploads remain the flat, root-`index.html` ZIP format; a portable
export is not accepted as a deployment archive without the explicit restore
path. Export does not change site state. Archive and restore use this versioned
portable bundle; a later Git integration must produce the same validated
internal deployment artifact.

The v1 bundle has one canonical byte representation. Serialize `format.json`
and `manifest.json` as the UTF-8 JSON Canonicalization Scheme defined by RFC
8785, without a byte-order mark and with exactly one trailing LF. The schema
permits only values that JCS can represent; fail rather than coerce any other
value. `format.json` contains only the fixed format name and integer version.
Its exact bytes are
`{"format":"lowerduckpond-export","version":1}\n`.
Write lowercase SHA-256 values, two ASCII spaces, and the normalized
envelope-relative UTF-8 path to `checksums.sha256`, sorted by path bytes and
terminated by one LF; control characters are already invalid in accepted paths.

Write ZIP members in this order: the three fixed metadata files, the `content/`
directory, then all descendant directory and regular-file paths in normalized
UTF-8 byte order. Use stored entries only, not implementation-dependent Deflate
output. Every local and central member has DOS time `0x0000` and date `0x0021`
(`1980-01-01 00:00:00`), version-made-by `0x0314` (Unix, 2.0),
version-needed `0x0014`, general-purpose flags `0x0800`, method `0x0000`, and
precomputed standard ZIP CRC-32 and 32-bit sizes. It has disk number and
internal attributes `0`, matching UTF-8 filename bytes, empty extra and comment
fields, and no data descriptor. Central external attributes are `0x81a40000`
for a regular file and `0x41ed0010` for a directory. The end record uses disk
numbers `0`, matching entry counts, the exact central-directory size and offset,
and an empty comment. There is no disk spanning, encryption, or ZIP64 metadata.
The central directory repeats the member order. A bundle implementation must
reject a value it cannot represent canonically rather than substitute
environment metadata.

Consequently, the same versioned export snapshot produces byte-identical ZIP
output and the portable-bundle SHA-256 is a reproducible identifier, not merely
a checksum of one encoder attempt. A future format may choose compression only
through a new version with equally complete canonical encoding rules.

## Consequences

ZIP is familiar to Windows and non-Git users and is available through Python's
standard library, but the platform must implement validation rather than call a
general-purpose extraction helper. Large individual media files and archives
that rely on Unix links or executable bits are deliberately unsupported.

Stored portable bundles trade network and archive-storage size for reproducible
bytes independent of zlib versions. The 100-MiB content and 120-MiB encoded
output ceilings include the bounded path and ZIP-header overhead.

The limits are platform policy and therefore belong in the schema and tests,
not scattered constants. Raising them requires reviewing disk, backup, and
denial-of-service implications.

Supporting only stored and Deflate input avoids decoder-controlled dictionaries
and reduces privileged parser surface. The constrained process can still delay
one serialized operation until its CPU or runtime limit, but it cannot consume
unbounded memory, swap, processes, descriptors, CPU concurrency, or wall time.

Export briefly consumes another bounded copy of the current release. Capturing
that copy under the shared state lock favors a coherent portable artifact over
concurrent mutation; compression proceeds outside the tenant-state lock so the
longer part of export does not block lifecycle changes. Global bundle
construction is intentionally serialized on the small initial host, and an
unacknowledged result can delay later exports until it is downloaded or expires,
in exchange for a strict disk and inode bound.

Archive snapshots retain two bounded manifest files with different authority:
the source manifest authorizes only final compare-and-swap revalidation, while
the proposed archived manifest is portable evidence inside the bundle. This
small duplication prevents a source-state bundle from being mistaken for the
exact archived generation required by ordinary deletion.

## Alternatives considered

Supporting TAR and ZIP together was rejected because TAR adds link and special
file semantics with no pilot benefit. Git-only deployment was rejected by ADR
0008. Preserving archive permissions was rejected because static sites do not
need executable or privileged filesystem bits.

## References

- [0008: Support archive upload before Git deployment](0008-archive-upload-first.md)
- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
