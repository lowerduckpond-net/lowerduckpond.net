# 0019: Constrain static archives and exports

- Status: accepted
- Date: 2026-08-22
- Storage placement amended by: [ADR 0025](0025-separate-tenant-archives-from-platform-backups.md)

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
the entry ceiling. An explicit directory record and a parent implied by one or
more descendants represent one materialized directory and consume one entry
only when their decoded component sequences are exactly equal after separator
validation and removal of the explicit directory marker but before NFC
normalization. The same exact implicit parent from multiple descendants also
coalesces and counts once. Still reject duplicate explicit directory records,
any path used as both file and directory, and any distinct pre-NFC spelling
whose NFC-normalized or case-folded path collides with another explicit or
implicit entry. Preserve original spelling and provenance until these checks
complete; normalization cannot erase evidence needed to distinguish an exact
merge from an ambiguous collision.

Reject `cdn-cgi` as a normalized, ASCII-case-insensitive first tenant path
component. Cloudflare reserves `/cdn-cgi/` on every proxied hostname, so
accepting that subtree would create files that cannot be served under their
manifested URL. Apply the same rejection after removing the portable-bundle
envelope prefix and before import or restore can construct a release.

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

Apply these initial limits during root-owned intake and again before and during
root-side extraction:

- at most 100 MiB in an uploaded deployment ZIP;
- at most 120 MiB in an uploaded v1 portable bundle presented to the explicit
  import path, whose content remains subject to the limits below;
- at most 100 MiB of extracted regular-file content;
- at most 5,000 extracted entries in total, counting both regular files and
  directories;
- at most 25 MiB in one file; and
- at most a 100:1 declared or observed expansion ratio.

The 1,024-byte path, 32-component depth, 5,000-entry count, and 100-MiB
expanded-content ceilings describe the tenant tree after normalization. A flat
deployment ZIP applies them directly at the structural gate. A v1 portable
bundle instead has these separate raw-envelope ceilings before its fixed prefix
can be removed:

- at most 5,004 central-directory records: `format.json`, `manifest.json`,
  `checksums.sha256`, the `content/` directory, and at most 5,000 tenant records;
- at most 1,056 UTF-8 bytes in a full regular-file member name and 1,057 bytes in
  a directory member whose final byte is its one permitted `/` marker,
  accounting for the 32-byte `lowerduckpond-export-v1/content/` prefix; both
  have at most 34 components after removing that marker;
- the same 255-byte component and 8-MiB central-directory ceilings;
- exactly 46 bytes for `format.json`, at most 16 KiB for `manifest.json`, and at
  most 5,495,158 bytes for `checksums.sha256`, derived from its two metadata
  lines and 5,000 maximum-length tenant-file lines; and
- at most 106 MiB of declared and observed regular-file member data before
  extraction, covering the 100-MiB tenant ceiling plus bounded metadata.

The envelope root is implicit and is not an allowed central-directory record.
The structural gate first normalizes and validates every full member name under
those type-aware envelope ceilings, permits only the four fixed records outside
`content/`, and validates their bounded canonical forms. It removes the one
directory-marker byte before path-length and depth accounting, then strips
exactly `lowerduckpond-export-v1/content/` from descendant names and applies the
ordinary 1,024-byte, 32-component, 5,000-entry, 100-MiB, per-file, collision,
and implicit-parent limits to the tenant subtree. Fixed envelope records and
the implicit envelope root never consume tenant quota. Passing either layer
cannot compensate for failing the other.

The restricted transport adapter enforces the applicable compressed-artifact
ceiling plus the aggregate one-artifact intake and host-free-space bounds while
streaming, before the activator or any ZIP parser can run. The activator repeats
the applicable ceiling while copying the admitted artifact into its immutable
snapshot.

Normalize directories to mode `0755` and regular files to `0644`; discard
executable, set-ID, and other archive-supplied permission semantics. Extract
only into a new root-owned non-public temporary directory and fail closed if
actual bytes or entry counts diverge from preflight metadata.

Every deployment and archive record represents release content with a
`lowerduckpond-release-tree-v1` digest record containing `algorithm: sha256` and
a 64-character lowercase hexadecimal value. Compute SHA-256 over this exact
binary stream:

1. ASCII `lowerduckpond-release-tree-v1` followed by one zero byte.
2. The number of tree entries as one unsigned 32-bit big-endian integer.
3. One record for every normalized non-root directory and regular file, sorted
   by its normalized relative UTF-8 path bytes:
   - a directory is byte `0x44`, the path-byte length as unsigned 32-bit
     big-endian, then the path bytes;
   - a regular file is byte `0x46`, the same length-prefixed path, its content
     length as unsigned 64-bit big-endian, then exactly its content bytes.

Paths use NFC and `/`, with no leading or trailing separator. Include every
materialized parent and empty directory, regardless of whether it was explicit
or implicit in the source ZIP. Do not include the root, modes, ownership,
timestamps, inode numbers, ZIP metadata, or filesystem iteration order; modes
and allowed types are already normalized. The SHA-256 of the exact admitted ZIP
snapshot remains the separately named artifact digest. A portable-bundle digest
is SHA-256 of its complete canonical ZIP bytes. Every producer and verifier
stores the format and algorithm with the value and must continue using v1 for
old evidence after an implementation upgrade.

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
hours or until the authenticated client matching its authorization-job operator
acknowledges the verified download, whichever comes first. It is never readable
through the provisioner; admission rejects another export while that slot is
occupied. Retries with the same authorization job and correlation ID return the
established result. Archive
construction uses the same lock, spool, admission accounting, and cleanup. It
captures the source manifest, its canonical digest, and the selected release
under shared tenant-state. While still holding that lock, root derives the
proposed canonical `archived` manifest by changing only the allowed lifecycle
fields and stores both manifests separately in the non-writable snapshot. The
source manifest is private compare-and-swap evidence and never becomes the
archive bundle's `manifest.json`; the proposed archived manifest is the bundle
manifest.

Archive releases tenant-state to build and move the verified bundle into
durable archive storage. Before making the first remote storage request, and
while still holding the export lock, root creates and syncs a construction
intent and its parent directory. The intent binds the correlation ID, a
root-generated authorization-job ID and unique upload-attempt ID, authenticated
operator, tenant ID, exact source and proposed manifest digests, selected
deployment and content digests, portable-bundle digest and size, and the exact
new durable object identity. The object identity
begins as the bucket and root-generated unique key; before upload, root lists
that exact key and requires it to have no current version, noncurrent version,
or delete marker. It cannot be caller-selected or reuse an existing or
previously bound key. The intent reaches durable `prepared` state before upload
begins.

The archive writer sends the completed local bundle through exactly one
known-length `PutObject` request to the Spaces regional endpoint. Its body size
must equal the intent-bound size and cannot exceed 120 MiB. It does not use a
high-level transfer manager, `CreateMultipartUpload`, `UploadPart`, or any SDK
configuration that may cross a multipart threshold. An interrupted request
therefore leaves either no object version or one complete discoverable version,
never separately billable uploaded parts outside version accounting. The
bucket's incomplete-multipart lifecycle rule remains defense in depth for
non-platform clients; it is not part of archive correctness, reclamation, or
capacity accounting.

After Spaces returns the new version ID, root revalidates that exact version's
bytes and metadata and durably advances the intent to `uploaded` with the
version ID. If the host dies between remote success and that phase update,
reconciliation lists the already-synced unique key to discover and classify all
versions rather than assuming an unversioned delete removed the bytes.

Archive then—without releasing the export lock—acquires publication followed by
exclusive tenant-state. It revalidates the exact source manifest, deployment,
and release digests before committing that already bundled proposed archived
manifest and its archive record. The archive record binds the proposed
archived-manifest digest, selected deployment and content digests,
portable-bundle digest and size, and the bucket, key, and exact Spaces version
ID. Revalidation, export, restore, and deletion address that version rather than
the mutable current-key view. The bundle alone grants no deletion authority
before this transaction commits the record.

Startup and pre-archive reconciliation acquire the export lock and resolve any
construction intent before admitting another archive. A matching lifecycle
intent is reconciled first. If authoritative state then contains the exact
bound archive record, recovery revalidates the durable object and clears the
construction intent only after the lifecycle transaction is durably complete.
Otherwise it uses version-aware deletion to purge every data version and delete
marker for the exact unique key, repeatedly lists that key, and clears
construction intent only after Spaces confirms that no version remains. An
ordinary unversioned `DELETE`, creation of a delete marker, or eventual
noncurrent-version expiration is not successful cleanup. If discovery is
ambiguous or any purge or confirmation fails, root durably records the key and
all known version IDs and markers in the quarantine ledger before changing the
intent. Missing objects and failures before upload become an audited failed
result. An unresolved construction intent or nonempty quarantine ledger keeps
archive admission charged and closed, so process exit or bucket versioning
cannot turn the serialized upload boundary into unbounded remote-object growth.
All version listing and version-specific deletion use the Spaces regional
endpoint and filter the prefix result to exact key equality.

If any source changed, archive records an aborted result and retains no
authorizing archive record; it never applies a stale snapshot. It follows the
same version-aware purge and construction-intent ordering, and records every
unconfirmed version or marker in the root-owned quarantine ledger for bounded
retry and garbage collection. Quarantined objects grant no restore or deletion
authority; archive admission remains closed and its remote capacity remains
charged while the ledger is nonempty, so repeated aborts cannot grow retained
versions without bound. The provisioner cannot create files directly in the
spool or bypass these limits.

Remote archive accounting lists every version and delete marker below the
dedicated `archives/` prefix; it does not rely on the mutable current-key view
or lifecycle expiration. The initial hard ceilings are 25 unique managed keys,
25 total stored data versions or delete markers, and 3,000 MiB summed from the
size of every data version. Before an upload, admission reserves one key, one
version, and the full 120-MiB encoded-bundle ceiling and refuses the operation
if reconciled use plus that reservation would cross any ceiling. Every object
bound by authoritative state, named by a construction or retirement intent, or
recorded in quarantine is charged until an exact version listing proves it
absent. An unknown key, version, or marker is durably quarantined and closes
archive admission; exceeding a ceiling also closes admission but never blocks
the reconciliation and deletion work needed to return below it.

Restore, ordinary deletion, and any emergency deletion that will make an
authoritative archive record unreferenced take the export lock before their
publication and tenant-state transaction. Before changing authoritative state,
root creates and syncs a retirement intent that binds the correlation ID,
authorization-job ID, authenticated operator, tenant ID, transition, exact
preceding manifest and archive record, bucket, unique key, version ID, bundle
digest, and size. The lifecycle transaction may
then either preserve that exact archived state or durably commit the new state,
result, and audit evidence that no longer bind the object. It never deletes the
bundle before that choice is durable.

Startup, pre-archive, and retirement reconciliation resolve any related
lifecycle intent first and inspect all authoritative archive records. If state
still binds the exact object, recovery preserves it and clears only a
retirement attempt whose lifecycle transaction durably rolled back. If the
completed transition made it unreferenced, recovery permanently purges every
version and delete marker for its unique key, confirms an empty exact-key
listing, records the cleanup result, and only then clears and syncs the
retirement intent. Ambiguous state or failed discovery, deletion, or
confirmation leaves the intent or quarantine ledger durable, keeps its full
remote capacity charged, and closes archive admission. Audit tombstones retain
the evidence digest and object identity needed to explain the deletion, not an
authority to preserve or restore the retired bytes. No cleanup may delete a key
while any authoritative tenant record still binds one of its versions.

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
without colliding with envelope metadata. Restore and import reject entries
outside the single envelope root, unknown or duplicate metadata, missing
required entries, and checksum or canonicalization failures before passing the
`content/` subtree through the ordinary deployment validator. Restore accepts
only the exact durable version bound by authoritative archived state. Import
accepts an uploaded v1 portable bundle only for an existing `undeployed`
target and treats its embedded manifest as provenance rather than target state.
The source may be an ordinary `active` or `suspended` export or a downloaded
`archived` export; in every case import creates a new target deployment.

Deployment uploads remain the flat, root-`index.html` ZIP format; a portable
export is not accepted by the ordinary deployment path. The explicit import
path consumes a caller-held portable bundle, while authoritative restore reads
the exact remote version bound by the archived source tenant. Export does not
change site state. A later Git integration must produce the same validated
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
output ceilings coexist with the separate 106-MiB raw member-data ceiling; the
fixed envelope allowance ensures every tenant tree at the ordinary path, depth,
entry, and content boundaries remains representable and restorable.

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
- [DigitalOcean Spaces limits](https://docs.digitalocean.com/products/spaces/details/limits/)
- [DigitalOcean Spaces versioning](https://docs.digitalocean.com/products/spaces/how-to/enable-versioning/)
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
