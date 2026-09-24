# M3.11 combined qualification evidence

This is the P6a evidence boundary for the
[accepted M3.11 plan](../plans/milestone-3.11.md). P5 reconstruction is merged.
The combined live producer and production integration remain P6b work. This
validator alone does not run qualification, authorize production convergence,
enable rotation, or establish live-provider behavior.

## Existing gate, explicit milestone

`scripts/m3_10_qualification_report.py` remains the report entry point. Its
explicit `--milestone 3.11` mode requires the new
`lowerduckpond-m3-11-installed-spaces-v1` envelope. The default M3.10 mode
continues to accept its original formats for their original purpose. Neither
mode accepts the other milestone's format; relabeling an old report cannot add
combined evidence. The operator commands promised by P6 are still pending;
operators must not construct these receipts by hand.

The M3.11 envelope retains every legacy phase (`create`, `prepare`, `converge`,
`idempotence`, `verify`, `destroy`), complete installed accounting, the original
storage acceptance report hash and run ID, and the final independent provider
proof timestamp. The combined receipt supplements that complete journey.
Independent group reports and diagnostic timing JSON cannot replace it.
The new envelope also retains the storage, installed-accounting and individual
legacy phase observation times, so consumption rechecks their original order
without access to the private run directory.

The original source revision, selected artifact, ADR 0029 input policy/digest,
and storage-target digest remain bound by the existing Git ancestry,
records-only equivalence and revocation checks. A records-only descendant
consumes the original report bytes without changing their source or timestamps.
A changed executable, harness, requirement, runbook or unknown input requires
new evidence. No production gate is switched to the new format in P6a.

## Private inputs and shareable output

In addition to the existing private run files, packaging requires:

| Input | Required authority |
| --- | --- |
| `combined-context.json` | Canonical context captured before combined proof begins: run UUIDv7, capture time, original source/artifact/input/target binding, original storage report run UUIDv7 and exact-byte SHA-256, distinct source/destination fixture hashes, dedicated backup-repository hash, selected Caddy binary hash and disposable subject-set hash. |
| `combined-names.json` | Private run binding, separate UUIDv7 nonce and the exact sorted four public-CA subjects. The nonce must differ from the shared run ID. |
| `combined.json` | Canonical completed combined receipt, with that exact context, every phase/check, reconstruction observations, public-CA proof, paired accounting and complete owned teardown. |

All three inputs must exist before their corresponding observations can be
packaged: context and names precede the first combined phase; the final combined
receipt precedes the existing final independent provider proof. Packaging does
not rewrite these files or repair their chronology. An interrupted or failed
run keeps its original receipts and resources under the existing diagnostic and
resumption rules; it produces no passing envelope.

The context's `storage_run_id` and `storage_report_sha256` must match the enclosing
legacy report at both packaging and consumption. Identical candidate inputs and
overlapping timestamps do not permit moving combined receipts between attempts;
the original storage report bytes remain part of the run identity.

The private name nonce generates `m3-11-<nonce-without-hyphens>` below each of
`lowerduckpond.net` and `lowerduckpond.com`, with its wildcard. The manifest
binds these four names to the run; production apex/wildcard names are rejected.
Only the sorted subject-set digest is shared. The nonce and names remain in the
private manifest. The producer must establish ownership before DNS mutation,
use the pinned Caddy build and actual cold-TLS verifier, validate public trust
and loopback presentation, and inspect challenge cleanup. A private or staging
CA cannot satisfy the public-CA receipt. This proof does not change production
namespace or certificate policy.

Digests are lowercase SHA-256. Their byte domains are:

| Field | Bytes hashed by the producer |
| --- | --- |
| Source/destination fixture | Canonical private `{id,name,owner,image}` identity document, with LF; verify the actual Docker identities and ownership before each use. |
| Backup repository | Exact UTF-8 trusted Restic repository string, without LF, naming the dedicated run-owned qualification prefix. Never the production repository. |
| Caddy binary | Exact installed binary bytes, after verifying the configured pinned build. |
| Subject set | Sorted four-subject JSON array, canonical separators and final LF. |
| Snapshot | ASCII full 64-character selected snapshot ID, without LF; the raw ID stays private. |
| Descriptor, index, journal | Exact original canonical document bytes. |
| Phase evidence | Exact private receipt bytes from the completed installed assertions, including their original observations. |
| Certificate evidence | Canonical private certificate-verification receipt, including the actual public chains, selected binary and loopback observations. |
| Source fence / pending inputs | Exact source-fence bytes / canonical private inventory of intentionally preserved source input authority. |

The shareable envelope contains only allowlisted identifiers, digests, counts,
phase outcomes and timestamps. It embeds the combined receipt and its exact-byte
hash. Raw object coordinates, snapshots, events, logs, certificates, names and
credentials remain private. JSON is bounded at 256 KiB; duplicate and unknown
fields, noncanonical new-format bytes and boolean/coerced counts are rejected.

## Required combined observations

Every phase below has original UTC start/end times, a private evidence digest,
and its exact named checks all marked `passed`. Missing, additional, failed or
skipped checks cannot qualify. Phases execute in this order without overlapping
receipt intervals; a timed concurrent mutation belongs inside its containing
backup phase.

| Phase | Required installed observations |
| --- | --- |
| Backup/mutation overlap | Coherent captured boundary, excluded secret canaries and actual concurrent mutation. |
| Protected rotation | Retention guard, interruption/resumption and unchanged historical replay across at least two protected full segments. |
| Reconstruction | Full restore, exact tenant archive versions, retained release digests, audit continuity, excluded-input outcomes, interruption/resumption and trusted regenerated runtime. |
| Reboot | Journal resumption, public-ingress gate and ordinary historical-result replay. |
| Public-CA cold recovery | Empty certificate store; public chain and loopback verification for all four subjects; DNS-01 in both zones; interrupted issuance; reboot with ingress closed; opening only after verification; challenge cleanup. |
| Paired accounting | Original source fenced; destination quiescent; independent archive absence; protected history verified before disposable repository retirement. |
| Owned teardown | Entire run-owned backup prefix removed; independent backup/archive absence; no challenges or remaining owned resources. |

Reconstruction records snapshot/descriptor/index/journal digests, at least two
protected segments and two retained releases, and positive counts for active,
suspended, archived and undeployed tenants. Public-CA observations require four
subjects, two zones, the production Let's Encrypt directory and system public
trust roots. These are proof obligations for the producer; a well-formed
self-authored JSON file is not independent evidence that a test ran.

The source and destination have different accounting obligations. The fenced
source preserves the deliberately excluded pending input and original snapshot
until the drill settles. Its fence and pending-input inventory are hashed.
Destination intents, intake, exports and staging must be empty, quarantine
false, and archive versions/markers/uploads absent. Final teardown additionally
requires zero owned resources, backup objects, archive versions/markers/uploads
and DNS challenges. Only the whole owned disposable backup prefix may be
retired; this adds no production protected-snapshot expiration command.

## Time and consumption

`oldest_evidence_at` includes the original context capture and all earlier legacy
observations. Combined phase chronology must precede the final provider-proof
start (`completed_at`), which precedes `packaged_at`. All evidence must be fresh
at packaging, with at most 24 hours between oldest observation and packaging.
Consumption remains limited to seven days from the oldest original observation.
Refreshing the outer timestamp, packaging late, changing the target or moving a
receipt between runs cannot extend either window. Future-dated evidence fails.

`tests/infrastructure/test_m3_11_qualification_report.py` maps these rejection
boundaries to hostile-vector, chronology, CLI and real-Git ancestry/revocation
checks. Existing M3.10 report, input-equivalence and production-workflow tests
continue to cover the legacy gate. P6b must supply installed and secure-workstation
producer evidence before the new envelope can qualify an M3.11 rollout.
