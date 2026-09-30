# M3.11 combined qualification evidence

This document maps the qualification and production evidence boundary for the
[accepted M3.11 plan](../plans/milestone-3.11.md). The report validator is P6a,
the [combined live producer](m3-11-backup-recovery.md#combined-live-qualification)
is P6b, and the explicit production controller is P6c. Report validation alone
does not run qualification, authorize production convergence, enable rotation,
or establish live-provider behavior.

## Existing gate, explicit milestone

`scripts/m3_10_qualification_report.py` remains the report entry point. Its
explicit `--milestone 3.11` mode requires the new
`lowerduckpond-m3-11-installed-spaces-v1` envelope. The default M3.10 mode
continues to accept its original formats for their original purpose. Neither
mode accepts the other milestone's format; relabeling an old report cannot add
combined evidence. P6b adds `just m3-11-spaces-qualification`; final execution
waits for P6c's production handoff and final merged inputs. Operators must not
construct these receipts by hand.

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

Failure evidence is separate from these passing receipts. Fresh fixtures retain
bounded private archive exception histories during the original execution,
before diagnostic replay. `test_archive_failure_capture.py` covers preservation
across successful calls and cleanup, limits, private-data exclusion, unsafe paths
and unchanged failures when capture is unavailable.
`test_qualification_archive_failure.py` covers independent host attribution,
exact correlation matching and preservation of original failure reports. The
installed archive boundary probe checks capture in each real helper sandbox.
These observations grant no qualification, recovery or deletion authority and
cannot retrospectively explain a failure with missing evidence.

`test_qualification_deadline.py` exercises real controller subprocesses,
termination handlers, surviving descendants, external interruption and a stalled
reporter. It verifies the original exit status, last entered phase and separately
collected failure report even when a child's TERM handler exits zero.
It also covers direct controller SIGKILL with a truncated timing append and
injects an exhausted reap wait after a real timeout. The wrapper regressions
target its PID during a foreground command and retain default M3.10 cancellation.
`qualification-exit.json` is diagnostic-only and cannot supply missing combined
receipts. The [live deadline amendment](../plans/milestone-3.11.md#live-qualification-deadline-amendment)
changes the execution ceiling, not this envelope or its uninterrupted proof.

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

Public interruption evidence also retains the independent activity hashes and
fresh absence hash from cancellation before process stop. The private Unix
socket cancels applications while the same Caddy process completes its DNS
cleanup; it is not a new provider writer. `test_m3_11_public_control.py` exercises
the actual Unix HTTP transport, unsafe socket metadata, active configurations,
response bounds and the stopped inventory's exact socket exclusion.
`test_m3_11_public_recovery.py` and `test_m3_11_dns_witness.py` cover ordered
cancellation/absence/stop/reboot, failed reads, deadline exhaustion, original
account checks and the shared observation bound. Live evidence still requires
the original ordered cold attempt and final public TLS and teardown observations.

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
continue to cover the legacy gate. The producer must supply installed and
secure-workstation evidence before the new envelope can qualify an M3.11 rollout.

## Production transaction evidence

The explicit controller consumes the exact original qualification report before
creating a transaction. Its phase records prove the actions in the
[production convergence procedure](m3-11-backup-recovery.md), separately from the
disposable live qualification. They cannot substitute for that qualification.

The component tests below live in `tests/infrastructure/`, except the candidate
tests explicitly listed under `packages/static-host-agent/tests/`.

| Required invariant | Component and process coverage | Installed or operator evidence |
| --- | --- | --- |
| Original report, source, artifact, inputs, target, chronology and fresh provider checks precede migration. | `test_m3_11_production_controller.py`, `test_m3_11_production_preflight.py`, existing qualification-report and input-equivalence tests. | Original private qualification report and retained artifact; fresh provider/host observations from the secure workstation. |
| One live controller and action own the transaction; lost ownership drains descendants and preserves service fences. | `test_m3_11_production_lease.py`, `test_m3_11_production_session.py`, `test_m3_11_production_transport.py`, `test_m3_11_production_remote.py`, `test_m3_11_production_fence.py`. | Actual SSH/systemd action units, service conditions and original drain observation. |
| Complete proposals survive interrupted publication without invented or rewritten history. | `test_m3_11_production_journal.py`, `test_m3_11_production_replica.py`, `test_m3_11_production_proposals.py`. | Matching original workstation/host chains and retained proposals across a fresh controller session. |
| Bootstrap initializes the original namespace and repository-bound lineage before recovery activation. | `test_m3_11_production_initialize.py`, `test_m3_11_production_gate.py`; candidate `test_production_namespace.py` and `test_production_lineage.py`. | Real bootstrap playbook, original namespace bytes, lineage/genesis snapshot and original repository binding. |
| Each activation uses two real converges; the second has zero changes and neither has failed, unreachable, rescued or ignored tasks. | `test_m3_11_production_converge.py`, `test_m3_11_production_workflow.py`. | Hash-bound actual Ansible recaps, variables and logs for recovery activation and subsequent rotation activation. |
| Retried backup verifies the original coherent capture and SQL, preserving resource limits and protected history. | `test_m3_11_production_backup.py`; candidate `test_production_database.py`, `test_production_capture.py`, `test_production_backup.py`, `test_production_rollout_backup.py`. | Actual bounded MariaDB/Restic capture and private restoration, original descriptor/index/snapshot and exact retained proof. |
| Completed invocation performs fresh inspection without deployment, capture or new receipts. | `test_m3_11_production_observe.py`, `test_m3_11_production_controller.py`, `test_m3_11_production_workflow.py`, backup inspection tests. | Unchanged original records and capture, fresh provider/repository checks, dark publication, enabled recovery/rotation and active required timers. |

Local native checks use disposable credentials and storage. Even a complete
local playbook rollout is diagnostic evidence: it cannot establish Spaces policy,
public-CA behavior, live qualification or actual production deployment. Keep
partial native runs and failed CI results separate from completed proof. Final
qualification must bind the merged input-changing revision; production execution
remains the operator's explicit secure-workstation step.

`just check-installed-group production-rollout` repeats the installed phase
engine on an owned host through the real production playbooks and SSH lease.
It deliberately stops after namespace initialization and after retaining the
original verified backup proposal, then resumes with fresh controller owners.
It compares original journal bytes and retained capture hashes/inodes/timestamps
through completion and repeated inspection. Its synthetic qualification binding
is labelled diagnostic and is never supplied to the public qualification gate;
the controller gate is covered separately above. This fixture does not record
production completion or replace final live qualification.

## Separate failed-fixture retirement evidence

The [retirement exception](../plans/m3-11-failed-fixture-retirement.md) leaves the
original qualification failed. Its `lowerduckpond-m3-11-failed-fixture-archive-retirement-v1`
receipt is an allowlisted administrative diagnostic. The combined report,
qualification report and production journal validators reject it. Original
failures, timestamps and artifact/input bindings are never repackaged as a pass.

| Retirement boundary | Evidence |
| --- | --- |
| Original run, artifact, endpoint, tenant/deployment and snapshot authority; no invented DNS history | `test_m3_11_retirement_bindings.py` rejects changed bindings, public-CA progress, foreign canonical archive ownership, nonempty names and ambiguous zones. Original public inputs are retained; only fresh absence is observed. |
| Original container incarnations, durable stop intent and untouched unused MinIO | `test_m3_11_retirement_containers.py` exercises lost stop responses, restarts/replacements, restart policies and unexpected local-server settings. Only three saved IDs acquire stop authority. |
| Private durable copies and clean offline state | `test_m3_11_retirement_files.py` exercises truncated/oversized streams, symlinks/hardlinks, inadequate capacity and interruptions around no-replace publication. Real ext4 images reject unsafe inodes/dirty state and remain byte-identical under read-only inspection. |
| Explicit digest approval, exact independent version inventories and interruption recovery | `test_m3_11_retirement_transaction.py` exercises every before/after-delete interruption, lost responses, changed evidence/inventory and foreign objects. Only a durable pending exact version can be reconciled as absent. |
| Local exclusion and diagnostic privacy | `test_qualification_storage_lease.py` launches real competing/inherited processes through `uv`. CLI tests reject private receipt fields and suppress provider error strings; expanded private probe bounds leave default diagnostic limits unchanged. |
| Real failed restore, real versions and retained original bytes | The fixed installed `failed-retirement` case deliberately faults the private archive helper after coherent restoration. It proves exact MinIO version removal with separate principals and retention of original source/destination job/result/audit bytes, protected Restic objects, stopped hosts and private copies. Its CI disposition states archive-only absence and no destruction authority. |

Local tests do not prove live Spaces deletion semantics or provider DNS absence.
Those remain fresh secure-workstation gates under the exact original transaction
and separately approved plan. A later fresh qualification must produce its own
complete live report before production convergence can be authorized.
