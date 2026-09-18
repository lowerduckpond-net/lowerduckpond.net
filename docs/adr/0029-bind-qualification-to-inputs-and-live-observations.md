# 0029: Bind qualification to inputs and live observations

- Status: accepted
- Date: 2026-09-18

## Context

M3.10 proved the installed lifecycle against production Spaces and completed
production convergence. Its report binds a source commit and artifact; all
supporting evidence expires after 24 hours. A completion marker similarly binds
an exact source. Recording completion advances Git even when the qualified
inputs do not change. Treating that new commit as a new installation causes
repeated qualification and creates pressure to deploy merely to record a deploy.

A host-agent digest alone cannot solve this: Ansible, service configuration,
verification code, dependencies, and requirements can change without changing
that archive. Provider behavior and deployed configuration can also change
without a repository commit. These are different reasons to invalidate evidence.

## Decision

### Candidate identity and closeout records

A versioned SHA-256 fingerprint binds every tracked input's repository path,
Git file mode, and content digest. It includes code, dependencies, toolchain
specifications, Ansible and service policy, configuration, tests, scripts,
requirements, and unknown/new paths by default. Git symlinks and submodules are
unsupported and fail closed. Both commits must be available, the evidence
source must be an ancestor of the candidate, and the candidate checkout must be
clean and complete. Git replacement objects cannot substitute another source.

Only non-executable `.md`, `.json`, and `.sha256` files in `docs/records/` and
`docs/threat-model/evidence/` are excluded. These directories are reserved for
historical records, not runtime, build, test, configuration, or requirements
inputs. Introducing such a dependency requires changing this policy first.
All other documentation remains an input, including plans, ADRs, runbooks, and
threat-model requirements. We deliberately avoid a blanket Markdown exemption.

Closeout-only commits go in those record directories. They reference the
original source, artifact, evidence digest, and actual acceptance results.
They do not edit requirements merely to advance milestone status. Updating a
record does not require production convergence. If an operator intentionally
reconfigures an equivalent completed installation, the runner retains its
original accepted source in the completion marker and repeats the live gates.

The artifact must still match independently. A SHA-256 digest of the Spaces
region, archive bucket, and backup bucket binds the storage target without
putting bucket names or credentials into the public report. Runtime credentials
remain subject to fresh capability checks. The completion marker records this
target too; an older marker or changed target cannot authorize qualification
reuse. Changing deployment inputs still requires a new qualified candidate.

### Validity and invalidation

| Evidence | Validity | Invalidation or required fresh proof |
| --- | --- | --- |
| Immutable candidate behavior and installation tests | Historical proof for the original input fingerprint and artifact; no calendar expiry as a historical fact | Changed input content/mode/path, changed artifact, changed requirements or policy, unavailable provenance, or a known regression |
| Full installed interaction with live Spaces, before accepting a new installation | At most seven days from the **oldest** supporting evidence | Expiry, changed candidate or storage target, known provider/OS regression, or failure of any fresh gate |
| Previously accepted, equivalent installation | Completion remains valid without periodic redeployment | Missing/untrusted completion, changed selection or inputs/target, failed live checks, or revocation |
| Host integrity, history/accounting, quiescence, and selected generation | Read anew in the same configuration invocation before host mutation | Any drift or unfinished work stops that invocation |
| Bucket controls, exact remote accounting, edge policy, firewall | Read anew in the same invocation before host mutation | Unknown, missing, foreign, or unsafe state stops that invocation |
| Current archive and backup runtime keys | Fresh disposable-prefix capability proof in that invocation | Failed version/read/delete, pagination, multipart, mutual-denial, or cleanup proof stops that invocation |
| Failed runs, diagnostics, or partial reports | Diagnostic evidence only | Never authorize installation, cleanup, or report promotion |

The seven-day limit is an explicit operating budget, not a measured provider
reliability guarantee. It accommodates one weekly deployment window, including
CI/review delays and a weekend, while bounding the age of full provider behavior
observed before accepting a new installation. Existing fresh probes cover
version reads, delete markers, forced pagination, multipart create/abort, mutual
bucket denial, and cleanup. They do not cover the complete installed full-size
archive path or injected recovery behavior. Spaces can change those semantics
without a visible configuration change; Ubuntu package repositories and base
images also contain mutable inputs within the declared platform bounds.

We accept up to seven days of residual uncertainty for those unobserved changes,
with fresh controls and exact candidate checks immediately before mutation.
A known regression revokes evidence immediately regardless of age. There is no
claim that either 24 hours or seven days eliminates that risk. Compared with the
previous blanket day-long window, this avoids repeating a multi-hour run just
because an otherwise unchanged review spans days. It does not schedule weekly
full runs or redeployments for an already accepted equivalent installation.
S3's independent installed case may later support a cheaper, separately reviewed
refresh of provider-specific proof; it does not replace the full gate here.

`scripts/qualification-revocations.json` records revoked sources, artifacts,
report digests, and input digests. A known regression must be recorded there as
part of its correction. The policy file itself is an input, so changing it also
invalidates earlier candidate fingerprints. An unavailable/malformed policy
fails closed. Revocation never authorizes repair or destruction of live state.

### Report lifecycle and migration

New CLI-created reports use `lowerduckpond-m3-10-installed-spaces-v2`, retaining
the original source, artifact, timestamps, storage evidence digest, six passing
phases, and exact zero final accounting. They add input-policy, input-fingerprint,
and storage-target digests. Verification recomputes both source trees; it does
not trust a caller-supplied equivalence assertion. The report is not rewritten
when a later record-only commit consumes it.

The live wrapper captures source, input fingerprint, and storage target before
the first provider proof. Packaging must match that original capture. Loading
a different bucket pair later cannot bind the old run's proof to the new target;
missing capture or unsuitable Git provenance fails before the long lifecycle.

Report **creation** retains the 24-hour input/phase packaging bound and existing
final-proof chronology checks. This is a bound on assembling one completed run,
not the lifetime of an already-created v2 report. Packaging stale partial work
cannot produce newly dated evidence. Future timestamps remain rejected outside
the existing five-minute clock tolerance. A newer envelope timestamp cannot
hide expired oldest evidence.

Existing v1 reports keep their exact-source, 24-hour consumption policy; they
are not relabelled or silently promoted to wider scope. Existing two-field
completion records remain readable as completed predecessors, but lack storage
target provenance and cannot authorize the new reuse path. The next deliberately
qualified and accepted installation records the new target-bound completion.
The already completed M3.10 deployment remains complete throughout this
migration; it needs no repeat deployment to record this policy's merge.

The replacement live workflow must pass complete secure-workstation
qualification before it is used as release authority. During sustainability
implementation, collect that proof with the final changed harness rather than
performing redundant intermediate production deployments. Local tests and CI
validate the policy machinery; they do not manufacture live-provider evidence.

## Consequences

Administrative records can advance independently of qualification. Production
still requires reviewed current main, exact artifacts, verified history, fresh
live controls, and successful convergence/idempotence/acceptance. No new cleanup,
retry, credential distribution, or publication authority is introduced.

Broad input inclusion may conservatively require qualification for changes that
ultimately prove irrelevant. Narrowing the input map is a reviewed policy change,
not a PR label or an operator override. Mutable realized OS/image versions are
not claimed to be reproducible merely because their declared versions match;
S1 records environment/timing detail and existing installed/host acceptance
continues to enforce the supported platform boundaries.

## Alternatives considered

- Keep exact Git identity and 24-hour expiry for everything: preserves the
  documented repeated-closeout problem and does not distinguish actual drift.
- Use only the artifact digest: misses installation, harness, policy, and
  requirements changes.
- Exempt all documentation: silently ignores changes to normative requirements.
- Make full live-provider evidence valid indefinitely: leaves unobserved provider
  and platform changes unbounded before a newly accepted installation.
- Extend expiry without identity and live checks: does not establish that the
  old proof applies to the candidate or current operating conditions.

## References

- [Sustainability plan](../plans/m3-operational-sustainability.md)
- [Convergence runbook](../operations/m3-10-convergence-preparation.md)
- [Security-boundary qualification](0022-test-static-publication-as-a-security-boundary.md)
