# Standing authorization and execution readiness

An authentic owner decision and a current execution check have different clocks.
Do not replace the original consent time with the time an operator prepares a
record. Waiting alone does not withdraw standing authority or require new consent.
Explicit action limits, withdrawal, narrower subsequent instructions, owner-set
expiry and credential/cleanup deadlines still apply.

The original `lowerduckpond-m3-11-live-approval-v2` path is unchanged, including its
one-day consent-to-expiry limit and explicit issuance approval. The separate
`lowerduckpond-m3-11-execution-readiness-v1` path supports **retained-lease reuse
only**. It cannot authorize new credentials, target changes, destructive archive
retirement, extra capacity, infrastructure changes or other separately controlled
actions. An existing v2 record is never silently converted or renewed.

## Evidence and exact scope

Keep original owner evidence immutable and private, outside the source checkout.
The standing authorization record has:

- `format`: `lowerduckpond-m3-11-standing-authorization-v1`;
- `consent`: original `approval_reference`, original `approved_at`, and
  `evidence_sha256` binding the retained authentic evidence;
- `scope`: `action: reuse-retained-lease`, exact non-null `lease_id`,
  `policy_sha256`, `targets`, authorized `modes`, and `not_after`.

Use the authentic original timestamp when available. Otherwise `approved_at` is
explicitly `null`; retain reported dates, relay receipt times and capture times in
provenance evidence without substituting them for original consent. A missing
timestamp does not grant authority or require the owner to consent again merely
to fill a field. `not_after` preserves an actual owner-imposed expiry, or is
explicitly `null` only when no applicable owner expiry exists. Policy digests
preserve original lifetime, retention and cleanup limits.

Separately retain an operator assessment of the latest applicable owner direction.
Its fields are `format: lowerduckpond-m3-11-authority-assessment-v1`,
`authority_sha256`, `scope_sha256`, explicit `action_id`, `status`, `checked_at`,
and `check_reference`. Only `status: active` passes. This check includes withdrawal,
subsequent scope restrictions and whether the learned correction justifies the
specific next attempt. A hash, generated file or assessment is not owner consent.
The record producer neither creates authority nor chooses a new action ID.

Maintain the current assessment at one canonical private path. Preserve older
assessment bytes as history before publishing a newer assessment at that path.
The execution record binds this path and the exact assessed bytes; an archived
active copy at another path cannot satisfy the launcher. A withdrawal or narrower
scope must update the current assessment before another submission. There is no
automatic subscription to the conversation backend: the operator is responsible
for reflecting authentic current instructions, not fabricating fresh checks.

## Offline record producer

Prepare the existing attempt proposal with `--reuse-status`, binding the released
failed attempt, original lease manifest/deadline, exact reviewed source/helper,
artifact, controller image, Docker daemon and targets. Its `--expires-at` is the
execution-record expiry. Then record readiness under the standing evidence:

```console
uv run --frozen python -m scripts.m3_11_unattended.operator_readiness \
  --proposal /private/attempt-proposal.json \
  --expected-proposal-sha256 EXACT_PROPOSAL_SHA256 \
  --authority /private/standing-authority.json \
  --assessment /private/current-authority.json \
  --learning-reference CORRECTION_AND_TEST_EVIDENCE \
  --review-reference EXACT_SOURCE_REVIEW_AND_CI \
  --output /private/execution-record
```

The producer rereads and rebuilds bound source facts. It retains original consent
unchanged and records its actual check start as `readiness.checked_at`, separately
from consent. It also requires learning and review references. Companion evidence
is written first; the consumable execution record is published last. Partial
output is never overwritten. Identical completed readback retains the original
clock even after expiry; it is not renewed readiness or permission to execute.
These offline checks do not replace live provider, storage, credential or cleanup
proofs.

When execution is separately in scope, the existing start command accepts the
execution record as `--approval` and requires
`--authority-assessment /private/current-authority.json`. The launcher rereads that
exact current file before admission submission and after the potentially long
admission helper, immediately before launch. Changed, withdrawn, missing or stale
assessment stops execution. Withdrawal during daemon probes may still leave a
local reservation; its exact candidate is preserved for read-only reconciliation,
without launch or replay. The daemon checks the bound assessment snapshot plus
existing native cancel/close guards; this is not instantaneous cross-host
withdrawal fencing.

The existing lock-held first admission record consumes the exact `action_id`.
Refreshing readiness, releasing the use, changing provenance or changing the
candidate UUID cannot reuse that action. An interrupted or partial admission
remains an obligation. A different action requires explicit new scope/learning
reconciliation within standing authority, never an automatic retry. Historical
admission validation uses the original admission time so later readiness expiry
or withdrawal does not block watchdog cleanup, evidence reads or lease release.

## Timing and future bindings

The inherited maximum age is 24 hours for both the current assessment and the
execution record. Assessment age starts at its own `checked_at`; execution age
starts at its own `readiness.checked_at` and ends at `expires_at`. Neither clock
starts at owner consent. These are validity bounds, not performance measurements
or owner reply deadlines. Refresh permitted evidence at execution time; retain
original consent and action identity. An actual owner `not_after`, credential
expiry and cleanup reserve remain independent constraints.

The added work is local bounded private-file validation and a scan of existing
admission records under the already-required ownership lock. It adds no provider
calls, retries, sleeps or timeouts. Existing provider/role/storage/cleanup runtime
budgets are unchanged; measure the changed path and keep the operational minimum
of 1.5 times comparable completed observations. A timed-out or failed observation
is not a completed baseline.

Publishing or merging this source is not live preparation or qualification.
Keep any sealed retirement proposal, executable, source checkout, dependencies
and evidence unchanged. A merge changes the native default-branch workflow source
revision even when the workflow file is unchanged. A separately sealed package
that binds an older native revision must fail closed on that drift and needs an
explicit reviewed binding reconciliation before use. Do not silently rewrite its
pins or expand its action-specific approval.
