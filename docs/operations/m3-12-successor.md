# M3.12 successor rollout

`just m3-12 prepare PATH` reads a pinned production successor proposal and
its phase views from a private journal without applying it.

The successor uses the original accepted M3.11 record chain as a predecessor.
Keep that chain and its selected namespace intact. The new transaction binds
its own lease, reviewed candidate and configuration for each authorized phase.

The installed `successor-rollout` case builds the accepted M3.11 source from
Git and uses the existing corrected bootstrap harness to complete the dark
rollout on the owned fixture. The case retains
its original journal. The case then stages and repeats the new candidate
dark, initializes the existing root-owned launch record and verifies its exact
retry, and converges and repeats enabled. It exercises physical rollback and
same-policy reactivation through the native Caddy selector and issuance gate.
It interrupts the owned action after selector handoff, checks that issuance
stays closed, and reconciles the original rollback under a fresh lease.
After an actual fixture reboot it checks
issuance and reads the original launch bytes from a new native Restic backup.
Each converge uses the verified SSH
transport to the same owned Docker fixture. The installed admission has no
authority for a Droplet or production host.

The hosted successor uses the 90-minute runner resource tier shared with
`production-rollout`. In the same CI run, the production rollout completed in
40 minutes 42 seconds, and the successor reached its former 45-minute ceiling
inside the before-reboot witness. Two measured converge/idempotence phases on
that runner took about six minutes together. The successor adds two such
pairs, launch and rollback checks, reboot, and Restic readback after the
predecessor flow. The runner ceiling leaves room for that work and fixture
accounting. It does not participate in any readiness or acceptance decision.
[Measured CI run](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/44925792356)

The installed diagnostics include `m3-12-successor-progress/*.json` with fixed
stage names, timestamps, and started or completed status. A started record
without completion identifies the last observed operation and leaves its
result unresolved. The files contain no command output or credentials and
carry no qualification authority.

The initializer uses the canonical pre-enablement admission, same original
intent, and existing descriptor-relative publication primitives. Publication
on a successor requires the independently reopened launch and namespace.
Restoration of successor launch authority requires its original admission,
intent and receipt as well as the backed-up record. The installed workflow and
local contract vectors confer no provider, production or restore authority.

The native production entry point is `m3-12-successor-action`. It reads the
root-owned proposal and verifies the staged candidate before importing any
candidate code. The installer can stage a verified artifact with
`--stage-only` while preserving the existing selector. Ansible uses
`ldp_m3_12` only for a host with the native transaction. Its SSH and piped
commands remain inside the distinct, descendant-tracked successor action unit.
The original M3.11 journal and its legacy connection stay separate.

The native action consumes a protected enrollment, proposal, current
invocation and independently observed readback. The current invocation must
bind the current lease and production preflight. The `start` and `reconcile`
operations consume exact phase readback. `launch` also requires the original
committed final-backup verification observation, exact pre-enablement
admission and its nested complete-disposable proof. The provider and live
evidence producers belong to later slices and are required before this path
can act on a real target.

`rollback` requires a scoped decision at the original journal head.
`resume-rollback` reconciles that same decision under a fresh verified
invocation. Rollback fences issuance under the ordered publication and
tenant-state locks, preserves intent and launch bytes, and confirms the
compatible original Caddy generation before completing. Reactivation
requires the completed dark effect and a fresh same-policy decision.
The fence remains until native readback succeeds, including across caller
loss. Tenant history, retained lifecycle work, or an unrelated active
generation closes the rollback path.

## Disposable Droplet admission

The P4 enrollment producer compares the reviewed OpenTofu allocation with
independent provider readback, guest metadata, and the pinned Ed25519 SSH
identity. It derives a `disposable-droplet` target and a separate enrollment
that binds the run, selected allocation, protected production exclusions,
machine ID, system UUID, and SSH public-key digest. The root adapter consumes
these canonical records, along with a protected launch-attempt record for the
current lease. It checks the connected Droplet's public IPv4 and ID before
passing the original admission to the common launch writer.

After launch, publication reopens the immutable launch chain and checks the
same local host identity without querying the network from a sandboxed
worker. An active controller is required for launch. The already committed
publication record survives controller release. Conflicting local production
or installed authority, revocation, or changed host facts close this path.

The component fixtures exercise this boundary with simulated provider
observations and a real local lease and launch record. The controller must
still establish the provider and SSH observations, distribute the protected
records, and prove the required read-only identity and authority view inside
the real worker sandbox. These fixtures confer no real-provider authority.

The Droplet worker and emergency reconciler mount the dedicated protected
`droplet-publication` directory and three local identity files read-only.
The private controller attempt and prerequisite receipts stay in the parent
outside both service views. Revocation and the publication fence belong in
the dedicated directory so a worker sees changes through the existing mount.
Standalone installed Docker and production successor layouts keep their
existing selection path.

On a verified local Docker daemon with a cached Ubuntu 26.04 Molecule systemd
image, run the offline worker witness with
`uv run --frozen python -m scripts.check_m3_12_worker_view IMAGE`. It builds
and verifies the locked artifact, renders the actual worker unit, and runs
the installed gate after the unit's normal sudo transition. The guest has no
network or host binds. The witness checks a valid identity, missing and
mismatched identity, revocation, read-only mount flags, and exclusion of the
controller directory and SSH private key. Its Droplet facts are synthetic.
The witness queries the booted systemd manager on its private connection.
Each start must produce a fresh test-only stop receipt after the sandbox
checks reach the gate. The receipt records the actual worker exit even if
systemd has already unloaded the unit. Identity and revocation cases must
report the launch-authority denial from the gate.

### Pinned SSH preparation

The P4 controller accepts two independently reobserved allocations and the
Ed25519 host keys from their authenticated provisioning chain. It records
the exact source and restore scopes in the private attempt before connecting.
Each read uses a fresh SSH connection to the approved numeric IPv4 address,
a private single-host key file, and the caller's approved client identity.
The transport disables forwarding and reuse of prior SSH sessions.

The controller runs a fixed standard-library probe over SSH stdin. This
lets the cold restore target report metadata, local identity digests, boot
identity, and selected state before installing the candidate. Both roles
must match their original provider allocation and SSH pin. Preparation
requires an independent restore host with no selected artifact, no launch
record, and publication absent or dark. The controller seals each role's
observation separately so a later transfer failure preserves the first
receipt. Repeated preparation compares the retained originals.

Boot inspection reopens the same approved role and preserves the original
preparation. A changed boot digest on the same host is an observation.
A full reboot assertion still needs the approved operation and service
readback. Provider provisioning, protected enrollment delivery, paired
restore, and ingress verification remain separate controller phases.

For cold restore, the controller reads the protected input directory through
the native bootstrap preflight. It verifies the canonical recovery policy,
the original source fencing receipt and the original origin-pull CA digests.
The machine identities must match the independently observed source and
restore hosts. The controller retains the exact snapshot and input digests
separately from the successful same-host cold readback. The restore journey
still needs repository and archive reads, live fence and ingress verification,
and materialization.

Native reconstruction preserves the original launch and namespace. The
source launch receipt retains its source target binding even when all
original bytes are recovered on the destination. For a launched snapshot,
keep `source-admission.json`, `source-launch-intent.json` and
`source-launch-receipt.json` beside the protected recovery inputs. The
controller validates the original launch chain against the source enrollment,
snapshot policy and namespace. After cold destination readback, it seals
`droplet-restore-target.json` as the native target policy. Its versioned
`dropletRestore` scope binds the source and destination targets and original
launch receipt. The native journal retains that scope alongside the exact
snapshot, source fence and policy. A dark snapshot has no launch receipt
and can only recover with publication disabled.

The destination reads its own root-owned enrollment and the source's original
admission, intent and receipt in the publication view. The native coordinator
rechecks the completed journal, original launch and namespace, destination
identity and selected artifact before setting publication and committing
admission. Ingress cleanup and boot reopen the same proof. The publication
gate requires completed destination admission for the restored source receipt.
The source receipt and restored launch bytes keep their original identity.
The [disposable preparation guide](m3-12-qualification.md) describes protected
delivery and readback through the native role. The installed destination
journey still needs real-host evidence.

Fresh installation uses a separate attempt and pins the reviewed artifact
digest before connecting. The controller requires publication configuration,
artifact selection, and durable launch to be absent before recording the
fresh role. Dark readback verifies the selected content address, dark
publication and absence of launch on the same host and records its boot ID
digest. The installed journey still needs artifact integrity, service health
and real reboot and activation evidence.

Normal CI runs the worker service witness in a separate GitHub-hosted job
when installed selection includes successor rollout. The job builds the
Ubuntu 26.04 systemd fixture and runs the worker with the guest network
disabled. CI synchronizes all locked workspace packages before starting the
witness. The Ansible aggregate requires it alongside the other
selected checks. The witness uses synthetic Droplet identity inputs.
