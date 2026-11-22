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
