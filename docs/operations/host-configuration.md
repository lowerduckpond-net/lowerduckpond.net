# Host configuration operations

Milestone 2 configuration runs from the trusted operator workstation. The
DigitalOcean Cloud Firewall admits SSH only from the administrative CIDR, so a
GitHub-hosted runner must not be given temporary public SSH access. The
administrative private key also remains outside GitHub.

## Credential boundaries

Prepare these values in a trusted shell; do not write them to the repository or
paste them into chat:

- `ANSIBLE_PRIVATE_KEY_FILE`: the local path to the backed-up, passphrase-
  protected `lowerduckpond.net-admin` private key. Load it into `ssh-agent`
  before the run.
- `ADMIN_SOURCE_CIDRS_JSON`: the same JSON CIDR list used by OpenTofu.
- `CADDY_CLOUDFLARE_API_TOKEN`: the dedicated, non-expiring account-owned
  token restricted to `lowerduckpond.net` and `lowerduckpond.com` with only
  Zone Read and DNS Edit. The current `.net`-only token must be replaced before
  Milestone 3 configures the tenant zone.
- `RESTIC_PASSWORD`: a new high-entropy value of at least 32 characters,
  backed up separately from DigitalOcean. Restic cannot recover repository
  data without it.
- `OPENTOFU_STATE_ACCESS_KEY_ID` and
  `OPENTOFU_STATE_SECRET_ACCESS_KEY`: the bucket-scoped production-state key.
  Recover these from the encrypted bootstrap state held in operator custody if
  they were originally copied only to GitHub environment secrets.
- `OPENTOFU_ENCRYPTION_PASSPHRASE`: the production state passphrase, not the
  bootstrap passphrase.
- `OPENTOFU_STATE_BUCKET` and `SPACES_REGION` (`nyc3`).
- `STATIC_OPERATOR_PUBLIC_KEY` and `STATIC_OPERATOR_PRINCIPAL`: beginning with
  M3.6, the public half of the separately backed-up dedicated Ed25519 operator
  key and its stable audit principal. The private key never enters the
  repository, Ansible variables, or the production host.

The runner reads the backup bucket name and its bucket-scoped runtime key
directly from encrypted production state. Those values remain in child-process
environment only. The Caddy token is installed as a root-owned, Caddy-readable
environment file; the Restic password and Spaces key are installed in a
root-only backup environment file.

The Caddy token intentionally has no expiry because unattended DNS-01 renewal
is an availability dependency. Rotate it annually by issuing an overlapping
replacement, rerunning configuration with the replacement, confirming an ACME
operation, and then revoking the old token.

## M3.5 dark-host starting gate

M3.5 changes ownership and backup scope but intentionally cannot publish a
tenant. From clean, current `main`, with the administrative key loaded and
`ANSIBLE_PRIVATE_KEY_FILE` set, use the supported x86-64 Linux trusted
workstation and run the read-only gate first:

```console
just preflight-m3-dark-host-production
```

It fetches `origin/main`, refuses any branch or working-tree drift, builds the
locked Linux x86-64/Python 3.14 host-agent artifact twice and requires
byte-identical output, verifies it with the pinned Python 3.14 runtime, and then
reads the production host to prove its architecture,
the absence of tenant history from the retired Milestone 2 directories (while
recognizing only byte-identical Ubuntu skeleton files and the exact empty
cloud-init locale marker in the old provisioner home), zero tenant route
inputs, active Caddy service, and the existing HTTPS fixture. It makes no
production change. Record the reported artifact SHA-256 and stop here until
the live convergence is explicitly authorized.

The subsequent `just configure-production` repeats this preflight before its
first mutation. Its first converge installs that exact artifact beneath its
SHA-256, atomically selects it, removes only proven-empty retired directories,
creates the root-owned static state and release layout, and installs a disabled
issuance gate plus an inert worker unit with a private 64-MiB/4,096-inode
workspace. Caddy contains no tenant import, and both job issuance and any
tenant-bearing Caddy candidate fail closed while
`static_publication_enabled` is false.

Configuration rollback is forward-only across this ownership migration. Keep
the current M3.5 Ansible roles, reproduce a preceding reviewed M3.5 artifact in
a separate clean x86-64 Linux worktree, and require its digest to equal the
SHA-256 recorded for that convergence. Then select it with the current roles:

```console
M3_DARK_HOST_ROLLBACK_ARTIFACT_PATH=/absolute/path/to/static-host-agent.tar \
M3_DARK_HOST_ROLLBACK_ARTIFACT_SHA256=<recorded-sha256> \
just configure-production
```

The command rejects a missing, relative, linked, partially specified, or
digest-mismatched artifact before convergence. The first M3.5 convergence has
no preceding host-agent artifact, so a failure remains dark and is repaired by
a reviewed forward fix; do not reconverge M3.4. In every case, retain the
root-owned state layout and do not recreate the retired provisioner-writable
home or job, manifest, or audit trees.

## First convergence

Before connecting, independently verify the current SSH host fingerprint from
the DigitalOcean console:

```console
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Compare it with a local `ssh-keyscan lowerduckpond.net`, then add only the
verified key to the operator's `known_hosts`. Never work around a mismatch by
disabling host-key checking.

Load the administrative key, export the values above, and run:

```console
ssh-add "$ANSIBLE_PRIVATE_KEY_FILE"
just configure-production
```

The command performs a read-only OpenTofu state initialization and output
read; it never plans or applies infrastructure. It then:

1. converges the hosting node;
2. converges it again and requires `changed=0`;
3. validates public listeners, Caddy, rootless Podman, MariaDB, timers, and the
   Restic repository; and
4. restores the latest snapshot into a temporary directory and verifies the
   known static fixture before deleting the temporary copy.

The initial converge places the first encrypted backup under
`backups/lowerduckpond-production-01` in the existing production bucket.

The first M3.5 production convergence completed on 2026-08-30 from source
revision `73c76254cf3aba05c3b7ecf70a01a2cd8e158d44` with pinned host-agent
artifact SHA-256
`3709daa0fd2465a73ae6b0c7dd0d6137cf0ec747e11e5e670df084113265d43b`.
The guarded runner passed its repeated preflight, idempotent second converge,
production acceptance, backup, and disposable restore. Static publication
remained disabled.

## M3.6 authenticated-execution starting gate

M3.6 installs a separate SSH identity for routine static operations and the
bounded systemd handoff that consumes its opaque authorization jobs. It still
cannot publish a tenant: production inventory keeps
`static_publication_enabled: false`, the forced command checks that flag before
reading a request, and every lifecycle handler remains mutation-free until its
later phase.

Before the live converge, create a dedicated passphrase-protected Ed25519 key
on the trusted workstation. Do not reuse the administrative key. Back up the
private key and its passphrase separately before proceeding; only the public
half is supplied to Ansible. Choose one stable audit principal that matches
`[A-Za-z0-9][A-Za-z0-9._@-]{0,127}` and does not change merely because the key
is later rotated. For example:

```console
operator_key="$HOME/private/lowerduckpond.net/static-operator"
install -d -m 0700 -- "$(dirname "$operator_key")"
ssh-keygen -t ed25519 -a 100 \
  -C 'lowerduckpond.net-static-operator' \
  -f "$operator_key"

export STATIC_OPERATOR_PUBLIC_KEY="$(<"${operator_key}.pub")"
export STATIC_OPERATOR_PRINCIPAL='production-static-operator'
```

The example path and role-based principal are suggestions, not protocol
requirements. Prefer a non-personal role alias so audit identity does not
unnecessarily disclose an operator's real-world identity.
After independently confirming the private-key backup, load the administrative
identity and run the read-only gate from clean, current `main`:

```console
export ANSIBLE_PRIVATE_KEY_FILE=/absolute/path/to/lowerduckpond.net-admin
ssh-add "$ANSIBLE_PRIVATE_KEY_FILE"
just preflight-m3-6-production
```

The gate rejects a missing, linked, malformed, non-Ed25519, or reused operator
identity and an invalid principal. It then repeats the M3.5 reproducible-build,
installed-artifact, SSH-host-key, Caddy, and local-HTTPS proofs. Its additional
remote checks require the exact disabled publication configuration and status,
the selected artifact to be either the recorded M3.5 identity or the exact
current reproducible candidate (so an interrupted converge remains repairable),
exact and empty platform, tenant, authorization, intent, intake, export, audit,
release, and Caddy-generation inventories; the exact authoritative-state and
authorization parent inventories; zero to four safely materialized protected
lock inodes with no unknown lock name; and no instantiated static worker. The
zero-lock M3.5 starting state and safe subsets left by an interrupted M3.6
converge are accepted. The command only reads local and production state.

Stop after the successful preflight until production convergence is explicitly
authorized. The subsequent `just configure-production` repeats this M3.6 gate,
then follows the existing two-converge, zero-change, acceptance, backup, and
disposable-restore sequence. It installs the public operator identity and
principal, never the private key. Publication remains disabled throughout.

The M3.6 production convergence completed on 2026-08-30 from source revision
`5c14355babbf6aab27db7c976b99f1ffe22e9c49` with pinned host-agent artifact
SHA-256
`ed1c2a95f1aa7b17dcd949c0efb5f815af59e6fae46e0edf3a1f08e3ea4da357`.
The guarded runner passed its repeated preflight, idempotent second converge,
production acceptance, backup, and disposable restore. A dedicated-key SSH
probe returned status 78 and `publication_disabled` from the installed forced
command. The private key and passphrase were separately backed up, the stable
audit principal is `production-static-operator`, authoritative state remained
empty, and publication remained disabled.

## Routine operations

After reviewed configuration changes merge, repeat `just
configure-production`. Ansible first repeats the current M3.6 production gate
and validates a candidate Caddyfile before its
atomic rename, and systemd validates the live configuration before every
reload.

Milestone 2 grants the provisioner no sudo capability and no access to Caddy's
configuration, admin socket, or empty root-owned route import directory. Tenant
publication begins in Milestone 3, where archive validation, immutable content
releases, and root-owned Caddy routes will be activated through one privileged
contract. Keeping content and route activation together prevents a validated
route from later following a provisioner-controlled link outside its tenant
release.

Useful host-side checks are:

```console
sudo systemctl status caddy mariadb prometheus-node-exporter
sudo systemctl list-timers 'lowerduckpond-*'
sudo journalctl --unit lowerduckpond-backup.service
sudo journalctl --unit lowerduckpond-health.service
sudo /usr/local/libexec/lowerduckpond/restic-check
```

The node exporter listens only on `127.0.0.1:9100`. Milestone 2 records Caddy,
database, rootless-runtime, scheduled-backup, and weekly-retention health as
Prometheus textfile metrics and in journald. Every Restic repository operation
takes the shared host lock in the root-only backup working directory before
loading the active backup configuration. Snapshot discovery, retention, and
restore select only snapshots tagged `scheduled`. Convergence and integration
tests run the initial jobs through their hardened systemd units so the scheduled
execution boundary is exercised before deployment. A central collector,
dashboards, and routed alerts belong with the control-plane observability work
rather than consuming the small development Droplet now.

Scheduled snapshots contain:

- immutable site releases and the platform fixture under `/srv/lowerduckpond`;
- Caddy state under `/var/lib/caddy`;
- authoritative static platform, tenant, authorization, intent, audit, and lock
  state under `/var/lib/lowerduckpond/static`; and
- a staged, compressed dump of all MariaDB databases.

The static intake and authenticated-delivery export spool are explicitly
excluded. Caddy runtime generations and its secret environment are also
excluded and are not backup sources. Every scheduled snapshot carries the
active backup-scope tag, so convergence creates and restores from a new
snapshot when the authoritative source or exclusion set changes rather than
mistaking an older Milestone 2 snapshot for current evidence.

The M3.6 trusted-workstation client is available as `just static-operator` and
requires explicit `--host`, `--identity`, and `--request` arguments, plus
`--artifact` for deploy/import and `--export` for an export destination. It
rejects an exposed private-key file, noncanonical or oversized request,
artifact mismatch, response/request mismatch, unframed response, and export
length or digest mismatch. The private key remains outside this repository.
The final M3.6 implementation replaces the initial denial adapter with a fixed
root entry point, but production continues to reject independently of request
bytes while `static_publication_enabled` is false. The separately authorized
M3.6 convergence installed that implementation while retaining the disabled
flag. The client cannot allocate a job while the flag remains false; hermetic
enabled-path fixtures return only mutation-free terminal
`not_implemented` results until the lifecycle handlers arrive in M3.8.
Startup recovery starts at most two committed jobs per pass beneath one
aggregate 512-MiB/64-task slice. Successful worker completion triggers the next
pass; failures fall back to a running one-minute timer, which also safely
resumes interrupted or coalesced handoffs without a zero-delay retry loop. A
root-owned, atomically replaced recovery cursor rotates each pass through the
sorted pending inventory, so a persistently failing prefix cannot consume every
batch or starve later stranded jobs. The cursor advances before non-blocking
handoff; a lost handoff therefore defers that job only until the bounded queue
wraps rather than pinning recovery to it.
Each worker begins as `ldp-provisioner` and crosses exactly the installed
UUID-only sudo rule into the root-owned executor. Its no-new-privileges
exception exists only for that transition; its capability bounding set retains
only `CAP_SETUID` and `CAP_SETGID`, neither is ambient, and the remaining unit
sandbox stays in force. Command-specific sudo policy disables Ubuntu's default
pseudo-terminal allocation only for the fixed executor, so the worker keeps its
PTY devices masked. The worker permits process creation, pipes, resource-limit
inspection/setup, and local sockets because `sudo` and PAM require them to spawn
the fixed executor. Its private network namespace permits only `AF_UNIX`, its
capability set cannot raise hard resource limits, and its shared slice and
per-unit cgroup/rlimit ceilings bound all descendants. The root reconciler also
retains only `AF_UNIX` socket access for its non-blocking systemd handoff inside
a private network namespace. Untrusted
archive helpers keep their own no-new-privileges and no-child-process policy.
Startup repair snapshots authorization state only after
it owns the intake lock, so an upload committed while repair waits cannot be
mistaken for abandoned bytes. Exact retries resolve against the original
immutable source binding and discard redundant terminal-job uploads
immediately. Stray intake bytes never create authority.

The current retention policy keeps 7 daily, 5 weekly, and 12 monthly scheduled
snapshots. A change to any of those counts invalidates the prior maintenance
evidence and causes convergence to apply the new policy immediately.

Milestone 3 audit rotation adds root-created snapshots tagged
`lowerduckpond-audit-archive`. Those snapshots are not members of the ordinary
7/5/12 retention sets and must be preserved by `forget` and `prune` until a
later explicit audit-retention policy authorizes their removal. Rotation may
delete a local audit segment only after restoring and verifying its protected
snapshot and durably indexing that snapshot; backup maintenance and recovery
must enumerate and verify the protected archive chain.

The root-only backup environment is activated with one atomic rename and carries
the repository, node name, retention policy, credentials, and separate backup
and maintenance status fingerprints together. A scheduled job therefore sees
either the complete old configuration or the complete new one. Changing the
repository or node cannot reuse old local success evidence, while changing any
retention input invalidates only maintenance evidence. Convergence recovers
backup status only from matching scheduled snapshots and immediately runs
retention for a new repository, node, or policy scope before health can become
green. Local repositories are also added explicitly to the backup services'
otherwise narrow writable-path sandbox.
Paths below `/home`, `/root`, and `/run/user` are rejected because the service
sandbox deliberately hides those trees with `ProtectHome=true`. A local
repository must be a dedicated, root-owned `0700` directory; convergence refuses
to change the attributes of an existing path. Its canonical path must also be
disjoint from every backed-up directory—it can be neither an ancestor nor a
descendant—so it cannot disrupt a service tree or ingest repository files that
Restic is writing.

The exact Caddy build inputs and the supported Ubuntu package ranges live in
`platform/versions.yml`. Ansible installs distribution packages normally so
security updates remain available, then refuses to converge when MariaDB,
Podman, or Restic falls outside the acceptance-tested range. Widening a range
therefore requires a reviewed change and a complete Molecule run.
