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
  token restricted to `lowerduckpond.net` with only Zone Read and DNS Edit.
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

The runner reads the backup bucket name and its bucket-scoped runtime key
directly from encrypted production state. Those values remain in child-process
environment only. The Caddy token is installed as a root-owned, Caddy-readable
environment file; the Restic password and Spaces key are installed in a
root-only backup environment file.

The Caddy token intentionally has no expiry because unattended DNS-01 renewal
is an availability dependency. Rotate it annually by issuing an overlapping
replacement, rerunning configuration with the replacement, confirming an ACME
operation, and then revoking the old token.

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

## Routine operations

After reviewed configuration changes merge, repeat `just
configure-production`. Ansible validates a candidate Caddyfile before its
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

- site content under `/srv/lowerduckpond`;
- Caddy state under `/var/lib/caddy`;
- provisioner state under `/var/lib/lowerduckpond/manifests` and
  `/var/lib/lowerduckpond/audit`; and
- a staged, compressed dump of all MariaDB databases.

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
