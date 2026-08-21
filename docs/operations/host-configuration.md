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

The provisioner cannot write Caddy syntax or its live import tree. It writes a
complete declarative set under
`/var/lib/lowerduckpond/caddy-routes-staging`: each regular
`<site-id>.route` file contains exactly one lowercase DNS label for a static
tenant. The sole permitted sudo command, `publish-caddy-routes`, rejects
symlinks, malformed identifiers, malformed or duplicate labels, and every
other input shape. It generates only a hostname matcher, the tenant's fixed
`/srv/lowerduckpond/sites/<site-id>/current` document root, and `file_server`.

The command writes those generated fragments into a root-owned immutable
release, validates that exact release, switches the live symlink atomically
under an exclusive lock, and only then reloads Caddy. A failed reload restores
the prior release. Supporting another route type requires an explicit extension
to this root-owned generator; provisioner-authored Caddy is never accepted.

Useful host-side checks are:

```console
sudo systemctl status caddy mariadb prometheus-node-exporter
sudo systemctl list-timers 'lowerduckpond-*'
sudo journalctl --unit lowerduckpond-backup.service
sudo journalctl --unit lowerduckpond-health.service
sudo /usr/local/libexec/lowerduckpond/restic-check
```

The node exporter listens only on `127.0.0.1:9100`. Milestone 2 records Caddy,
database, rootless-runtime, and backup health as Prometheus textfile metrics and
in journald; a central collector, dashboards, and routed alerts belong with the
control-plane observability work rather than consuming the small development
Droplet now.
