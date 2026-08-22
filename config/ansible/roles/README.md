# Ansible roles

- `base` owns packages, locale, time, updates, journald, SSH, and kernel
  hardening.
- `firewall` installs a validated nftables policy as a second boundary behind
  the DigitalOcean Cloud Firewall.
- `caddy` builds the pinned edge binary with the pinned Cloudflare module and
  validates every candidate configuration and reload.
- `podman` establishes a non-login rootless runtime identity, subordinate IDs,
  lingering, a network, and a reboot-persistent readiness unit.
- `database` installs loopback-only MariaDB and a socket-authenticated,
  dump-only backup account.
- `backup` initializes an encrypted Restic repository, creates the first
  backup, applies retention, and supplies a disposable restore check.
- `monitoring` exposes node and project health metrics only on loopback and
  records health failures in the journal.
- `provisioner` creates the non-login service account and its private job,
  manifest, and audit directories without granting host-configuration or Caddy
  privileges.

Roles own host configuration, not tenant lifecycle state. Tenant-specific
static content activation and routes begin together in Milestone 3. Queue-backed
control-plane integration begins in Milestone 4; tenant-specific Unix
identities, containers, and databases begin in Milestone 6. Before accepting
tenant data, Milestone 3 also migrates authoritative manifest and audit storage
from the empty provisioner-owned baseline directories to root ownership.
