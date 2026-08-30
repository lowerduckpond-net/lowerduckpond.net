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
- `provisioner` retains the non-login execution identity without a persistent
  writable home or job store and grants it no host-configuration or Caddy
  privileges.
- `static_host_agent` verifies and atomically selects the locked, immutable
  host-agent artifact; migrates the proven-empty Milestone 2 state; installs
  the private worker sandbox and disabled publication gates; and owns the new
  durable state and unpublished release boundaries.

Roles own host configuration, not tenant lifecycle state. Tenant-specific
static content activation and routes begin together in Milestone 3. Queue-backed
control-plane integration begins in Milestone 4; tenant-specific Unix
identities, containers, and databases begin in Milestone 6. M3.5 performs the
empty-host ownership migration while publication remains disabled. It creates
no tenant job, route, or provisioner-writable persistent workspace.
