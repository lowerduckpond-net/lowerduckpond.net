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
- `provisioner` creates queue/content boundaries and permits only a validated
  Caddy reload through sudo.

Roles own host configuration, not tenant lifecycle state. Tenant-specific
routes, identities, containers, and databases begin in Milestone 3.
