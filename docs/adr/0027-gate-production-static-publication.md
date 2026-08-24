# 0027: Gate production static publication

- Status: accepted
- Date: 2026-08-23

## Context

Milestone 3 replaces ownership, Caddy runtime generation, privileged command,
archive, backup-locking, and recovery boundaries on the production host. The
components must be installed and qualified before they can safely accept
tenant history or publish tenant-controlled bytes.

A partially implemented path is especially dangerous here: a schema or archive
parser without complete authorization, durability, routing, reconciliation, and
recovery behavior would create a public security boundary that the remaining
phases merely assume is safe.

## Decision

Add an Ansible variable named `static_publication_enabled`. Default it to
`false` in every inventory, including production, and require an explicit
reviewed production change to set it to `true`.

While false:

- install, converge, inspect, and test the static host-agent components;
- retain the Milestone 2 platform fixture and platform-only Caddy routes;
- reject every externally requested tenant lifecycle job before accepting an
  artifact, allocating tenant state, or mutating publication state; and
- reject any Caddy runtime candidate containing a tenant canonical or alias
  route.

The gate is not a suspension or emergency-shutdown mechanism. If tenant history
or a tenant-bearing active generation already exists, changing the configured
value back to false fails convergence without deleting state, removing routes,
or stopping the last known-good Caddy process. Use the lifecycle and emergency
procedures for an existing tenant.

Enable production only after the complete disposable-host suite passes and a
production preflight records all of these facts:

1. the ADR 0024 dual-domain DNS, TLS, supported-browser, and Caddy cookie-policy
   qualification passes;
2. the dedicated archive Space, credential isolation, version operations, and
   empty-accounting baseline pass;
3. the dedicated operator forced-command and denial tests pass;
4. filesystem durability, systemd/Caddy descriptor pinning, archive parser,
   lifecycle, backup overlap, restore, and reconciliation tests pass;
5. production capacity and free-space reserves pass; and
6. the rollback procedure can restore the preceding platform-only generation
   without altering authoritative tenant state.

After the reviewed enablement converge, run one synthetic production canary
through the ordinary operator interface. The canary must exercise create,
deploy, replace, rollback, suspend, resume, rename and slug reuse, export,
and import into a separately created undeployed target. Exercise both the
source and active imported target through backup, restored-state reconciliation,
post-reboot HTTPS, and route verification. Archive, restore, rearchive with
evidence bound to the restored generation, and ordinarily delete the source;
separately archive and ordinarily delete the imported target. Confirm both
tenants' route classes are absent and every bound archive object is retired
while audit evidence remains. No real tenant is onboarded until the two-tenant
canary report passes.

Record the first successful enablement in root-owned platform state, including
the configuration version, trusted platform domain, pinned alias and origin
suffixes, cookie-policy version, and acceptance-evidence digest.
Reconciliation requires that launch record once tenant history exists; it
cannot infer launch authority merely from a configuration boolean.

## Consequences

Most implementation and host migration can land dark while the existing HTTPS
fixture remains available. An accidental partial deploy cannot create tenant
state or routes. Production activation becomes a small, explicit, reversible
configuration change followed by an ordinary lifecycle drill.

The full acceptance suite must be practical on a disposable production-like
host. Production-only facts still require a preflight and canary, so the gate
reduces rollout risk rather than eliminating it.

The launch record makes enablement durable and auditable. It also means that
turning the boolean off is intentionally not a shortcut for global tenant
suspension.

## Alternatives considered

Enabling each feature as its implementation PR lands was rejected because many
security properties span authorization, archive parsing, state, Caddy, systemd,
backup, and recovery components. Protecting only the CLI was rejected because
another local path or stale Caddy generation could still publish tenant data.

Using a tenant-count check without an explicit gate was rejected because it
does not prevent the first unsafe tenant mutation. Automatically disabling all
existing tenants when configuration turns false was rejected because a host
configuration mistake would become an unaudited bulk lifecycle transition.

## References

- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [0022: Test static publication as a security boundary](0022-test-static-publication-as-a-security-boundary.md)
- [0024: Separate trusted platform and untrusted tenant domains](0024-separate-platform-and-tenant-domains.md)
- [0025: Separate tenant archives from platform backups](0025-separate-tenant-archives-from-platform-backups.md)
- [0026: Separate static operation from host administration](0026-separate-static-operation-from-host-administration.md)
