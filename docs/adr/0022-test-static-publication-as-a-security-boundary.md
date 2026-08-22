# 0022: Test static publication as a security boundary

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 combines parser, filesystem, privilege, routing, concurrency, and
recovery behavior. Unit tests alone cannot demonstrate the installed ownership,
Caddy, systemd, backup, or host-reboot boundaries, while production-only testing
would discover security and destructive-lifecycle failures too late.

## Decision

Deliver Milestone 3 through these reviewable layers:

1. threat model, ADRs, schema, fixtures, and test matrix;
2. manifest parsing, validation, slug rules, and desired/observed state;
3. hostile archive validation and deterministic portable export;
4. root-owned immutable release activation and generated Caddy routing;
5. lifecycle commands, reconciliation, rollback, and audit records;
6. backup locking and restored-state reconciliation; and
7. disposable host integration followed by a production canary acceptance
   drill.

Use unit and property-based tests for schemas, normalization, archive limits,
state transitions, idempotency, and route generation. Use process-level tests
for concurrent operations and failure injection at every publication commit
step. Use Molecule and Testinfra to exercise actual Unix identities,
permissions, immutable releases, the privileged helper, Caddy validation and
reload, backup overlap, restore, and reboot-relevant service configuration.

Hostile fixtures must cover traversal, absolute and ambiguous paths, links,
special entries, duplicate and case-colliding names, expansion and quota abuse,
arbitrary route input, cross-tenant reads, interrupted activation, failed Caddy
reload, concurrent deployment, repeated correlation IDs, and restore followed
by reconciliation. Tests must also prove that the provisioner cannot invoke or
simulate the operator-authenticated emergency deletion path, modify manifests
or observed state, or truncate, replace, or remove audit evidence.

After CI and disposable-host acceptance pass, publish a reserved production
canary below the existing wildcard, verify HTTPS, rollback, suspension, restore,
backup recovery, and idempotence, and remove all canary state through the same
operator interface. Dynamic or destructive isolation tests remain off the
production host.

## Consequences

The implementation is split along contract and trust boundaries instead of
arriving as one massive pull request. CI takes longer, but most review findings
are reproducible before production. The canary drill provides evidence for the
Milestone 3 exit criterion without onboarding a real tenant.

Production acceptance requires an explicit operator action from the trusted
workstation, as in Milestone 2. Sanitized results should be recorded without
tenant content, credentials, or backup metadata.

## Alternatives considered

One end-to-end implementation pull request was rejected because privilege and
state-model problems would be difficult to isolate. Unit tests without an
installed-host scenario were rejected because ownership, Caddy, and systemd are
material boundaries. Running destructive hostile tests on production was
rejected because a disposable environment can exercise them safely.

## References

- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [Static-publication threat model](../threat-model/static-publication.md)
