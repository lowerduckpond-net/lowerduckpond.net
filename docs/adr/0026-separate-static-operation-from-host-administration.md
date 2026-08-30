# 0026: Separate static operation from host administration

- Status: accepted
- Date: 2026-08-23

## Context

Milestone 2 production convergence uses the `ldp-admin` SSH account and a
trusted-workstation administrative key. Milestone 3 also needs an authenticated
SSH transport for routine tenant lifecycle commands. Reusing the administrative
account or its unrestricted shell would make every ordinary deployment carry
the authority intended for host configuration and emergency recovery.

ADR 0020 requires the SSH boundary to derive an operator principal and issue an
immutable root-owned authorization job. That boundary should be independently
revocable and unable to turn a protocol or parsing defect into a general shell.

## Decision

Create a dedicated, password-disabled `ldp-operator` Unix account and a
dedicated operator SSH key. The account carries a syntactically valid hash for
a randomly generated and immediately discarded password because Ubuntu's
OpenSSH rejects literally locked shadow entries before public-key
authentication. Password and keyboard-interactive authentication remain denied
globally and in the account's `Match` policy, so no password credential exists
or can be used. Keep `ldp-admin` and its existing key for Ansible convergence,
host maintenance, and emergency administration only.

Store the operator authorized key in a root-owned system path outside any
operator-writable home. Bind each key entry to a versioned operator principal
and one root-owned forced-command adapter. Apply OpenSSH restrictions that deny
interactive shell, PTY, SFTP/SCP, port, agent and X11 forwarding, user startup
files, and arbitrary environment input. The account has no persistent writable
home or application state.

The forced command ignores `SSH_ORIGINAL_COMMAND` as authority and reads only
the bounded, versioned operation protocol from standard input. It invokes one
exact root-owned job issuer through a fixed sudo rule. Neither the account nor
its key can invoke the activator, job executor, emergency deletion path, shell,
Ansible, or arbitrary sudo commands. The issuer derives the configured
principal from the root-owned key binding rather than accepting a request
field.

The trusted-workstation CLI uses the operator key for all ordinary Milestone 3
commands. A separate explicit administrative workflow may invoke root-only
emergency recovery through `ldp-admin`; it is never disguised as or reachable
through an ordinary tenant operation.

Tests inspect the effective sshd configuration and authorized-key options,
exercise the real forced-command boundary, and attempt every prohibited SSH
feature. Authentication success without a valid framed request must allocate no
job, correlation, artifact, result, or audit payload beyond a bounded rejection
record.

## Consequences

Routine tenant work no longer exposes a general administrative session or the
Ansible identity. The operator key can be rotated or revoked independently, and
the authorization record can identify which configured key principal approved
an operation.

The operator must create and back up another key pair. Ansible must manage a
carefully tested sshd `Match` policy, root-owned authorized-key file, forced
command, and exact sudo rule. The account still reaches a privileged parser by
design, so all raw-size, timeout, decoder, schema, expected-state, and audit
controls remain mandatory.

Milestone 4 can replace the SSH issuer with authenticated control-plane job
issuance while retaining the same root-owned job envelope and worker executor.

## Alternatives considered

Reusing `ldp-admin` was rejected because an ordinary operation key would also
authorize host administration. A command convention enforced only by the
client was rejected because a compromised client can choose its SSH command.
Giving `ldp-operator` a normal shell plus a narrow sudo command was rejected
because shell, filesystem, forwarding, and local-process capabilities are not
needed by the protocol.

Creating one Unix account per future customer was rejected for Milestone 3;
the only caller is the trusted operator, and Milestone 4 moves customer and
administrator authentication into the control plane rather than host SSH.

## References

- [0002: Use Ansible for durable host configuration](0002-use-ansible.md)
- [0020: Use a trusted-workstation static operator interface](0020-use-a-trusted-workstation-static-operator-interface.md)
- [0022: Test static publication as a security boundary](0022-test-static-publication-as-a-security-boundary.md)
