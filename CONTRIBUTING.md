# Contributing

Lower Duck Pond Hosting welcomes infrastructure, application, documentation,
testing, security, and operations contributions.

## Development workflow

Prerequisites are Git and [mise](https://mise.jdx.dev/) 2026.7.14 or newer. From
a fresh clone:

```console
mise install
just setup
just check
```

Use `just --list` to discover narrower commands. Use `just format` to apply
formatters, then run `just check` before opening a pull request.

The installed-host M3.8 qualification is deliberately slow. Pull requests and
`main` pushes run it only when its Ansible, lifecycle, artifact, protocol,
toolchain, or dependency inputs change. Scheduled and manually dispatched CI
runs always exercise the full gate; its stable `Ansible` aggregate check remains
available to branch protection when the expensive lane is selectively skipped.

Create a focused branch, keep each pull request to one coherent change, and
describe the behavior and validation performed. Architecture changes should add
or update an ADR in `docs/adr/`.

Installed qualification records monotonic timing diagnostics automatically.
Read [qualification diagnostics](docs/operations/qualification-diagnostics.md)
for report locations, overlapping categories, comparison limits, and the single
read-only command that summarizes a retained failure. Python
checks also print their 20 slowest tests above one second.
Use `just check-archive-full-size` for the fresh, independently runnable local
100-MiB archive case; its diagnostic pass does not replace complete qualification.
Use `just check-installed-group CASE` for the declared
[independent installed checks](docs/operations/installed-groups.md), including
configuration overlap and the cross-feature reboot journey.

Record deployment closeouts under `docs/records/` with their original source,
artifact, and evidence; recording completion does not require redeployment.
Those records must never become executable, configuration, test, or requirements
inputs. All other tracked files remain qualification inputs by default under
[ADR 0029](docs/adr/0029-bind-qualification-to-inputs-and-live-observations.md).

## Repository safety

Never commit:

- credentials, private keys, access tokens, or recovery codes;
- OpenTofu state or saved production plans;
- production inventory, logs, backup metadata, or abuse reports;
- tenant content, contact information, or other private user data.

Use clearly fake values in examples. If a secret is committed, rotate it before
attempting to remove it from history and report the incident privately.

## Community identity

This project serves a role-playing community. Do not reveal or attempt to link a
participant's fictional identity to a real-world identity. Contributors control
how they identify themselves publicly, subject to GitHub's terms.

## Licensing

By submitting a contribution, you agree that it may be distributed under the
Apache License 2.0. No contributor license agreement is required.
