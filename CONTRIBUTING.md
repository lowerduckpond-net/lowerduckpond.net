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

Create a focused branch, keep each pull request to one coherent change, and
describe the behavior and validation performed. Architecture changes should add
or update an ADR in `docs/adr/`.

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
