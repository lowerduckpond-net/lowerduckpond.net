# Lower Duck Pond Hosting

Lower Duck Pond Hosting is a free, community-scale web host for participants in
the `r/HaveWeMet` role-playing community. It is intended for small, handmade
sites belonging to fictional residents, businesses, clubs, campaigns, and civic
departments.

The project is currently **pre-alpha**. Milestone 0 establishes the repository,
toolchain, application boundaries, and validation workflow; it does not create
cloud resources or host tenant content.

## Start here

1. Install [mise](https://mise.jdx.dev/) 2026.7.14 or newer.
2. Install the pinned project tools with `mise install`.
3. Prepare the locked development environment with `just setup`.
4. Run the complete validation suite with `just check`.

`just check` runs the same checks required by continuous integration. Some
pre-commit hygiene hooks apply safe whitespace or end-of-file fixes before
reporting failure; rerun the command after reviewing those changes.

## Repository map

- [`docs/architecture.md`](docs/architecture.md) describes the product vision,
  security boundaries, and scaling path.
- [`docs/roadmap.md`](docs/roadmap.md) defines the implementation milestones and
  exit criteria.
- [`docs/adr/`](docs/adr/) records accepted architecture decisions.
- `services/control-plane/` contains the public FastAPI application boundary.
- `services/provisioner/` contains the separately executable provisioner
  boundary.
- `infra/opentofu/` and `config/ansible/` contain infrastructure and host
  configuration foundations.

The fictional city site at `lowerduckpond.com` will live in a separate
repository and use the same tenant interface as every other site.

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before proposing a change. Please report
security problems privately according to [`SECURITY.md`](SECURITY.md); do not put
credentials, tenant information, or vulnerability details in a public issue.

Original project code is licensed under the [Apache License 2.0](LICENSE).
