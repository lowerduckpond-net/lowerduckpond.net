# OpenTofu infrastructure

Milestone 1 provides three reusable modules and two operational roots. M3.0
adds a third, explicitly disposable root:

- `bootstrap-state/` creates the private, versioned Spaces state bucket and its
  bucket-scoped backend key. It intentionally retains local state under
  encrypted operator custody.
- `environments/production/` creates the NYC1 network, small development
  Droplet, retained reserved address, firewall, isolated backup and tenant-
  archive storage, independently scoped runtime keys, and Cloudflare records.
- `environments/qualification/` temporarily creates only the production-
  equivalent M3.0 host, firewall, project assignment, and four test records. It
  has a separate encrypted state key and must be destroyed after the no-skip
  gate runs.
- `modules/` contains the host, Spaces, and two-zone public-edge resource
  boundaries.

Production state uses the Spaces S3-compatible backend and OpenTofu client-side
AES-GCM encryption. Native S3 lockfiles remain disabled until conditional-write
behavior has been tested; GitHub Actions serializes every production plan and
apply with one concurrency group.

Never commit state, saved plans, backend credentials, provider tokens, or real
variable files. Follow
[`docs/operations/infrastructure.md`](../../docs/operations/infrastructure.md)
for the controlled workflow.
The M3.0 exception is separately bounded in
[`docs/operations/m3-qualification.md`](../../docs/operations/m3-qualification.md).
