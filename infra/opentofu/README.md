# OpenTofu infrastructure

Milestone 1 provides three reusable modules and two operational roots:

- `bootstrap-state/` creates the private, versioned Spaces state bucket and its
  bucket-scoped backend key. It intentionally retains local state under
  encrypted operator custody.
- `environments/production/` creates the NYC1 network, small development
  Droplet, retained reserved address, firewall, backup storage, scoped runtime
  key, and Cloudflare records.
- `modules/` contains the host, Spaces, and DNS resource boundaries.

Production state uses the Spaces S3-compatible backend and OpenTofu client-side
AES-GCM encryption. Native S3 lockfiles remain disabled until conditional-write
behavior has been tested; GitHub Actions serializes every production plan and
apply with one concurrency group.

Never commit state, saved plans, backend credentials, provider tokens, or real
variable files. Follow
[`docs/operations/infrastructure.md`](../../docs/operations/infrastructure.md)
for the controlled workflow.
