# Infrastructure operations

Production infrastructure changes use reviewed OpenTofu plans and an exact-plan
apply. Do not run an uncoordinated production plan or apply from a workstation.
The GitHub workflow serializes every operation with the
`opentofu-production` concurrency group.

## Fixed foundation choices

- DigitalOcean compute region: `nyc1`
- DigitalOcean project: the existing `lowerduckpond.net` project
- Spaces region: `nyc3`, the nearest Spaces location
- Development Droplet size: `s-1vcpu-2gb`
- Initial tenant Droplet target: `s-2vcpu-4gb-amd`
- Host image: `ubuntu-26-04-x64`
- Trusted platform DNS zone: `lowerduckpond.net`
- Untrusted tenant DNS zone: `lowerduckpond.com` (added in Milestone 3)

The Droplet sets `resize_disk = false`. Starting with the smaller root disk and
resizing only CPU and memory keeps the development size available as a later
downscale target. Powered-off Droplets continue to incur charges; destroy a
dormant Droplet instead of merely powering it off.

## Credential boundaries

Never send credentials through issues, pull requests, repository files, or
chat. Enter them directly into the GitHub `production` environment or into the
trusted shell used for the one-time bootstrap.

The workflow needs three distinct DigitalOcean credential roles:

1. `DIGITALOCEAN_TOKEN` manages Droplets, VPCs, firewalls, reserved addresses,
   SSH keys, project assignments, and scoped Spaces keys. Create it inside the
   dedicated `lowerduckpond.net` DigitalOcean team; projects organize resources
   but do not form credential boundaries. Use a 90-day custom-scoped token with
   these exact scopes:
   - `actions:read`, `regions:read`, `sizes:read`, `image:read`, and
     `snapshot:read`
   - `droplet:create`, `droplet:read`, `droplet:update`, and `droplet:delete`
   - `firewall:create`, `firewall:read`, `firewall:update`, and
     `firewall:delete`
   - `project:read` and `project:assign_resource`
   - `reserved_ip:create`, `reserved_ip:read`, and `reserved_ip:update`
   - `spaces:read`
   - `spaces_key:create_credentials`, `spaces_key:read`, `spaces_key:update`,
     and `spaces_key:delete`
   - `ssh_key:create`, `ssh_key:read`, `ssh_key:update`, and `ssh_key:delete`
   - `tag:create`, `tag:read`, and `tag:delete`
   - `vpc:create`, `vpc:read`, `vpc:update`, and `vpc:delete`
   Do not grant global read/full access, `droplet:admin`, project creation or
   deletion, `reserved_ip:delete`, or `spaces:update`.
2. `SPACES_OPERATOR_ACCESS_KEY_ID` and `SPACES_OPERATOR_SECRET_ACCESS_KEY`
   manage bucket configuration. Keep this full-access operator key only in the
   protected environment; its otherwise broad access is contained by the
   dedicated DigitalOcean team.
3. `OPENTOFU_STATE_ACCESS_KEY_ID` and
   `OPENTOFU_STATE_SECRET_ACCESS_KEY` can read and write only the state bucket.
   The bootstrap root creates this pair.

`CLOUDFLARE_API_TOKEN` should be an account-owned token limited to the
`lowerduckpond.net` and `lowerduckpond.com` zones with DNS Write, Zone Settings
Write, Cache Settings Write, Config Settings Write, Zone WAF Write, and SSL and
Certificates Write. Those grants cover the managed records, Full (strict),
cache-bypass and transform rules, `/cdn-cgi/` block, origin-pull association,
and public-certificate status read. The zone IDs are supplied separately, so
the token does not need Zone Read. Do not substitute an account-wide ruleset or
certificate grant. The production stack creates a separate Spaces key limited
to read/write operations on the backup bucket. M3.1 adds an independently
scoped archive key, retrieves and backs it up only from a trusted workstation,
and defers host installation until the root-owned archive component lands in
M3.10.

This OpenTofu token is distinct from the Caddy runtime token documented in
[`host-configuration.md`](host-configuration.md). Caddy needs both Zone Read
and DNS Edit for its provider module and must not receive the infrastructure
token.

## Administrative SSH key

Create a dedicated, passphrase-protected Ed25519 key named for the project.
Keep its private key and passphrase under operator custody. Store only the
single-line public key in the GitHub `production` environment as
`ADMIN_SSH_PUBLIC_KEY`; OpenTofu uploads that public half to DigitalOcean and
cloud-init authorizes it for the non-root administrative user. Do not reuse
this human-administrator key for CI automation.

## One-time state bootstrap

The bootstrap needs the DigitalOcean token and a Spaces operator key because
Spaces bucket management uses its S3-compatible API.

1. Copy `infra/opentofu/bootstrap-state/terraform.tfvars.example` to an ignored
   `terraform.tfvars` and replace the bucket name with a globally unique name.
2. Export `DIGITALOCEAN_TOKEN`, `SPACES_ACCESS_KEY_ID`, and
   `SPACES_SECRET_ACCESS_KEY` in a trusted shell. Also set
   `TF_VAR_state_encryption_passphrase` to a generated high-entropy value of at
   least 32 characters. This bootstrap passphrase must be distinct from the
   production state passphrase stored in GitHub.
3. In `infra/opentofu/bootstrap-state`, run `tofu init`, review a saved
   `tofu plan`, and apply that saved plan.
4. Retrieve the two sensitive outputs directly into the corresponding GitHub
   environment secrets. Do not paste them into logs or shell history.
5. Move the OpenTofu-encrypted bootstrap state file into operator custody and
   store its encryption passphrase separately. It contains the generated state
   secret and must not become a CI artifact.

The state bucket is private, versioned, accessed through Spaces' required HTTPS
endpoint, and protected against normal destruction. OpenTofu encrypts state and
saved plans client-side with AES-GCM;
the bucket alone is not the encryption boundary. Native S3 lockfiles remain
disabled until Spaces conditional writes are independently tested. GitHub
serialization is the active locking control meanwhile.

## GitHub production environment

Create an environment named `production`, require the repository owner as a
reviewer, prevent self-review when a second maintainer can approve, and allow
deployments only from `main`. Pull-request plans never receive this
environment's credentials.

Configure these environment secrets:

- `ADMIN_SOURCE_CIDRS_JSON`, formatted as a JSON list such as
  `["192.0.2.10/32"]`
- `ADMIN_SSH_PUBLIC_KEY`
- `CLOUDFLARE_API_TOKEN`
- `DIGITALOCEAN_TOKEN`
- `OPENTOFU_STATE_ACCESS_KEY_ID`
- `OPENTOFU_STATE_SECRET_ACCESS_KEY`
- `OPENTOFU_ENCRYPTION_PASSPHRASE`, a production-only passphrase generated
  independently from the bootstrap passphrase and stored outside DigitalOcean
  as well as in GitHub
- `SPACES_OPERATOR_ACCESS_KEY_ID`
- `SPACES_OPERATOR_SECRET_ACCESS_KEY`

DigitalOcean Cloud Firewalls accept IP addresses and CIDRs, not dynamic DNS
names. If an administrative `/32` changes, update `ADMIN_SOURCE_CIDRS_JSON`
and run the protected plan/apply workflow to restore SSH access. Do not publish
a personal network address under the game domain solely for firewall access.

Configure these environment variables:

- `BACKUP_BUCKET_NAME`, using a second globally unique name
- `ARCHIVE_BUCKET_NAME`, set in M3.1 to the selected durable production name
  `lowerduckpond-net-production-tenant-archives-4f3e6b91`; OpenTofu creates and
  owns this service-lifetime bucket, so do not create it manually
- `CLOUDFLARE_ZONE_ID`, the trusted `lowerduckpond.net` zone
- `CLOUDFLARE_TENANT_ZONE_ID`, the untrusted `lowerduckpond.com` zone, required
  when the Milestone 3 tenant namespace lands
- `CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID`, the public ID of the separately
  uploaded, active `.net` zone-level origin-pull leaf
- `CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID`, the public ID of the
  separately uploaded, active `.com` zone-level origin-pull leaf
- `DIGITALOCEAN_PROJECT_ID`
- `OPENTOFU_STATE_BUCKET`
- `SPACES_REGION`, set to `nyc3`

Set the repository variable `INFRASTRUCTURE_PLANS_ENABLED` to `true` only after
the bootstrap and environment configuration are complete.

## Plan and apply

Pull requests that change the production OpenTofu tree create a no-credential
speculative plan using empty state and clearly fake inputs. It is useful for
reviewing the proposed resource shape but cannot be applied. This keeps cloud
credentials away from pull-request code, including forks.

After merge, a protected main-branch run creates the real remote plan. The
workflow publishes a human-readable plan summary, runs policy assertions over
the JSON representation, and retains the encrypted saved plan for three days.

After merging:

1. Dispatch **Infrastructure** from `main` with `operation` set to `plan`.
2. Approve the protected environment job and review its plan summary.
3. Note the successful plan workflow's numeric run ID.
4. Dispatch **Infrastructure** again from `main` with `operation` set to
   `apply` and supply that run ID.
5. Approve the apply job. It rejects plans from pull requests, other commits,
   other branches, or modified artifacts before applying the exact saved plan.

The apply exports a short-lived `production-ansible-inventory` artifact. It
contains host addresses and the administrative username, but no private key or
cloud credential.

The one-time M3.1 archive-storage migration has an additional exact-plan flag,
preflight, credential-backup step, and live gate. Follow
[`m3-archive-storage.md`](m3-archive-storage.md); do not treat it as an ordinary
unflagged infrastructure apply.

M3.7 public-edge changes likewise require an explicit `public_edge_phase` on
both the plan and apply dispatches. `proxied` creates the `.com` records and
enables both reviewed zone policies while both origin firewalls remain open;
`enforced` narrows the DigitalOcean web-ingress allowlist only after the host
has independently required origin pulls and adopted the same reviewed
Cloudflare networks. Roll back `enforced` to `proxied` before selecting
`direct`; the plan policy rejects an enforced-to-direct jump. `none` is the
ordinary non-edge mode and retains the phase recorded in production state. It
resolves to `direct` only for the one-time legacy state that predates this
output and contains no managed edge policy.

The committed Cloudflare network snapshot separates the currently published
ranges from temporarily `retiring` ranges. Both the DigitalOcean and host
firewalls and Caddy's trusted-proxy boundary use their union while enforcement
is active. When Cloudflare changes its list, first replace the active arrays
with the exact newly published sets and place every removed range in the
retiring arrays; rebuild and converge the host artifact and both firewalls,
then verify the edge before removing the retiring ranges in a later reviewed
change. Active and retiring arrays must be disjoint, and live plans never fetch
or trust ranges that were not committed for review.

The two certificate IDs are nonsecret object identifiers. Uploading or
retiring the corresponding leaves remains a separate temporary-credential
operation; neither PEM input files nor private keys enter OpenTofu variables or
GitHub variables. The provider reads the selected public leaf and its metadata
into encrypted plans and state to prove it active. Its private key must never
enter OpenTofu configuration, plans, or state.

## Rebuild drill

To prove that compute remains replaceable, dispatch a main-branch plan with
`replace_droplet` enabled. The policy permits a create-before-destroy Droplet
replacement plus only the required reserved-IP assignment, firewall, and
host-project-membership changes. The reserved IP and both Spaces buckets use a
separate project assignment that must remain unchanged. The policy checks both
the action types and their field-level deltas, and rejects any deletion of the
reserved address or either Spaces bucket.

After a change to the project-assignment structure itself, first apply a normal
non-drill plan and confirm that the Droplet, reserved IP, and both Spaces
buckets still appear in the production project. Then create a fresh replacement
plan. After review, apply that exact plan normally and verify:

- the reserved public address is unchanged;
- the apex and wildcard records are unchanged;
- the replacement node appears in the existing DigitalOcean project; and
- objects already stored in Spaces remain present.

Use this drill only when the expected temporary compute overlap, downtime, and
reconfiguration work are acceptable.
