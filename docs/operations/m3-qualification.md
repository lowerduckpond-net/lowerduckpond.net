# Milestone 3 platform qualification

M3.0 is a destructive-safe, production-equivalent experiment. It creates one
disposable NYC1 Droplet, one firewall, a project assignment, and four temporary
DNS records. It never changes the production Droplet, reserved address, Caddy
configuration, tenant state, or either domain apex record. The exact
`lowerduckpond.com` apex route is exercised locally on the disposable host with
an HTTPS address override.

The gate has 37 named checks and no skip or warning result. Its report format
can contain only fixed check identifiers, pass/fail status, bounded versions and
counts, booleans, filesystem type, and fixed error codes. It cannot serialize
command output, exceptions, request or response headers, cookies, logs,
credentials, or nested arbitrary evidence.

## Authorization boundary

Repository validation and its direct library probe are hermetic and may run
anywhere. The operator-facing `just m3-qualification` commands are bound to a
live session. Do not plan, apply, configure, probe, or destroy the live
qualification stack until the operator explicitly authorizes that live run.

Run the live sequence only from the trusted administrative workstation that
holds the backed-up SSH key. Do not copy its private key, OpenTofu passphrase,
Cloudflare token, provider token, backend key, or real variable files into a
Coder workspace or GitHub Actions.

## One-time inputs

Prepare these values in the trusted workstation's password manager or process
environment:

- the existing DigitalOcean custom-scoped OpenTofu token;
- the existing state-bucket backend key and state-encryption passphrase;
- the existing administrative SSH public key and the fingerprint DigitalOcean
  records for that key;
- the existing DigitalOcean project ID and administrative source CIDR;
- both Cloudflare zone IDs;
- a temporary, expiring Cloudflare token limited to zone read and DNS edit for
  exactly `lowerduckpond.net` and `lowerduckpond.com`; and
- an operator copy of the domain attestation fixture confirming current
  registrant control and auto-renewal for both registrations.

The temporary dual-zone Cloudflare token is used by OpenTofu to create and
remove four A records, by the domain preflight to inspect both zones, and by
Caddy to complete DNS-01 issuance on the disposable host. Revoke it after the
host and records are destroyed. It is distinct from the production Caddy token.
The fixture obtains and verifies both the apex and wildcard certificate path
for each domain through direct-address TLS connections; this does not repoint
either apex DNS record to the disposable host.

Copy
[`domain-attestation.example.json`](../../tests/static-publication/qualification/fixtures/domain-attestation.example.json)
outside the repository, re-check both registrations at the registrar, and
leave each boolean true only if the assertion is currently accurate. The file
contains no identity or registrar account data.

## Provision the disposable stack

From the repository on the trusted workstation, initialize the dedicated
qualification root with its own remote-state key:

```bash
cd infra/opentofu/environments/qualification
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
# Fill the two ignored files without placing provider credentials in either.
export AWS_ACCESS_KEY_ID='state-bucket-key-id'
export AWS_SECRET_ACCESS_KEY='state-bucket-secret'
export DIGITALOCEAN_TOKEN='existing-custom-scoped-opentofu-token'
export CLOUDFLARE_API_TOKEN='temporary-dual-zone-token'
tofu init -backend-config=backend.hcl
tofu plan -out=m3-qualification.tfplan
tofu show -json m3-qualification.tfplan | \
  ../../../../scripts/assert_m3_qualification_plan.py
tofu show m3-qualification.tfplan
tofu apply m3-qualification.tfplan
```

The reviewed plan must contain only one disposable Droplet, one firewall, its
project assignment, and these records:

- `m3-qualification.lowerduckpond.net`;
- `m3-a.lowerduckpond.com`;
- `t-0198d17f6f4a70008000000000000001.lowerduckpond.com`; and
- `m3-unknown.lowerduckpond.com`.

It must not contain a reserved address, Space, key, VPC, apex DNS record, or any
production resource action.

Read the address with `tofu output -raw ipv4_address`. Before Ansible first
connects, verify the new host key through an independent DigitalOcean console
path and record it in the trusted workstation's `known_hosts` by making one
ordinary SSH connection. The qualification commands do not accept an address;
they bind a clean Git revision to the OpenTofu output and independently require
the connected host's DigitalOcean metadata ID to match before Ansible gathers
facts or changes the host. `begin` also creates a UUIDv7 run ID and removes all
prior fragments. Every fragment records that run ID and source revision, and
assembly rejects fragments from another run or revision.

## Configure and run the gate

Return to the repository root. Keep the temporary Cloudflare token exported
under both names needed by OpenTofu and the qualification tools:

```bash
export M3_QUALIFICATION_CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN"
export M3_QUALIFICATION_NET_ZONE_ID='lowerduckpond-net-zone-id'
export M3_QUALIFICATION_COM_ZONE_ID='lowerduckpond-com-zone-id'
just m3-qualification begin
just m3-qualification configure
```

Install Playwright's pinned browser engines and their workstation dependencies
once. This changes only the trusted workstation:

```bash
uv run playwright install --with-deps chromium firefox webkit
```

Run all four report fragments, then require the exact 37-check union:

```bash
just m3-qualification libraries
just m3-qualification domains '/outside/repository/domain-attestation.json'
just m3-qualification host
just m3-qualification browser
just m3-qualification assemble
```

The final command succeeds only if every technical probe and both domain checks
passed. Review `.artifacts/m3-qualification/m3-qualification.json`. A failed
check exposes only its fixed identifier and `probe_failed`; use the disposable
host interactively to diagnose it, then rerun the affected fragment. Do not
replace a failure with a skipped check. A failed primitive that changes an
accepted design assumption requires architecture review.

After operator review, copy the final sanitized report into the M3.0 pull
request as evidence. Do not attach Ansible output, Caddy logs, browser traces,
Cloudflare responses, OpenTofu state, or saved plans.

## Mandatory teardown

Destroy from a saved, reviewed plan even when a probe fails:

```bash
cd infra/opentofu/environments/qualification
tofu plan -destroy -out=m3-qualification-destroy.tfplan
tofu show -json m3-qualification-destroy.tfplan | \
  ../../../../scripts/assert_m3_qualification_plan.py --destroy
tofu show m3-qualification-destroy.tfplan
tofu apply m3-qualification-destroy.tfplan
tofu state list
```

The final state list must be empty. Confirm the Droplet and firewall are absent
from the DigitalOcean project and the four temporary records are absent from
Cloudflare. Also confirm Caddy left no `_acme-challenge` TXT record behind in
either zone. Remove the ignored variable, backend, and plan files from the
trusted workstation; retain the encrypted empty remote state and the
sanitized qualification report. Finally revoke the temporary dual-zone
Cloudflare token.

If creation or configuration fails partway through, use the same destroy
sequence. The destroy policy deliberately accepts any created subset of the
seven allowlisted resources while still rejecting a non-delete action, an
unrelated resource, or an allowlisted state address whose destructive-side
identity no longer matches the disposable name and type. When the Droplet and
dependent resources coexist, the policy also requires the firewall, project
membership, and DNS addresses to remain bound to that exact Droplet.
