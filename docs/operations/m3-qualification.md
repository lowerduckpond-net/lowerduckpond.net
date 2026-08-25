# Milestone 3 platform qualification

> **Status: implementation under review. Do not start the live sequence until
> its implementation PR is merged and the trusted workstation is on that exact,
> clean `main` revision.** Repository validation is safe to run before merge.

M3.0 is a destructive, disposable qualification drill. It puts four temporary
hostnames through the real Cloudflare edge, uses a production-equivalent NYC1
Droplet, proves a complete origin-pull CA rollover, emits one sanitized
54-check report, and then removes the complete stack. It does not change the
production Droplet, reserved address, Caddy input, domain apex records, tenant
state, or zone-wide Cloudflare settings.

The initial OpenTofu boundary contains exactly 17 resources:

- one disposable Droplet, firewall, and project assignment;
- four proxied A records;
- four per-hostname Authenticated Origin Pulls associations; and
- two-zone cache-bypass, transform-disable, and `/cdn-cgi` block rulesets.

Uploaded origin-pull certificates are deliberately outside OpenTofu because
their private keys must never enter configuration, a plan, or state. The exact
`.com` apex contract remains a loopback-only component probe; this drill never
changes the real apex record.

## Authorization and workstation boundary

Run every live command from the trusted WSL2 administrative workstation that
holds the backed-up SSH key. Do not copy its private key, CA private keys,
OpenTofu passphrase, Cloudflare tokens, provider token, backend key, or real
variable files into a Coder workspace or GitHub Actions.

Planning, applying, changing an origin-pull association, stopping the
disposable Caddy service, and destroying the stack are live mutations. Obtain
operator authorization for the complete drill before starting. A failed check
does not authorize a broader Cloudflare or production change.

The tools bind a clean Git revision, remote OpenTofu identity, DigitalOcean
metadata ID, SSH host, root-owned convergence marker, origin-pull trust stage,
and UUIDv7 run ID. Do not bypass those guards with direct Ansible or probe
commands.

## Required inputs

Have these existing values ready only on the trusted workstation:

- the qualification backend's Spaces key in `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY` (these are S3-compatible backend variable names);
- the state-encryption passphrase;
- the existing custom-scoped DigitalOcean OpenTofu token;
- the DigitalOcean project ID, administrative CIDR, SSH public key, and the
  lowercase MD5-style fingerprint DigitalOcean records for that key;
- the `lowerduckpond.net` and `lowerduckpond.com` Cloudflare zone IDs; and
- the current external copy of the dual-domain registration attestation.

If the external attestation must be refreshed, copy
[`domain-attestation.example.json`](../../tests/static-publication/qualification/fixtures/domain-attestation.example.json)
outside the repository, re-check both registrations at the registrar, and
leave a boolean true only while that assertion remains accurate. Do not add
identity or registrar-account data.

Create two separate temporary Cloudflare API tokens:

1. An **M3 edge token** limited to both owned zones and only Zone Read, DNS
   Write, Zone Settings Read, Rulesets Write, and SSL and Certificates Write.
   OpenTofu uses it for disposable DNS, rules, and per-hostname associations;
   Caddy uses it for DNS-01; the qualification client uses it read-only. Keep
   its lifetime bounded to the drill.
2. An **M3 certificate-upload token** valid for at most seven days, limited to
   both zones, with only Zone Read and SSL and Certificates Write. Use it only
   from the trusted workstation to upload and later delete the four leaf
   certificates.

Cloudflare exposes leaf upload and hostname association through the same coarse
SSL and Certificates Write permission. Separate tokens therefore constrain
which process sees leaf private keys; they do not create a provider-enforced
sub-permission between upload and association. Never give OpenTofu or the edge
token a leaf private key.

The M3 edge token is not the production OpenTofu token or the non-expiring
production Caddy DNS token. Revoke both M3 tokens after complete teardown.

## Prepare the origin-pull CAs and leaves

Work in a private directory outside the repository with `umask 077`. Create two
independent, passphrase-protected 4096-bit RSA CA keys. Give each CA a maximum
five-year certificate and back up both encrypted keys, public certificates, and
passphrases before proceeding. The commands prompt for each CA passphrase:

```bash
umask 077
cd /absolute/private/path/outside-the-repository

openssl genrsa -aes256 -out primary-ca.key 4096
openssl req -x509 -new -key primary-ca.key -sha256 -days 1825 \
  -subj '/CN=Lower Duck Pond origin pull primary CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out primary-ca.pem

openssl genrsa -aes256 -out replacement-ca.key 4096
openssl req -x509 -new -key replacement-ca.key -sha256 -days 1825 \
  -subj '/CN=Lower Duck Pond origin pull replacement CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out replacement-ca.pem
```

Issue one 30-day client leaf for each CA generation and zone. The leaf keys are
intentionally unencrypted because Cloudflare must receive them; keep them only
in this private directory until upload verification. Repeat the following with
`GENERATION` set to `primary` and `replacement`, and `ZONE` set to
`lowerduckpond.net` and `lowerduckpond.com`:

```bash
GENERATION=primary
ZONE=lowerduckpond.net

openssl req -new -newkey rsa:4096 -nodes \
  -keyout "${GENERATION}-${ZONE}.key" \
  -out "${GENERATION}-${ZONE}.csr" \
  -subj "/CN=${ZONE}" \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=clientAuth' \
  -addext "subjectAltName=DNS:${ZONE}"

openssl x509 -req \
  -in "${GENERATION}-${ZONE}.csr" \
  -CA "${GENERATION}-ca.pem" \
  -CAkey "${GENERATION}-ca.key" \
  -CAcreateserial -sha256 -days 30 -copy_extensions copy \
  -out "${GENERATION}-${ZONE}.pem"

openssl verify -CAfile "${GENERATION}-ca.pem" \
  "${GENERATION}-${ZONE}.pem"
openssl x509 -checkend 1209600 -noout \
  -in "${GENERATION}-${ZONE}.pem"
```

The last check requires at least 14 full days remaining. Inspect each leaf with
`openssl x509 -noout -subject -issuer -dates -text`; require `CA:FALSE` and
`TLS Web Client Authentication`, and do not print a private key.

Export the certificate-upload token under a distinct name. Upload each leaf to
its corresponding zone's hostname-certificate endpoint, piping the request so
no private-key-bearing JSON file is created:

```bash
export M3_QUALIFICATION_CERT_UPLOAD_TOKEN='temporary-certificate-upload-token'
export M3_QUALIFICATION_NET_ZONE_ID='lowerduckpond-net-zone-id'
export M3_QUALIFICATION_COM_ZONE_ID='lowerduckpond-com-zone-id'

jq --null-input \
  --rawfile certificate primary-lowerduckpond.net.pem \
  --rawfile private_key primary-lowerduckpond.net.key \
  '{certificate: $certificate, private_key: $private_key}' | \
  curl --silent --show-error --fail-with-body \
    --request POST \
    --header "Authorization: Bearer $M3_QUALIFICATION_CERT_UPLOAD_TOKEN" \
    --header 'Content-Type: application/json' \
    --data-binary @- \
    "https://api.cloudflare.com/client/v4/zones/$M3_QUALIFICATION_NET_ZONE_ID/origin_tls_client_auth/hostnames/certificates" | \
  jq --exit-status --raw-output \
    'if .success == true then .result.id else error("upload failed") end'
```

Repeat for all four generation/zone pairs, using the `.com` zone ID for the two
`.com` leaves. Record only the four returned IDs. Cloudflare permits at most ten
hostname certificates per zone, so confirm the two new leaves are the intended
entries rather than consuming unexplained capacity.

## Prepare the qualification root

Start from a clean, current `main` checkout. Load the administrative SSH key in
the workstation's agent. In the qualification root, prepare the two ignored
files from their examples and fill every value. Set
`origin_pull_generation = "primary"` and place only the four non-secret
certificate IDs in `origin_pull_certificate_ids`.

```bash
cd /absolute/path/to/lowerduckpond.net
git status --short --branch

cd infra/opentofu/environments/qualification
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
# Edit both ignored files; do not put provider credentials in either.

export AWS_ACCESS_KEY_ID='qualification-state-key-id'
export AWS_SECRET_ACCESS_KEY='qualification-state-key-secret'
export DIGITALOCEAN_TOKEN='existing-custom-scoped-opentofu-token'
export CLOUDFLARE_API_TOKEN='temporary-m3-edge-token'
export M3_QUALIFICATION_CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN"
export M3_QUALIFICATION_NET_ZONE_ID='lowerduckpond-net-zone-id'
export M3_QUALIFICATION_COM_ZONE_ID='lowerduckpond-com-zone-id'
export M3_QUALIFICATION_PRIMARY_CA_PATH='/absolute/private/path/primary-ca.pem'
export M3_QUALIFICATION_REPLACEMENT_CA_PATH='/absolute/private/path/replacement-ca.pem'

tofu init -backend-config=backend.hcl
cd ../../../..
just m3-qualification preflight
```

The preflight is read-only. It requires Full (strict) and Always Online off in
both zones, no existing zone-entrypoint ruleset in any phase the disposable
stack must own, per-hostname AOP entitlement, and exactly one self-issued,
CA-signing certificate in each public CA file. Each CA must have no more than a
five-year lifetime and at least 31 days remaining. The four distinct active
uploaded leaves must chain to the intended CA, carry only the intended zone DNS
name, have client-leaf constraints, have a 29–31 day upload-to-expiry lifetime,
and have at least 14 days remaining. If preflight fails, stop. Do not have M3.0
silently change a zone-wide setting or overwrite an existing ruleset.

After preflight passes, the leaf upload is verified. Remove the four
leaf private keys and CSRs from the workstation. Retain their public leaves and
IDs until teardown. Do not remove either CA key or public certificate.

## Provision the exact disposable stack

Create and inspect an encrypted saved plan:

```bash
cd infra/opentofu/environments/qualification
tofu plan -out=m3-qualification.tfplan
tofu show -json m3-qualification.tfplan | \
  ../../../../scripts/assert_m3_qualification_plan.py
tofu show m3-qualification.tfplan
```

The policy must report an exact initial boundary: 17 to add, 0 to change, and
0 to destroy. The human-readable plan must contain only the resources listed at
the top of this guide. Confirm all four A records are proxied, web ingress uses
only the committed Cloudflare network snapshot, the four AOP associations
select the primary IDs, and every ruleset expression names only the disposable
hostnames. Then apply the saved plan:

```bash
tofu apply m3-qualification.tfplan
tofu state list
```

Verify the new Droplet host key through DigitalOcean's out-of-band Recovery
Console before accepting it over SSH. If the console requires a temporary root
password, lock root again before leaving it. Require the fingerprint from
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` to match the ordinary
`ldp-admin` connection, then record it in the trusted workstation's
`known_hosts`.

## Run the edge and CA-rollover gate

Return to the repository root. Create the session, run the hermetic library
fragment, and install a dual-CA-trust Caddy generation:

```bash
just m3-qualification begin
just m3-qualification libraries
just m3-qualification configure dual
just m3-qualification edge primary
```

For every association transition below, edit only
`origin_pull_generation` in `terraform.tfvars`, save a new plan, run the exact
transition policy, inspect it, and apply it. A transition plan must contain
exactly four in-place AOP association updates and no other mutation. For the
first transition:

```bash
# Set origin_pull_generation = "replacement" in terraform.tfvars.
cd infra/opentofu/environments/qualification
tofu plan -out=m3-aop-replacement.tfplan
tofu show -json m3-aop-replacement.tfplan | \
  ../../../../scripts/assert_m3_qualification_plan.py --transition replacement
tofu show m3-aop-replacement.tfplan
tofu apply m3-aop-replacement.tfplan
cd ../../../..
just m3-qualification edge replacement
```

Use the same guarded procedure for this exact sequence:

1. select `primary`, apply a `--transition primary` plan, then run
   `just m3-qualification edge rollback`;
2. select `replacement`, apply a `--transition replacement` plan, then run
   `just m3-qualification edge forward`;
3. run `just m3-qualification configure replacement` to remove primary-CA
   trust from Caddy;
4. select `primary`, apply a `--transition primary` plan, then run
   `just m3-qualification edge retired-primary`; this must prove exact `525`
   rejection in both zones without an origin marker; and
5. select `replacement`, apply a `--transition replacement` plan, then run
   `just m3-qualification edge final`.

The final edge stage proves current zone policy, proxied DNS, distinct edge and
origin certificates, direct-origin denial, forwarding-header authenticity,
cache bypass, representation fidelity, reserved-path blocking, generic unknown
hosts, method/host/path/query-preserving HTTP redirects, and the absence of
stale bytes during a bounded disposable Caddy outage followed by recovery.

Install Playwright's pinned browsers and workstation dependencies once, then
produce the remaining report fragments under replacement-only trust:

```bash
uv run playwright install --with-deps chromium firefox webkit
just m3-qualification host replacement
just m3-qualification domains '/outside/repository/domain-attestation.json'
just m3-qualification browser
just m3-qualification assemble
```

Assembly succeeds only for the exact 54-check union with no failure, warning,
or skip. Review
`.artifacts/m3-qualification/m3-qualification.json`. It contains only fixed
check IDs, status, bounded allowlisted evidence, and fixed error codes. Attach
only that sanitized report to the M3.0 PR—never Ansible output, Caddy logs,
browser traces, Cloudflare responses, saved plans, state, or credentials.

## Mandatory teardown

Destroy from a saved, reviewed plan even when provisioning or a probe fails:

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
from the DigitalOcean project; all four A records, all four hostname AOP
associations, and all six disposable rulesets are absent; and Caddy left no
`_acme-challenge` record in either zone.

Delete each of the four uploaded leaves with the certificate-upload token and
its recorded zone and certificate ID:

```bash
curl --silent --show-error --fail-with-body \
  --request DELETE \
  --header "Authorization: Bearer $M3_QUALIFICATION_CERT_UPLOAD_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$M3_QUALIFICATION_NET_ZONE_ID/origin_tls_client_auth/hostnames/certificates/CERTIFICATE_ID" | \
  jq --exit-status '.success == true' >/dev/null
```

List hostname certificates in both zones and require all four IDs to be absent.
Then revoke both temporary M3 tokens. Remove `backend.hcl`, `terraform.tfvars`,
all saved plans, any request material, and leaf artifacts from the trusted
workstation. Retain the encrypted empty remote state, sanitized report, and the
backed-up CA material until the project records its production-CA disposition.

The destroy policy accepts an allowlisted subset after a partial create but
still rejects an unrelated address, a non-delete action, or a changed resource
identity. Never use a console toggle as teardown.

## Dangerous assumptions and stop conditions

This drill exists to test assumptions rather than normalize around them. Stop
for architecture review if any of these fail:

- the account and plan support per-hostname AOP, the three required zone
  ruleset phases, and four proxied disposable hostnames;
- the zones are already Full (strict), Always Online is off, and no existing
  root ruleset competes for a managed phase;
- Cloudflare accepts 30-day project-CA leaves and exposes stable active
  association state through the documented API;
- Cloudflare presents the newly selected leaf promptly enough for forward and
  rollback convergence and returns `525` after the old CA is retired;
- Cloudflare DNS answers expose only addresses in the reviewed provider
  snapshot, and both DigitalOcean and host firewalls deny the known origin;
- Cloudflare preserves the admitted response while cache bypass and transform
  controls are active, and its `/cdn-cgi` block wins before Caddy; and
- the provider returns a documented `520`–`527` response without stale or
  archived bytes when only the disposable origin is unavailable.

Rerunning the same guarded stage after ordinary propagation delay is safe. A
different status contract, missing entitlement, conflicting ruleset, inability
to prove teardown, or need to weaken origin authentication is not a retry; it
requires a reviewed change.
