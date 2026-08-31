# M3.7 production public-edge rollout

> **Status: implementation complete; production is still direct and dark.**
> Complete the read-only starting gate on clean, current `main`, then stop for
> explicit authorization before the first host convergence or protected edge
> plan. Static publication remains disabled throughout M3.7.

M3.7 replaces the production Caddy runtime with complete immutable generations
and moves the two public zones behind the reviewed Cloudflare edge. The live
transaction is deliberately split so a rollback never leaves an origin that
requires a client certificate or Cloudflare source address behind DNS-only
records.

## Custody and the remaining CA choice

The origin-pull CA private key and passphrase remain only in the trusted
operator backup. Cloudflare receives one replaceable client leaf and its
temporary private key for each zone. Caddy receives only the CA's public
certificate. OpenTofu and GitHub receive only the two non-secret Cloudflare
certificate IDs; no CA or leaf private key may enter this repository, GitHub,
OpenTofu configuration, a plan, or state.

The retained M3.0 qualification roots have not been designated as production
roots. The recommended default is a new, separately named production CA so the
disposable drill and service-lifetime trust domains remain distinct. Reusing a
retained qualification root is technically compatible with the gate only
while it still satisfies the accepted five-year and remaining-lifetime policy,
but requires an explicit operator decision. The commands below assume a new
production CA.

Work outside the repository with a restrictive umask. The CA key is encrypted;
the two leaf keys are intentionally unencrypted because Cloudflare must receive
them and are deleted after upload verification.

```bash
umask 077
production_pki="$HOME/private/lowerduckpond-production-origin-pull"
install -d -m 0700 -- "$production_pki"
cd "$production_pki"

openssl genrsa -aes256 -out production-origin-pull-ca.key 4096
openssl req -x509 -new -key production-origin-pull-ca.key -sha256 -days 1825 \
  -subj '/CN=Lower Duck Pond production origin pull CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out production-origin-pull-ca.pem

for zone in lowerduckpond.net lowerduckpond.com; do
  openssl req -new -newkey rsa:4096 -nodes \
    -keyout "production-${zone}.key" \
    -out "production-${zone}.csr" \
    -subj "/CN=${zone}" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=clientAuth' \
    -addext "subjectAltName=DNS:${zone}"

  openssl x509 -req \
    -in "production-${zone}.csr" \
    -CA production-origin-pull-ca.pem \
    -CAkey production-origin-pull-ca.key \
    -CAserial production-origin-pull-ca.srl \
    -CAcreateserial -sha256 -days 365 -copy_extensions copy \
    -out "production-${zone}.pem"

  openssl verify -purpose sslclient \
    -CAfile production-origin-pull-ca.pem \
    "production-${zone}.pem"
  openssl x509 -checkend 5184000 -noout -in "production-${zone}.pem"
done
```

Inspect the CA and both leaves without printing either private key. Require a
self-issued `CA:TRUE` root, `CA:FALSE` leaves, TLS Web Client Authentication,
the exact single-zone DNS name, and the expected dates. Back up the encrypted
CA key, public certificate, serial file, and passphrase separately before
uploading anything. A production leaf is valid for at most one year and must
have at least 60 full days remaining; the CA is valid for at most five years
and must retain at least one full production-leaf lifetime.

## Upload the two zone-level leaves

Create a distinct Cloudflare certificate-lifecycle token valid for no more
than seven days. Limit it to the two owned zones and only Zone Read plus SSL
and Certificates Write. This is not the production OpenTofu edge token and not
the non-expiring Caddy DNS token.

On the trusted workstation, set the two known zone IDs and the temporary token,
then upload exactly one leaf to each zone-level endpoint. The pipeline keeps
the private-key-bearing request in memory and prints only the public ID.

```bash
set -euo pipefail

export M3_7_CERTIFICATE_UPLOAD_TOKEN='temporary-seven-day-token'
export CLOUDFLARE_ZONE_ID='lowerduckpond-net-zone-id'
export CLOUDFLARE_TENANT_ZONE_ID='lowerduckpond-com-zone-id'

upload_response_directory=$(mktemp -d)
chmod 0700 "$upload_response_directory"

upload_zone_leaf() {
  local zone_id=$1
  local certificate_path=$2
  local private_key_path=$3
  local response_path=$4

  if ! jq --null-input \
      --rawfile certificate "$certificate_path" \
      --rawfile private_key "$private_key_path" \
      '{certificate: $certificate, private_key: $private_key}' | \
      curl --silent --show-error --fail-with-body \
        --request POST \
        --header "Authorization: Bearer $M3_7_CERTIFICATE_UPLOAD_TOKEN" \
        --header 'Content-Type: application/json' \
        --data-binary @- \
        --output "$response_path" \
        "https://api.cloudflare.com/client/v4/zones/${zone_id}/origin_tls_client_auth"
  then
    return 1
  fi
  chmod 0600 "$response_path"
  jq --exit-status --raw-output \
    'if .success == true
        and (.result.id | type) == "string"
        and (.result.id | test("^[0-9a-f]{32}$"))
     then .result.id else error("zone-level leaf upload failed") end' \
    "$response_path"
}

if ! lowerduckpond_net_certificate_id=$(
    upload_zone_leaf \
    "$CLOUDFLARE_ZONE_ID" \
    production-lowerduckpond.net.pem \
    production-lowerduckpond.net.key \
    "$upload_response_directory/lowerduckpond-net.json"
); then
  printf 'STOP: .net upload failed; retain secured response directory: %s\n' \
    "$upload_response_directory" >&2
  exit 1
fi
if ! lowerduckpond_com_certificate_id=$(
    upload_zone_leaf \
    "$CLOUDFLARE_TENANT_ZONE_ID" \
    production-lowerduckpond.com.pem \
    production-lowerduckpond.com.key \
    "$upload_response_directory/lowerduckpond-com.json"
); then
  printf 'STOP: .com upload failed; retain secured response directory: %s\n' \
    "$upload_response_directory" >&2
  exit 1
fi

export CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID="$lowerduckpond_net_certificate_id"
export CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID="$lowerduckpond_com_certificate_id"

rm -- "$upload_response_directory/lowerduckpond-net.json" \
  "$upload_response_directory/lowerduckpond-com.json"
rmdir -- "$upload_response_directory"

jq --null-input \
  --arg lowerduckpond_net "$CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID" \
  --arg lowerduckpond_com "$CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID" \
  '{lowerduckpond_net: $lowerduckpond_net,
    lowerduckpond_com: $lowerduckpond_com}' \
  > origin-pull-certificate-ids.json
chmod 0600 origin-pull-certificate-ids.json
```

Do not enable zone-level Authenticated Origin Pulls in the Cloudflare UI. The
protected OpenTofu transition owns that setting. Keep the temporary lifecycle
token only through the reviewed rollout and rollback window, never beyond its
seven-day maximum, then revoke it. A later rotation creates a fresh token.

## Configure the protected workflow inputs

The production OpenTofu edge token is an account-owned token limited to both
zones with DNS Write, Zone Settings Write, Cache Settings Write, Config
Settings Write, Zone WAF Write, and SSL and Certificates Write. It does not
need Zone Read and must not receive a leaf key. The Caddy runtime token remains
separate and retains only Zone Read and DNS Write for the two zones.

Create one additional, temporary account-owned token for the read-only starting
gate. Give it only Account API Tokens Read on the single Lower Duck Pond
account, set a lifetime of no more than seven days, and name it for the M3.7
token audit and creation date. Do not install or back up this token. The gate
uses it only to read the two target tokens' Cloudflare policy documents, bind
them to their self-verified token IDs, and prove the exact permission and zone
resource sets above. Revoke it after the gate passes.

After locally exporting the verified OpenTofu edge token as
`CLOUDFLARE_API_TOKEN`, set the four public identifiers and replace the opaque
protected secret. These commands do not print the token.

```bash
gh variable set CLOUDFLARE_ZONE_ID \
  --env production --body "$CLOUDFLARE_ZONE_ID"
gh variable set CLOUDFLARE_TENANT_ZONE_ID \
  --env production --body "$CLOUDFLARE_TENANT_ZONE_ID"
gh variable set CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID \
  --env production --body "$CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID"
gh variable set CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID \
  --env production --body "$CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID"
printf '%s' "$CLOUDFLARE_API_TOKEN" | \
  gh secret set CLOUDFLARE_API_TOKEN --env production
```

The local read-only gate can prove the token supplied to it, the four visible
GitHub variables, and the existence of the opaque GitHub secret name. GitHub
does not expose a stored secret for comparison, so replacing the secret with
the same locally verified edge token is an explicit operator custody step.

## Run the read-only starting gate

Start from clean, current `main`. Load the existing administrative key and
export the already-backed-up M3.6 operator public identity. Supply the existing
bucket-scoped production-state credentials, not the full-access Spaces
operator key. Set the CA-path JSON to the public certificate only.

```bash
cd ~/dev/lowerduckpond.net
git switch main
git pull --ff-only
git status --short --branch

export ANSIBLE_PRIVATE_KEY_FILE='/absolute/path/to/lowerduckpond.net-admin'
ssh-add "$ANSIBLE_PRIVATE_KEY_FILE"
export STATIC_OPERATOR_PRINCIPAL='production-static-operator'
export STATIC_OPERATOR_PUBLIC_KEY="$(cat /absolute/path/to/static-operator.pub)"

export OPENTOFU_STATE_ACCESS_KEY_ID='bucket-scoped-state-key-id'
export OPENTOFU_STATE_SECRET_ACCESS_KEY='bucket-scoped-state-secret'
export OPENTOFU_ENCRYPTION_PASSPHRASE='production-state-passphrase'
export OPENTOFU_STATE_BUCKET='production-state-bucket'
export SPACES_REGION='nyc3'

export CADDY_CLOUDFLARE_API_TOKEN='two-zone-caddy-dns-token'
export CLOUDFLARE_API_TOKEN='two-zone-opentofu-edge-token'
export M3_7_TOKEN_AUDIT_TOKEN='temporary-account-token-read-token'
export CADDY_ORIGIN_PULL_CA_PATHS_JSON="$(
  jq --compact-output --null-input \
    --arg path "$production_pki/production-origin-pull-ca.pem" \
    '[$path]'
)"

# Retain the four CLOUDFLARE_* IDs exported during upload, or restore them
# from the separately backed-up public record before running the gate.
just preflight-m3-7-production
```

The command first repeats the full M3.6 dark-host gate. It then reads encrypted
production state and requires the direct phase (including the compatible
legacy state before that output is first materialized), no managed M3.7 edge
policy, exactly one direct A record (and no competing record type) at each
`.net` apex and wildcard, and no record of any type at either `.com` rollout
name. It proves all three token roles are distinct, the two durable tokens have
exactly their reviewed write/read permissions and two-zone resources, no enabled
zone-level or per-hostname origin-pull policy, no conflicting zone entrypoint,
one safe public CA, and exactly one active, selected, CA-chained zone-level
leaf per zone. It also requires the four GitHub production variables to match
and protected infrastructure plans to remain enabled. It performs no plan,
apply, upload, DNS write, GitHub write, or host convergence.

After the gate passes, delete the two leaf keys and CSRs from the workstation;
retain the public leaves, ID file, encrypted CA key, CA certificate, serial,
and separate backups. Stop and request explicit authorization before
continuing.

## Authorized convergence sequence

Never collapse these boundaries into one shell chain or infer authorization
for a later boundary from an earlier one.

1. With `CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED=false`, run the separately
   authorized guarded `just configure-production`. This stages the public CA
   in a complete generation while leaving origin-pull verification optional and
   both web firewalls open.
2. Dispatch a protected Infrastructure `plan` from exact `main` with
   `public_edge_phase=proxied` and `origin_pull_host_state=unconfirmed`. Review
   the exact plan, then dispatch `apply` with the recorded run ID and the same
   inputs.
3. Prove both zones through the edge, Full (strict), the selected account-only
   client leaves, cache and transform policy, `/cdn-cgi/` denial, forwarded
   address authenticity, exact representations, strict host handling, and
   continued direct-origin availability for rollback.
4. With `CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED=true`, run the separately
   authorized guarded production convergence. Prove edge requests succeed and
   direct requests without the project leaf fail.
5. Dispatch and apply the separately reviewed `enforced` plan with
   `origin_pull_host_state=required`. This narrows DigitalOcean ingress to the
   same committed Cloudflare network union already used by the host and Caddy.
6. Repeat edge, direct-origin-denial, reboot, selected-generation, browser, and
   disabled-publication proofs. Revoke the temporary certificate-lifecycle
   token before its deadline.

Rollback from `enforced` first applies the reviewed `proxied` phase, then
converges the host with enforcement false, and only then applies `direct` with
`origin_pull_host_state=staged`. Reopen both origin boundaries before making
records DNS-only; never strand a direct record behind Cloudflare-only ingress
or required client authentication.
