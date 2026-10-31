# Isolated public-CA cold-recovery diagnostic

This is an inactive, separately reviewed diagnostic adapter. It is not a stock
qualification entry point, a completed isolated proof, or permission to create
credentials, containers, DNS records or certificates. No network mode is selected
by default. The existing seven-role credential protocol and scheduled cleanup
gates are unchanged.

The failed public action must pass in isolation, including cleanup, before
another complete qualification is attempted. A DNS connectivity probe or a
synthetic component test does not satisfy that prerequisite.

## Shared recovery and genuine prerequisites

`m3_11_public_sequence.exercise` is the existing native transition sequence.
Native qualification retains its original context, LiveStorage, credential,
identity and report guards. The isolated adapter has its own context and result
formats and never writes a combined qualification report.

The isolated path first needs a new owned local-MinIO fixture. Capture original
public roots, hosts and resolv.conf immediately after source creation, before
Molecule prepare or converge. The capture uses the existing bounded fresh-input
probe and copies; it cannot capture a previously prepared source.

`isolated_public_ca_recovery.reconstruct` calls the native full-history local
source preparation, actual reconstruction and reconstruction assertions. The
guest public probe still requires the real completed RestoreStore journal and
fenced source. There is no synthesized COMPLETE journal or fake LiveStorage.

The shared public sequence then requires:

1. A separate initially empty public certificate/account store and original
   public trust/DNS inputs under the exact selected Caddy binary and artifact.
2. Real DNS-01 publication observed independently in both zones, while ingress
   remains closed. Issuance finishing before the observed interruption fails.
3. Cancellation and record-cleanup observations, a stopped issuer with actual
   ACME account bytes, a destination systemd reboot, and unchanged retained bytes.
4. Resumption within the same native 1,800-second deadline; real public-CA
   certificates for all four fixed disposable subjects; native trusted-chain,
   subject, key and presented-certificate checks before ingress opens.
5. Both-zone activity and fresh challenge absence, the native peer/ingress
   assertions, and native service reactivation.

The functional observation explicitly leaves cleanup pending. It cannot serve
as a complete isolated prerequisite or combined qualification result.

## Failure observations

The controller opts into the selected guest's typed failure protocol. A failed
action returns only a strict envelope with the expected action/context, fixed
assertion and exception labels, and bounded line numbers from selected helper
modules. The controller rejects that envelope before accepting any observation,
retains `public-probe-failure-<action>.json` once, and raises a safe error through
the existing failure-stop and cleanup path. Malformed or mismatched envelopes
fail closed without saving their raw bytes. Receipt-write failure cannot hide
the action failure or suppress cleanup; cleanup failures cannot replace the
primary failure.

Exception messages, arguments, notes, chains, locals, source lines, configuration
and raw stderr are not diagnostic output. Known native TLS assertions use only
an exact fixed-code allowlist. Unknown failures remain unclassified. A transport
failure without a valid envelope remains an ordinary failed command.

Direct guest consumers, including native host stop/cleanup, do not opt in and
retain nonzero failure exits. A guest-program digest change requires fresh
source/runtime/preparation bindings. It cannot update or reinterpret a consumed
attempt. A suspension failure still fails the sequence before interruption,
reboot or any success receipt; reporting an error does not relax that gate.

The caller's final result/status can use `retained_failures` to surface validated
isolated failure receipts after reader disposal. Only fixed action filenames are
read and each receipt must match the original context. Damaged or unavailable
diagnostics yield fixed unavailable-action labels; they grant no authority and
cannot prevent the existing cleanup. Caller wiring and its exact package bytes
require their own offline finalizer check before another private handoff.

In the caller, import `retained_failures` from `scripts.m3_11_public_errors` and
add `result["public_probe_diagnostics"] = retained_failures(root / "phase")`
to both read-only status and the final result, after native closure checks and
reader disposal. This field is diagnostic only; it cannot replace any original
closure, admission or prerequisite fact.

## DNS modes

The strict plan requires a mode and resolver list. Missing or ambiguous input
fails before guest mutation; there is no fallback between modes.

- `authoritative` requires an empty resolver list. It preserves the native Caddy
  configuration and its default CertMagic authoritative propagation precheck.
- `recursive-precheck` requires one explicit IP resolver. It changes only the
  supported Caddy DNS `resolvers` field. It does not disable propagation checking,
  replace public roots, change the public CA or weaken native TLS assertions.
  It proves recursive visibility plus actual CA validation; it does not prove
  that the guest can reach public authorities directly.

An isolated result must be bound to the same implementation, binary, DNS mode,
resolver inputs and network path intended for a subsequent full run. The native
full qualification still has its original authoritative configuration; selecting
another mode here does not silently configure the full run.

## Three-role credential contract

The separate contract permits exactly these Cloudflare account-token roles:

| Role | Exact permissions | Resources | Placement |
| --- | --- | --- | --- |
| audit | Account API Tokens Read | One approved account | Private controller/watchdog only |
| caddy | DNS Write, Zone Read | The two approved zones | Owned public issuer guest only |
| observer | DNS Read, Zone Read | The same two zones | Private controller/watchdog only |

Only `lowerduckpond.net` and `lowerduckpond.com` can be selected. Actual account
and zone IDs are explicit private-plan inputs and checked against fresh provider
identity. Caddy's provider permission is zone-wide; the harness's two newly owned
challenge names do not reduce that underlying grant.

There are no Spaces, DigitalOcean, operator or Page Rules roles. The provider
adapter allows only the Cloudflare account-token API. The diagnostic does not
need a production Connect reader or independent Connect server credentials on
crow or the operator workstation.

The plan binds source, controller/fixture images, installed artifact, Caddy
binary, Docker endpoint/daemon, explicit approval/start cutoff, credential
lifetime and cleanup reserve. All three intents must agree on their plan,
request/expiry window, baseline inventory and distinct approved issuer/cleanup
fingerprints. Fresh permission-registry and inventory checks precede CREATE.
Admission is rechecked after prearm/journal I/O. Issuance capability remains
unverified until the actual approved CREATE; credentials are never created as
an authentication probe.

Fixture preparation precedes child issuance. A proposed four-hour credential
lifetime is sufficient for the native thirty-minute public phase plus an
explicit thirty-minute cleanup reserve; it is a proposal requiring fresh
approval, not a default or extension of a previous run window. The implementation
requires exact approved timing inputs. It never extends a consumed attempt.

## Cleanup and no replay

The contract requires one durable run-wide reservation as well as exclusive
local markers and independently acknowledged intents before CREATE. Unknown
CREATE outcomes stop later issuance and cannot be replayed from another output
directory. Exact name, ID, baseline exclusion, grants, resources, creation and
expiry are required for revocation; a prefix alone is insufficient.

After positively fencing the issuer, cleanup tries every known owned obligation.
A journal or one-provider failure cannot suppress the other safe revocations.
Exact owned expired/disabled tokens may be revoked; issuance still requires
active authentication. Missing secrets, uncertain CREATE, provider absence
without denied authentication, or missing independent readback leave closure
pending. No child secret belongs in public journal records, artifacts or logs.

The public issuer's failure-stop guard checks the exact destination and original
guest journal/unit/context without depending on an unrelated MinIO or peer
remaining alive. Normal functional identity checks remain strict.

## Native execution and closure

The supported sequence is deliberately separate from full qualification:

1. Acquire `m3_11_isolation_runtime.Fence` using the native daemon-wide admission
   name. Use `Evidence` to verify the actual native evidence volume and mount
   inode, then retain its ticket. A second output directory cannot bypass the
   per-run create-only, fsynced reservation.
2. On the new owned local-MinIO graph, call the installed adapter's `capture`
   immediately after source creation and before prepare/converge. Complete
   `reconstruct` and `observe_preparation`. The latter reads the actual completed
   restore journal, selected Caddy binary, original public inputs and exact five
   actors; it cannot manufacture a completed reconstruction.
3. Derive the explicit public plan and three intents after preparation. Store its
   canonical `manifest.json` under `/evidence/public-ca/runs/<run-id>/`. The
   private phase and child files use that directory's `phase/` and `credentials/`.
   No current plan or network mode is installed by this source change.
4. Place only the approved cleanup-reader configuration at
   `/cleanup/public-ca/<run-id>/access.json` in the existing native cleanup volume.
   `m3_11_isolation_controller.publication` publishes the exact manifest and
   genuine prepared graph under a diagnostic-only Connect tag/schema.
5. Install the identical public JSON as `M3_11_PUBLIC_CA_MANIFEST` and use the
   protected **M3.11 isolated public CA cleanup** workflow. Candidate `validate`
   is GET-only. `confirm` writes one exact pre-CREATE confirmation. The existing
   `M3_11_CONNECT_BOOTSTRAP` secret and seven-role scheduled cleaner stay intact.
   No independent server credentials are exported to crow or the operator.
6. `arm` creates the separate cleanup-only watchdog once. `require_armed` checks
   its exact image, command, mise entrypoint, image-derived environment, socket,
   mounts and fresh heartbeat. `execute` captures the actual confirmation run
   through authenticated GitHub GETs and verifies both ZIP digests before the
   native once-only issuer can create the three children. The installed adapter
   runs the shared public recovery sequence once.
7. Host cleanup first fences the issuer and stops all exact prepared actors,
   even during a Connect outage. Caddy owns challenge cleanup; fallback deletion
   accepts only actual observed ID/name/type/content tuples. Fresh observer
   absence, provider absence and host denied-authentication facts are required.
   An unknown CREATE remains pending. Known safe revocations still proceed when
   another role or publication fails.
8. The protected independent `reconcile`/`cleanup` operations select only the
   existing Cloudflare account cleanup authority. They can revoke exact owned
   tokens and freshly verify provider absence, but cannot invent a host denied
   probe without its child bytes. An explicit remote cleanup requests local
   consumer stop; expiry permits owned revocation while uncertainty remains.
9. `m3_11_isolation_seal.seal` checks original native functional envelopes,
   interrupted/rebooted account continuity, four actual production-CA subjects,
   both-zone publication and DNS cleanup, exact stopped actors, all three denied
   credentials and a complete independent native run/job/two-ZIP proof. It
   rechecks local state after the external capture and writes only the separate
   prerequisite. A status label, dispatch receipt or connectivity probe cannot
   substitute for these observations.

`Fence.release` performs the authenticated final capture internally. It releases
stock qualification admission only after an **authoritative-mode** prerequisite
passes; a recursive-mode result does not silently permit different stock
semantics. A failed or uncertain diagnostic retains the inert fence and evidence
while cleanup continues. A later corrective attempt requires an explicit owned
handoff of that fence, never removal of reservation markers or automatic retry.

The diagnostic workflow is inert while its public variable is absent. After
retaining final native proof, the live closeout removes that variable, stops the
exact watchdog and disposes only the approved temporary reader/child copies.
Authoritative vault originals and all evidence remain. That live configuration
and disposal are part of the future bounded execution, not effects of this PR.

## Current network evidence

The supplied outer Docker Compose places `coder_dind` at `192.168.20.3` on
macvlan `eth0.20`, gateway `192.168.20.1`. LAN-only DNS NAT is not established as
the cause of the failed authoritative queries. Actual pfSense ingress remains
unproven; a narrow existing log/state or coordinated capture for source
`192.168.20.3` to authoritative UDP/TCP 53 on VLAN20 is the remaining route check.
No resolver mode or network-policy change is selected here.

Elevated Docker metadata inspection was denied during preparation. It was not
retried or bypassed. Offline tests exercise real adapters with synthetic
transport responses; they do not claim a current daemon or live CA proof.

## Bounded execution proposal

Once integration/review and the network choice are complete, present one fresh
approval binding the exact source/image/artifact/plan and one diagnostic attempt:

- Four fresh local fixture containers: source, local MinIO, destination and
  controlled ACME peer; plus the native controller/cleanup actor machinery.
  Source and destination need the existing privileged systemd/ext4 fixture mode.
  No new Droplet, production bucket or preserved-fixture restart is involved.
- The native fixture uses 56 GiB of sparse virtual ext4 images across source and
  destination. This is not an actual disk-use ceiling; images, caches, Restic,
  MinIO and retained evidence consume additional storage.
- Three fresh short-lived Cloudflare children with the exact grants above,
  privately delivered to their designated processes. Existing provision/cleanup
  readers may reveal their existing secrets and retain journal-write capability;
  their temporary copies need exact private destinations and verified disposal.
- Real production Let's Encrypt DNS-01 activity for apex/wildcard subjects below
  one new UUIDv7 prefix in each zone, including a controlled interruption/reboot.
  The native phase deadline stays 1,800 seconds. There is no automatic diagnostic
  or complete-qualification retry.
- Caddy owns primary challenge cleanup. Any fallback delete must be separately
  bounded to exact observed owned record IDs/content. No unrelated DNS, archive,
  Page Rules or network-policy change is included.

This is not yet a live approval request: the final merged source/runtime
bindings, explicit network selection, fresh exact timestamps and live native
cleanup proofs must be bound before execution. The previous full-qualification start window is not reused.
