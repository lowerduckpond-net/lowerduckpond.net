"""Run the existing site playbook once on the reviewed fenced disposable source."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import file_digest, sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent.durable import DurableDirectory

from scripts.m3_11_production_converge import recap
from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import Attempt, publish
from scripts.m3_12_disposable_routing import prepare_source_bootstrap
from scripts.m3_12_droplet_inventory import ApprovedAllocation, ProviderIdentity
from scripts.m3_12_droplet_journey import committed_dispatches
from scripts.m3_12_droplet_native import REPOSITORY, AdapterInputs, inspect_host
from scripts.m3_12_droplet_scope import ReviewedJourney
from scripts.m3_12_droplet_ssh import Endpoint, _arguments, installation_inventory, source_command
from scripts.qualification_probe import bounded_command

FORMAT = "lowerduckpond-m3-12-source-operator-v1"
HOST = "m312-source"
CONFIG = REPOSITORY / "config/ansible"
KEYS = {
    "format",
    "manifestSha256",
    "predecessor",
    "predecessorBootstrapSha256",
    "sitePolicy",
    "sitePolicySha256",
    "candidate",
    "observedResources",
    "productionExclusions",
    "hostPublicKey",
    "originPullCaSha256",
    "backupNodeName",
    "operatorPublicKey",
    "operatorPrincipal",
}
CREDENTIALS = (
    "CADDY_CLOUDFLARE_API_TOKEN",
    "RESTIC_PASSWORD",
    "SPACES_BACKUP_ACCESS_KEY_ID",
    "SPACES_BACKUP_SECRET_ACCESS_KEY",
    "SPACES_ARCHIVE_ACCESS_KEY_ID",
    "SPACES_ARCHIVE_SECRET_ACCESS_KEY",
)


def _read(directory: DurableDirectory, name: str) -> bytes:
    return directory.read_regular(
        (name,), expected_owner=os.geteuid(), expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
    )


def _digest(path: Path) -> str:
    require(path.resolve(strict=True) == path and path.is_file(), "source-operator-unsafe-file")
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def _inputs(
    attempt: Attempt, reviewed_sha256: str, identity_file: Path
) -> tuple[Document, AdapterInputs, Endpoint]:
    with DurableDirectory.open(
        attempt.directory, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as retained:
        raw = _read(retained, "source-operator.json")
        allocation = _read(retained, "journey-allocation.json")
        intent = _read(retained, "journey-dark-stage-intent.json")
    require(sha256(raw).hexdigest() == reviewed_sha256, "source-operator-review-changed")
    review: Document = decode_json_object(raw)
    require(
        set(review) == KEYS and review["format"] == FORMAT and encode(review) == raw,
        "source-operator-review-invalid",
    )
    inputs = AdapterInputs(
        attempt,
        allocation,
        ReviewedJourney(
            review["manifestSha256"],
            tuple((row["name"], row["raw"].encode("ascii")) for row in review["predecessor"]),
            review["predecessorBootstrapSha256"],
            review["sitePolicySha256"],
            encode(review["candidate"]),
            encode(review["observedResources"]),
            encode(review["productionExclusions"]),
        ),
        intent,
    )
    scope, _ = inputs.open(frozenset({"dark-stage"}))
    host = scope["resources"]["hosts"]["source"]
    target = host["target"]
    identity = ProviderIdentity(
        target["droplet"]["projectIdSha256"],
        target["droplet"]["dropletId"],
        host["enrollment"]["ipv4"],
    )
    endpoint = Endpoint(
        ApprovedAllocation(
            run_id=scope["runId"],
            role="source",
            state_sha256=target["stateSha256"],
            allocation_sha256=target["allocationSha256"],
            inventory_sha256=target["inventorySha256"],
            transaction_namespace_sha256=target["transactionNamespaceSha256"],
            identity=identity,
        ),
        identity,
        review["hostPublicKey"].encode("ascii"),
        identity_file,
    )
    return review, inputs, endpoint


@contextmanager
def _owner(endpoint: Endpoint, known_hosts: Path, handoff: Document) -> Iterator[str]:
    command = source_command(handoff["artifactSha256"], "owner")
    with subprocess.Popen(  # noqa: S603 - one pinned host and fixed source owner command
        _arguments(endpoint, known_hosts, command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert process.stdin is not None and process.stdout is not None  # noqa: S101 - fixed pipes
        try:
            process.stdin.write(encode(handoff))
            process.stdin.flush()
            line = process.stdout.readline(65)
            require(
                re.fullmatch(rb"[0-9a-f]{64}\n", line) is not None and line != b"0" * 64 + b"\n",
                "source-operator-owner-refused",
            )
            yield line[:-1].decode("ascii")
            require(process.poll() is None, "source-operator-owner-ended")
        finally:
            # EOF revokes the owner and drains the fixed unit, including after interruption.
            process.stdin.close()
        require(process.wait() == 0, "source-operator-release-unverified")


def _run_site(  # noqa: PLR0913 - exact private controller inputs
    directory: Path,
    endpoint: Endpoint,
    handoff: Document,
    variables: Document,
    context: str,
    *,
    credentials: dict[str, str],
) -> tuple[str, dict[str, int]]:
    public_key, _ = endpoint.validate()
    known_hosts = directory / "known_hosts"
    known_hosts.write_bytes(endpoint.provider.ipv4.encode() + b" " + public_key + b"\n")
    known_hosts.chmod(0o600)
    inventory = installation_inventory(endpoint, known_hosts)
    inventory["hosting_nodes"]["hosts"][HOST]["ansible_connection"] = "ldp_m3_12_droplet"
    files = directory / "inventory.json", directory / "variables.json"
    for path, contents in zip(files, (inventory, variables), strict=True):
        path.write_bytes(encode(contents))
        path.chmod(0o600)
    receipt = directory / "recap.json"
    with _owner(endpoint, known_hosts, handoff) as token:
        environment = {
            # Do not inherit ANSIBLE, SSH agent, provider or vault overrides.
            **credentials,
            "PATH": "/usr/bin:/bin",
            "HOME": str(directory),
            "LANG": "C.UTF-8",
            "ANSIBLE_CONFIG": str(CONFIG / "ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(directory),
            "ANSIBLE_COLLECTIONS_PATH": str(Path.home() / ".ansible/collections"),
            "ANSIBLE_CONNECTION_PLUGINS": str(CONFIG / "plugins/connection"),
            "ANSIBLE_CALLBACK_PLUGINS": str(CONFIG / "plugins/callback"),
            "ANSIBLE_CALLBACKS_ENABLED": "ldp_m3_11_receipt",
            "ANSIBLE_SSH_USETTY": "false",
            "ANSIBLE_SSH_RETRIES": "0",
            "ANSIBLE_SSH_TRANSFER_METHOD": "piped",
            "LDP_M3_12_DROPLET_LEASE_TOKEN": token,
            "LDP_M3_12_SOURCE_ARTIFACT": handoff["artifactSha256"],
            "LDP_M3_11_PLAYBOOK_CONTEXT": context,
            "LDP_M3_11_PLAYBOOK_RECEIPT": str(receipt),
        }
        result = subprocess.run(  # noqa: S603 - fixed one-host playbook and immutable selection
            [
                str(REPOSITORY / ".venv/bin/ansible-playbook"),
                "--inventory",
                str(files[0]),
                "--limit",
                HOST,
                "--extra-vars",
                "@" + str(files[1]),
                str(CONFIG / "playbooks/site.yml"),
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        require(result.returncode == 0, "source-operator-site-failed")
        raw, counters = recap(receipt, context, idempotent=False, expected_host=HOST)
    return sha256(raw).hexdigest(), counters


def _variables(
    review: Document, handoff: Document, artifact: Path, ca: list[Path], admin: list[str]
) -> Document:
    def credential(name: str) -> str:
        return "{{ lookup('ansible.builtin.env', '" + name + "') }}"

    return {
        "static_host_agent_artifact_path": str(artifact),
        "static_host_agent_artifact_sha256": handoff["artifactSha256"],
        "static_host_agent_verified_completed_candidate": False,
        "static_host_agent_archive_lifecycle_enabled": True,
        "caddy_generation_enabled": True,
        "static_publication_enabled": False,
        "host_recovery_bootstrap_enabled": False,
        "backup_static_recovery_enabled": True,
        "backup_audit_rotation_enabled": True,
        "m3_12_source_bootstrap_required": True,
        "firewall_admin_source_cidrs": admin,
        "backup_node_name": review["backupNodeName"],
        "backup_repository": handoff["repository"],
        "backup_spaces_region": handoff["backupRegion"],
        "caddy_origin_pull_ca_paths": [str(path) for path in ca],
        "caddy_origin_pull_enforcement_enabled": True,
        "static_operator_public_key": review["operatorPublicKey"],
        "static_operator_principal": review["operatorPrincipal"],
        "caddy_cloudflare_api_token": credential("CADDY_CLOUDFLARE_API_TOKEN"),
        "backup_restic_password": credential("RESTIC_PASSWORD"),
        "backup_spaces_access_key_id": credential("SPACES_BACKUP_ACCESS_KEY_ID"),
        "backup_spaces_secret_access_key": credential("SPACES_BACKUP_SECRET_ACCESS_KEY"),
        "static_host_agent_archive_configuration": {
            "format": "lowerduckpond-archive-configuration-v1",
            "region": handoff["archiveRegion"],
            "bucket": handoff["archiveBucket"],
            "accessKeyId": credential("SPACES_ARCHIVE_ACCESS_KEY_ID"),
            "secretAccessKey": credential("SPACES_ARCHIVE_SECRET_ACCESS_KEY"),
        },
    }


def run(
    attempt: Attempt, review_sha256: str, identity: Path, artifact: Path, ca: list[Path]
) -> None:
    with attempt.lock("droplet-journey.lock", blocking=False):
        review, inputs, endpoint = _inputs(attempt, review_sha256, identity)
        scope, action = inputs.open(frozenset({"dark-stage"}))
        require(
            _digest(artifact) == scope["candidate"]["hostAgentSha256"]
            and len(ca) in (1, 2)
            and [_digest(path) for path in ca] == review["originPullCaSha256"],
            "source-operator-artifact-or-trust-changed",
        )
        marker = f"native-submitted-{digest(action)}.json"
        require(
            not os.path.lexists(attempt.directory / marker)
            and "dark-stage" not in committed_dispatches(attempt, scope),
            "source-operator-original-result-needs-reconciliation",
        )
        credentials = {name: os.environ.get(name, "") for name in CREDENTIALS}
        require(all(credentials.values()), "source-operator-scoped-credentials-missing")
        handoff = prepare_source_bootstrap(
            inputs, endpoint, encode(review["sitePolicy"]), bounded_command
        )
        host = scope["resources"]["hosts"]["source"]
        variables = _variables(review, handoff, artifact, ca, host["adminCidrs"])
        evidence = {
            "format": "lowerduckpond-m3-12-source-converge-evidence-v1",
            "reviewSha256": review_sha256,
            "intentSha256": digest(action),
            "handoffSha256": digest(handoff),
            "sourceTargetSha256": digest(host["target"]),
            "stateKey": host["stateKey"],
            "sourceStateSha256": host["target"]["stateSha256"],
            "artifactSha256": handoff["artifactSha256"],
            "playbookSha256": _digest(CONFIG / "playbooks/site.yml"),
        }
        publish(attempt.directory, "source-converge-original.json", evidence)
        publish(attempt.directory, marker, {"intentSha256": digest(action)})
        with TemporaryDirectory(prefix="m312-source-", dir=attempt.directory) as work:
            recap_sha, counters = _run_site(
                Path(work), endpoint, handoff, variables, digest(evidence), credentials=credentials
            )
        observed = inspect_host(inputs, endpoint, bounded_command)
        require(
            observed["bootSha256"] == handoff["bootSha256"]
            and observed["state"]
            == {
                "artifactSha256": handoff["artifactSha256"],
                "publication": "dark",
                "launchPresent": False,
            },
            "source-operator-final-observation-changed",
        )
        publish(
            attempt.directory,
            "source-converge-result.json",
            {
                **evidence,
                "recapSha256": recap_sha,
                "counters": counters,
                "observation": observed,
                "ownerReleased": True,
            },
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    parser.add_argument("--review-sha256", required=True)
    parser.add_argument("--identity-file", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--ca", action="append", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(
            Attempt(args.attempt.absolute()),
            args.review_sha256,
            args.identity_file,
            args.artifact,
            args.ca,
        )
    except ValidationError as error:
        parser.exit(
            2, f"Disposable source converge refused ({error}). Inspect the private attempt.\n"
        )
    except OSError, RuntimeError, ValueError, KeyError, TypeError:
        parser.exit(
            2, "Disposable source converge refused or incomplete. Inspect the private attempt.\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
