"""Prepare P4 journeys using pinned, independently enrolled SSH endpoints."""

from __future__ import annotations

import os
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.droplet_enrollment import ENROLLMENT, EXCLUSIONS, TARGET
from lowerduckpond_static_host_agent.durable import DurableDirectory, StateAlreadyExistsError
from lowerduckpond_static_host_agent.host_restore_bootstrap import verify_bootstrap_inputs
from lowerduckpond_static_host_agent.host_restore_delivery import LAUNCH_FILES, publication_files
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    DROPLET_BINDING,
    DROPLET_SCOPE_FORMAT,
    RestorePhase,
)
from lowerduckpond_static_host_agent.host_restore_paths import private_directory

from scripts.m3_12_contracts import (
    DISPOSABLE,
    MAX_RECORD_BYTES,
    Document,
    decode,
    digest,
    encode,
    require,
    validate_launch,
)
from scripts.m3_12_diagnostic_store import Attempt, clock, failure, publish, read
from scripts.m3_12_droplet_inventory import (
    ConnectedDroplet,
    OwnedDroplet,
    enrollment_records,
    prepare_source_and_restore,
)
from scripts.m3_12_droplet_ssh import (
    Endpoint,
    installation_inventory,
    observe,
    restore_delivery,
    restore_status,
)

COLD_STATE = (
    {"artifactSha256": None, "launchPresent": False, "publication": "absent"},
    {"artifactSha256": None, "launchPresent": False, "publication": "dark"},
)


def _seal(directory: Path, name: str, document: Document) -> None:
    try:
        publish(directory, name, document)
    except FileExistsError:
        require(read(directory, name) == document, "droplet-preparation-original-changed")


def _scope(endpoint: Endpoint, production: Document) -> Document:
    _, key = endpoint.validate()
    approved = endpoint.allocation
    require(
        type(endpoint.provider.droplet_id) is int
        and endpoint.provider.droplet_id > 0
        and all(
            re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for value in (
                endpoint.provider.project_id_sha256,
                approved.state_sha256,
                approved.allocation_sha256,
                approved.inventory_sha256,
                approved.transaction_namespace_sha256,
            )
        ),
        "droplet-preparation-allocation-invalid",
    )
    excluded = {*production["dropletIds"], *production["addresses"], *production["identityDigests"]}
    identifiers = {
        endpoint.provider.droplet_id,
        endpoint.provider.ipv4,
        key,
        digest(endpoint.provider.document()),
        approved.state_sha256,
        approved.allocation_sha256,
        approved.inventory_sha256,
        approved.transaction_namespace_sha256,
    }
    require(not excluded.intersection(identifiers), "production-crossover")
    return {
        "provider": endpoint.provider.document(),
        "role": approved.role,
        "sshKeySha256": key,
        "stateSha256": approved.state_sha256,
        "allocationSha256": approved.allocation_sha256,
        "inventorySha256": approved.inventory_sha256,
        "transactionNamespaceSha256": approved.transaction_namespace_sha256,
    }


def _observe_role(
    attempt: Attempt, role: str, endpoint: Endpoint, prepared: Document
) -> tuple[OwnedDroplet, Document]:
    doc = observe(endpoint)
    _seal(
        attempt.directory,
        f"droplet-{role}-observation.json",
        {
            "format": "lowerduckpond-m3-12-preparation-observation-v1",
            "role": role,
            "preparationSha256": digest(prepared),
            "observation": doc,
        },
    )
    return _owned(endpoint, prepared[role]["sshKeySha256"], doc), doc


def _owned(endpoint: Endpoint, ssh_key_sha256: str, observation: Document) -> OwnedDroplet:
    observed = ConnectedDroplet(
        provider=endpoint.provider,
        metadata_id=observation["metadata"]["dropletId"],
        metadata_ipv4=observation["metadata"]["ipv4"],
        host_identity=observation["hostIdentity"],
        pinned_host_key_sha256=ssh_key_sha256,
    )
    return OwnedDroplet(endpoint.allocation, observed)


def _record_failure(attempt: Attempt, started: tuple[str, int], error: Exception) -> None:
    category = "transport" if isinstance(error, ConnectionError) else "authority"
    try:
        attempt.append(
            "preparation",
            "ssh",
            started,
            status=1,
            incident=failure("primary", category, "ssh", error),
        )
    except Exception:
        print("M3.12 SSH preparation failure could not be persisted.", file=sys.stderr)


def prepare(
    attempt: Attempt, source: Endpoint, restore: Endpoint, production_exclusions: bytes
) -> dict[str, tuple[Document, Document]]:
    """Pin both endpoints before connecting. Read back the original preparation on retry."""
    with attempt.lock("controller.lock", blocking=False):
        started = clock()
        attempt.append("preparation", "ssh", started)
        try:
            result = _prepare(attempt, source, restore, production_exclusions)
        except Exception as error:
            _record_failure(attempt, started, error)
            raise
        attempt.append("preparation", "ssh", started, status=0)
        return result


def _prepare(
    attempt: Attempt, source: Endpoint, restore: Endpoint, production_exclusions: bytes
) -> dict[str, tuple[Document, Document]]:
    run_id = attempt.directory.parent.name
    require(
        source.allocation.run_id == restore.allocation.run_id == run_id
        and source.allocation.role == "source"
        and restore.allocation.role == "restore"
        and source.provider.droplet_id != restore.provider.droplet_id
        and source.provider.ipv4 != restore.provider.ipv4
        and source.allocation.transaction_namespace_sha256
        != restore.allocation.transaction_namespace_sha256,
        "droplet-preparation-role-conflict",
    )
    production = decode(production_exclusions, "droplet-production-exclusions")
    prepared: Document = {
        "format": "lowerduckpond-m3-12-disposable-preparation-v1",
        "runId": run_id,
        "invocationId": attempt.directory.name,
        "productionExclusionsSha256": digest(production),
        "source": _scope(source, production),
        "restore": _scope(restore, production),
    }
    require(
        prepared["source"]["sshKeySha256"] != prepared["restore"]["sshKeySha256"],
        "droplet-preparation-role-conflict",
    )
    _seal(attempt.directory, "droplet-preparation.json", prepared)
    source_host, _ = _observe_role(attempt, "source", source, prepared)
    restore_host, restore_doc = _observe_role(attempt, "restore", restore, prepared)
    require(restore_doc["state"] in COLD_STATE, "droplet-restore-target-is-not-cold")
    pair = prepare_source_and_restore(source_host, restore_host, production_exclusions)
    _seal(
        attempt.directory,
        "droplet-preparation-result.json",
        {
            "format": "lowerduckpond-m3-12-disposable-preparation-result-v1",
            "preparationSha256": digest(prepared),
            **{
                role: {"target": target, "enrollment": enrollment}
                for role, (target, enrollment) in pair.items()
            },
        },
    )
    return pair


def prepare_fresh(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes, *, artifact_sha256: str
) -> tuple[Document, Document]:
    """Seal an independent fresh-install role before any candidate setup."""
    with attempt.lock("controller.lock", blocking=False):
        started = clock()
        attempt.append("preparation", "ssh", started)
        try:
            result = _prepare_fresh(attempt, endpoint, production_exclusions, artifact_sha256)
        except Exception as error:
            _record_failure(attempt, started, error)
            raise
        attempt.append("preparation", "ssh", started, status=0)
        return result


def _prepare_fresh(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes, artifact_sha256: str
) -> tuple[Document, Document]:
    run_id = attempt.directory.parent.name
    require(
        endpoint.allocation.run_id == run_id and endpoint.allocation.role == "fresh",
        "droplet-preparation-role-conflict",
    )
    require(
        re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is not None,
        "droplet-fresh-candidate-invalid",
    )
    production = decode(production_exclusions, "droplet-production-exclusions")
    prepared = {
        "format": "lowerduckpond-m3-12-disposable-preparation-v1",
        "runId": run_id,
        "invocationId": attempt.directory.name,
        "productionExclusionsSha256": digest(production),
        "fresh": _scope(endpoint, production),
        "expectedArtifactSha256": artifact_sha256,
    }
    _seal(attempt.directory, "droplet-preparation.json", prepared)
    host, observed = _observe_role(attempt, "fresh", endpoint, prepared)
    require(observed["state"] == COLD_STATE[0], "droplet-fresh-target-is-not-pristine")
    target, enrollment = enrollment_records(
        host.allocation, host.observation, production_exclusions
    )
    _seal(
        attempt.directory,
        "droplet-preparation-result.json",
        {
            "format": "lowerduckpond-m3-12-disposable-preparation-result-v1",
            "preparationSha256": digest(prepared),
            "fresh": {"target": target, "enrollment": enrollment},
        },
    )
    return target, enrollment


def _retained_role(
    attempt: Attempt, role: str, endpoint: Endpoint, production_exclusions: bytes
) -> tuple[Document, Document, Document, Document]:
    production = decode(production_exclusions, "droplet-production-exclusions")
    prepared = read(attempt.directory, "droplet-preparation.json")
    original_scope = digest(prepared)
    completed = read(attempt.directory, "droplet-preparation-result.json")
    require(
        prepared["runId"] == attempt.directory.parent.name
        and prepared["invocationId"] == attempt.directory.name
        and prepared["productionExclusionsSha256"] == digest(production)
        and completed["preparationSha256"] == original_scope
        and prepared.get(role) == _scope(endpoint, production)
        and role in completed
        and endpoint.allocation.run_id == prepared["runId"]
        and endpoint.allocation.role == role,
        "droplet-inspection-scope-changed",
    )
    original = read(attempt.directory, f"droplet-{role}-observation.json")
    require(
        original["role"] == role and original["preparationSha256"] == original_scope,
        "droplet-inspection-observation-changed",
    )
    before = decode(encode(original["observation"]), "droplet-observation")
    host = _owned(endpoint, prepared[role]["sshKeySha256"], before)
    target, enrollment = enrollment_records(
        host.allocation, host.observation, production_exclusions
    )
    require(
        completed[role] == {"target": target, "enrollment": enrollment},
        "droplet-inspection-enrollment-changed",
    )
    return prepared, completed, original, before


def _observe_same_host(endpoint: Endpoint, before: Document) -> Document:
    after = observe(endpoint)
    require(
        before["metadata"] == after["metadata"] and before["hostIdentity"] == after["hostIdentity"],
        "droplet-inspection-host-changed",
    )
    return after


def source_launch_provenance(
    directory: Path, inputs: RestoreInputs, source_target: Document, *, owner: int
) -> Document | None:
    """Bind original launch bytes from reviewed custody to the enrolled source."""
    launch = inputs.document["launch"]
    if launch is None:
        return None
    with DurableDirectory.open(
        directory, expected_owner=owner, expected_directory_mode=0o700
    ) as protected:
        admission_raw, intent_raw, receipt_raw = (
            protected.read_regular(
                (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
            )
            for name in (
                "source-admission.json",
                "source-launch-intent.json",
                "source-launch-receipt.json",
            )
        )
    receipt = validate_launch(admission_raw, intent_raw, encode(launch), receipt_raw)
    admission = decode(admission_raw, "admission")
    require(
        source_target["targetKind"] == DISPOSABLE
        and admission["target"] == source_target
        and admission["candidate"]["hostAgentSha256"] == inputs.document["originalArtifactSha256"]
        and admission["platform"]["namespaceSha256"] == digest(inputs.document["namespace"]),
        "droplet-restore-source-launch-changed",
    )
    return {
        "admissionSha256": receipt["admissionSha256"],
        "intentSha256": receipt["intentSha256"],
        "launchRecordSha256": receipt["launchRecordSha256"],
        "launchReceiptSha256": digest(receipt),
    }


def prepare_cold_restore(
    attempt: Attempt,
    source: Endpoint,
    restore: Endpoint,
    production_exclusions: bytes,
    *,
    inputs_directory: Path,
) -> Document:
    """Bind the original recovery policy to the pinned pair before destination setup.

    Inputs come from separately reviewed custody. This uses the native restore
    preflight, which does not prove repository contents, live firewall state,
    snapshot materialization, archive versions or ingress verification.
    """
    with attempt.lock("controller.lock", blocking=False):
        _, completed, _, source_before = _retained_role(
            attempt, "source", source, production_exclusions
        )
        _, _, _, restore_before = _retained_role(attempt, "restore", restore, production_exclusions)
        owner = os.geteuid()
        inputs = RestoreInputs.load(inputs_directory, owner=owner)
        require(
            sha256(cast(str, inputs.document["sourceMachineId"]).encode("ascii")).hexdigest()
            == source_before["hostIdentity"]["machineSha256"]
            and sha256(
                cast(str, inputs.document["destinationMachineId"]).encode("ascii")
            ).hexdigest()
            == restore_before["hostIdentity"]["machineSha256"],
            "droplet-restore-policy-host-changed",
        )
        original_ca_count = verify_bootstrap_inputs(inputs_directory, inputs, owner=owner)
        source_target = completed["source"]["target"]
        destination_target = completed["restore"]["target"]
        launch = source_launch_provenance(inputs_directory, inputs, source_target, owner=owner)
        scope = {
            "format": DROPLET_SCOPE_FORMAT,
            "runId": attempt.directory.parent.name,
            "sourceTargetSha256": digest(source_target),
            "destinationTargetSha256": digest(destination_target),
            "sourceLaunchReceiptSha256": None if launch is None else launch["launchReceiptSha256"],
        }
        require(inputs.droplet_scope in (None, scope), "droplet-restore-policy-scope-changed")
        scoped = RestoreInputs.from_bytes(encode({**inputs.document, DROPLET_BINDING: scope}))
        plan = {
            "format": "lowerduckpond-m3-12-cold-restore-inputs-v1",
            "preparationSha256": digest(completed),
            "restoreId": inputs.restore_id,
            "snapshotId": inputs.snapshot_id,
            "trustedInputs": scoped.digest,
            "activationScope": scoped.droplet_scope_digest,
            "sourceFence": inputs.document["sourceFenceDigest"],
            "originalCaCount": original_ca_count,
            "sourceTargetSha256": digest(source_target),
            "destinationTargetSha256": digest(destination_target),
            "sourceLaunch": launch,
        }
        _seal(attempt.directory, "droplet-cold-restore-inputs.json", plan)
        observed = _observe_same_host(restore, restore_before)
        require(observed["state"] in COLD_STATE, "droplet-restore-target-is-not-cold")
        observed_sha = digest(observed)
        _seal(
            attempt.directory,
            f"droplet-cold-restore-readback-{observed_sha}.json",
            {
                "format": "lowerduckpond-m3-12-cold-restore-readback-v1",
                "inputsSha256": digest(plan),
                "observationSha256": observed_sha,
                "bootSha256": observed["bootSha256"],
                "publication": observed["state"]["publication"],
            },
        )
        _seal(attempt.directory, "droplet-restore-target.json", scoped.document)
        return plan


def stage_restore_delivery(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes, *, inputs_directory: Path
) -> Path:
    """Build the fixed private native bootstrap directory from the sealed restore plan."""
    with attempt.lock("controller.lock", blocking=False):
        _, completed, _, original = _retained_role(
            attempt, "restore", endpoint, production_exclusions
        )
        plan = read(attempt.directory, "droplet-cold-restore-inputs.json")
        scoped = RestoreInputs.from_bytes(
            encode(read(attempt.directory, "droplet-restore-target.json"))
        )
        owner = os.geteuid()
        original_inputs = RestoreInputs.load(inputs_directory, owner=owner)
        ca_count = verify_bootstrap_inputs(inputs_directory, original_inputs, owner=owner)
        require(
            ca_count == plan["originalCaCount"]
            and scoped.digest == plan["trustedInputs"]
            and digest(completed) == plan["preparationSha256"]
            and {**original_inputs.document, DROPLET_BINDING: scoped.droplet_scope}
            == scoped.document
            and original_inputs.droplet_scope in (None, scoped.droplet_scope),
            "droplet-restore-delivery-inputs-changed",
        )
        after = _observe_same_host(endpoint, original)
        require(after["state"] in COLD_STATE, "droplet-restore-target-is-not-cold")
        site = attempt.directory / "restore-delivery"
        private_directory(site, owner=owner)
        bound = completed["restore"]
        files = {
            "target.json": encode(scoped.document),
            TARGET: encode(bound["target"]),
            ENROLLMENT: encode(bound["enrollment"]),
            EXCLUSIONS: production_exclusions,
        }
        with DurableDirectory.open(
            inputs_directory, expected_owner=owner, expected_directory_mode=0o700
        ) as source:
            names = {
                f"source-fence-{scoped.restore_id}.json": f"source-fence-{scoped.restore_id}.json"
            }
            names.update(
                {
                    f"original-origin-pull-ca-{i}.pem": f"original-origin-pull-ca-{i}.pem"
                    for i in range(ca_count)
                }
            )
            if scoped.document["launch"] is not None:
                names.update({f"source-{name}": name for name in LAUNCH_FILES})
            for original_name, destination_name in names.items():
                files[destination_name] = source.read_regular(
                    (original_name,),
                    expected_owner=owner,
                    expected_mode=0o600,
                    maximum_bytes=MAX_RECORD_BYTES,
                )
        _retain_files(site, files, owner=owner)
        verify_bootstrap_inputs(site, scoped, owner=owner)
        published = publication_files(site, scoped, owner=owner)
        _seal(
            attempt.directory,
            "droplet-restore-delivery.json",
            {
                "format": "lowerduckpond-m3-12-restore-delivery-v1",
                "restoreId": scoped.restore_id,
                "trustedInputsDigest": scoped.digest,
                "activationScopeDigest": scoped.droplet_scope_digest,
                "publicationFiles": published,
            },
        )
        return site


def _retain_files(site: Path, files: dict[str, bytes], *, owner: int) -> None:
    with DurableDirectory.open(
        site, expected_owner=owner, expected_directory_mode=0o700
    ) as destination:
        for name, raw in files.items():
            try:
                destination.create_immutable((name,), raw)
            except StateAlreadyExistsError:
                previous = destination.read_regular(
                    (name,),
                    expected_owner=owner,
                    expected_mode=0o600,
                    maximum_bytes=MAX_RECORD_BYTES,
                )
                require(previous == raw, "droplet-restore-delivery-original-changed")


def prepare_install_handoff(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes
) -> Path:
    """Seal the pinned Ansible inventory and fixed dark vars for one owned role."""
    role = endpoint.allocation.role
    require(role in {"fresh", "restore"}, "droplet-install-role-invalid")
    with attempt.lock("controller.lock", blocking=False):
        prepared, _, _, before = _retained_role(attempt, role, endpoint, production_exclusions)
        owner = os.geteuid()
        stage: Document = {
            "caddy_generation_enabled": True,
            "backup_static_recovery_enabled": True,
            "backup_audit_rotation_enabled": False,
            "static_publication_enabled": False,
            "host_recovery_bootstrap_enabled": role == "restore",
        }
        if role == "restore":
            delivery_directory = attempt.directory / "restore-delivery"
            scoped = RestoreInputs.load(delivery_directory, owner=owner)
            delivery = read(attempt.directory, "droplet-restore-delivery.json")
            require(
                delivery["trustedInputsDigest"] == scoped.digest
                and delivery["activationScopeDigest"] == scoped.droplet_scope_digest
                and delivery["publicationFiles"]
                == publication_files(delivery_directory, scoped, owner=owner),
                "droplet-restore-install-delivery-changed",
            )
            verify_bootstrap_inputs(delivery_directory, scoped, owner=owner)
            stage.update(
                host_recovery_restore_id=scoped.restore_id,
                host_recovery_input_directory=str(delivery_directory),
                static_host_agent_artifact_sha256=scoped.document["originalArtifactSha256"],
            )
        else:
            stage["static_host_agent_artifact_sha256"] = prepared["expectedArtifactSha256"]
        after = _observe_same_host(endpoint, before)
        require(
            after["state"] in (COLD_STATE if role == "restore" else COLD_STATE[:1]),
            "droplet-install-target-is-not-cold",
        )
        site = attempt.directory / f"install-{role}"
        private_directory(site, owner=owner)
        key, _ = endpoint.validate()
        inventory = installation_inventory(endpoint, site / "known_hosts")
        _retain_files(
            site,
            {
                "inventory.json": encode(inventory),
                "stage.json": encode(stage),
                "known_hosts": endpoint.provider.ipv4.encode("ascii") + b" " + key + b"\n",
            },
            owner=owner,
        )
        return site


def inspect_restored_host(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes
) -> Document:
    """Join native status and delivered authority on the same pinned bootstrap."""
    with attempt.lock("controller.lock", blocking=False):
        _, _, _, original = _retained_role(attempt, "restore", endpoint, production_exclusions)
        staged = read(attempt.directory, "droplet-restore-delivery.json")
        approved = read(attempt.directory, "droplet-restore-target.json")
        first = _observe_same_host(endpoint, original)
        delivered = restore_delivery(endpoint)
        require(
            delivered == {name: value for name, value in staged.items() if name != "format"},
            "droplet-restore-installed-delivery-changed",
        )
        status = restore_status(endpoint)
        if status != {"phase": "not-started"}:
            require(
                set(status) == {"restoreId", "snapshotId", "phase", "activationPending"}
                and status["restoreId"] == approved["restoreId"]
                and status["snapshotId"] == approved["snapshotId"]
                and type(status["phase"]) is str
                and status["phase"] in set(RestorePhase)
                and type(status["activationPending"]) is bool
                and (status["phase"] == RestorePhase.COMPLETE or status["activationPending"]),
                "droplet-restore-installed-status-changed",
            )
        last = _observe_same_host(endpoint, original)
        require(
            first == last and last["state"]["artifactSha256"] == approved["originalArtifactSha256"],
            "droplet-restore-installed-observation-changed",
        )
        if status.get("phase") == RestorePhase.COMPLETE and status["activationPending"] is False:
            require(
                last["state"]["publication"]
                == ("enabled" if approved["publicationEnabled"] else "dark")
                and last["state"]["launchPresent"] == (approved["launch"] is not None),
                "droplet-restore-installed-publication-changed",
            )
        result = {
            "format": "lowerduckpond-m3-12-restore-status-observation-v1",
            "deliverySha256": digest(staged),
            "bootSha256": last["bootSha256"],
            "guestObservationSha256": digest(last),
            "restoreStatus": status,
        }
        _seal(attempt.directory, f"droplet-restore-status-{digest(result)}.json", result)
        return result


def inspect_fresh_dark(
    attempt: Attempt, endpoint: Endpoint, production_exclusions: bytes
) -> Document:
    """Record boot-specific dark selection of the artifact pinned before installation."""
    with attempt.lock("controller.lock", blocking=False):
        prepared, _, original, before = _retained_role(
            attempt, "fresh", endpoint, production_exclusions
        )
        after = _observe_same_host(endpoint, before)
        expected = prepared["expectedArtifactSha256"]
        require(
            after["state"]
            == {
                "artifactSha256": expected,
                "launchPresent": False,
                "publication": "dark",
            },
            "droplet-fresh-dark-state-changed",
        )
        result = {
            "format": "lowerduckpond-m3-12-fresh-dark-observation-v1",
            "preparationSha256": digest(prepared),
            "originalObservationSha256": digest(original),
            "artifactSha256": expected,
            "bootSha256": after["bootSha256"],
        }
        _seal(attempt.directory, f"droplet-fresh-dark-{after['bootSha256']}.json", result)
        return result


def inspect_boot(
    attempt: Attempt, role: str, endpoint: Endpoint, production_exclusions: bytes
) -> Document:
    """Observe boot continuity for the exact enrolled host without causing a reboot."""
    require(role in {"source", "restore", "fresh"}, "droplet-inspection-role-invalid")
    with attempt.lock("controller.lock", blocking=False):
        prepared, _, original, before = _retained_role(
            attempt, role, endpoint, production_exclusions
        )
        after = _observe_same_host(endpoint, before)
        result = {
            "format": "lowerduckpond-m3-12-boot-observation-v1",
            "preparationSha256": digest(prepared),
            "role": role,
            "originalObservationSha256": digest(original),
            "originalBootSha256": before["bootSha256"],
            "observedBootSha256": after["bootSha256"],
            "bootChanged": after["bootSha256"] != before["bootSha256"],
        }
        _seal(attempt.directory, f"droplet-{role}-boot-{after['bootSha256']}.json", result)
        return result
