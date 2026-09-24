from __future__ import annotations

import hashlib
import os
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, manifest_digest
from lowerduckpond_static_host_agent import entrypoints
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.backup_descriptor import (
    backup_descriptor_digest,
    encode_backup_descriptor,
)
from lowerduckpond_static_host_agent.caddy_generation import (
    CaddyBinarySource,
    CaddyGenerationPayload,
    CaddyGenerationStore,
)
from lowerduckpond_static_host_agent.caddy_routes import build_tenant_caddy_routes
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore, start_target
from lowerduckpond_static_host_agent.execution import _validate_observed_state
from lowerduckpond_static_host_agent.host_restore_history import (
    import_prior_provenance,
    seal_provenance,
)
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_mapping import (
    MAPPING_NAME,
    MAX_PLAN_BYTES,
    PLAN_NAME,
    RuntimeInputs,
    RuntimeMapping,
    apply_runtime_mapping,
    commit_runtime_mapping,
    map_runtime_request,
    prepare_runtime_inputs,
    read_runtime_mapping,
    require_mapped_current_observation,
    runtime_mappings,
    translate_runtime_request,
)
from lowerduckpond_static_host_agent.host_restore_startup import (
    complete_restore_startup,
    require_restore_startup,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.route_snapshot import snapshot_tenant_routes
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - shared capture fixture
from test_backup_capture import Capture
from test_backup_capture import capture as capture  # noqa: PLC0414
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_backup_inventory import DEPLOYMENT, TENANT
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_routes import begin

OLD = "0198d17f-6f4a-7000-8000-000000000095"
NEW = "0198d17f-6f4a-7000-8000-000000000096"
OLD_CA = (b"original reviewed public CA",)
NEW_CA = (b"replacement reviewed public CA",)
ENVIRONMENT = b"CLOUDFLARE_API_TOKEN=fixture-only\n"


def setup(
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
    *,
    suspended: bool = False,
) -> tuple[RestoreJournal, RestoreInputs, dict[str, object], CaddyBinarySource]:
    # The general inventory fixture carries an extra archive record; this live
    # source has no construction/retirement and must be settled before capture.
    (capture.state.root / "tenants" / TENANT / "archives" / f"{DEPLOYMENT}.json").unlink()
    with StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository:
        desired = repository.read(StateRecordPath.tenant_desired(TENANT)).document
        observed = repository.read(StateRecordPath.tenant_observed(TENANT)).document
    if suspended:
        cast(dict[str, object], desired["spec"])["desiredState"] = "suspended"
        observed.update(
            observedState="suspended",
            runtimeGenerationId=None,
            desiredManifestDigest=manifest_digest(desired).to_dict(),
        )
    observed["desiredManifestDigest"] = manifest_digest(desired).to_dict()
    capture.state.write(f"tenants/{TENANT}/desired.json", desired)
    capture.state.write(f"tenants/{TENANT}/observed.json", observed)
    runtime = tmp_path / "coherent-runtime"
    runtime.mkdir(mode=0o750)
    (runtime / "generations").mkdir(mode=0o750)
    (runtime / "intents").mkdir(mode=0o700)
    binary_path = tmp_path / "reviewed-binary"
    binary_path.write_bytes(b"immutable test binary payload")
    binary_path.chmod(0o755)
    binary = CaddyBinarySource(binary_path, os.geteuid(), os.getegid())
    with (
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
        repository.publication_transaction() as transaction,
    ):
        source = snapshot_tenant_routes(transaction)
    old_routes = build_tenant_caddy_routes(
        platform_namespace=source.platform_namespace,
        tenants=source.tenants,
        runtime_generation_id=OLD,
        origin_pull_ca_der=OLD_CA,
        origin_pull_required=True,
    )
    with CaddyGenerationStore.open(
        runtime / "generations", expected_owner=os.geteuid(), expected_group=os.getegid()
    ) as generations:
        generations.publish(
            OLD,
            CaddyGenerationPayload(
                binary, ENVIRONMENT, old_routes.configuration, old_routes.route_metadata
            ),
        )
    capture.caddy.root = runtime
    capture.caddy.active(OLD)
    descriptor = capture.descriptor()
    configuration.update(
        restoreId=journal.restore_id,
        snapshotId=journal.snapshot_id,
        namespace=source.platform_namespace,
    )
    policy = cast(dict[str, object], configuration["caddy"])
    policy.update(
        binarySha256=hashlib.sha256(binary_path.read_bytes()).hexdigest(),
        environmentSha256=hashlib.sha256(ENVIRONMENT).hexdigest(),
        originalOriginPullCaSha256=[hashlib.sha256(value).hexdigest() for value in OLD_CA],
        originPullCaSha256=[hashlib.sha256(value).hexdigest() for value in NEW_CA],
    )
    trusted = RestoreInputs.from_bytes(canonical_json_bytes(configuration))
    journal = replace(
        journal,
        capture_id=str(descriptor["captureId"]),
        bindings={
            **journal.bindings,
            "backupDescriptor": backup_descriptor_digest(encode_backup_descriptor(descriptor)),
            "trustedInputs": trusted.digest,
            "repository": cast(dict[str, str], trusted.document["repositoryBinding"]),
            "sourceFence": cast(dict[str, str], trusted.document["sourceFenceDigest"]),
            "originalArtifact": cast(dict[str, str], descriptor["artifactDigest"]),
        },
    )
    return journal, trusted, descriptor, binary


def mapping(  # noqa: PLR0913, PLR0917 - complete runtime publication inputs
    store: RestoreStore,
    repository: StateRepository,
    trusted: RestoreInputs,
    descriptor: dict[str, object],
    binary: CaddyBinarySource,
    runtime: Path,
    *,
    generation_id: str = NEW,
    original_ca: tuple[bytes, ...] = OLD_CA,
    current_ca: tuple[bytes, ...] = NEW_CA,
) -> RuntimeMapping:
    with repository.publication_transaction() as transaction:
        source = snapshot_tenant_routes(transaction)
    inputs = prepare_runtime_inputs(
        store, source, descriptor, trusted, generation_id, original_ca, current_ca
    )
    routes = inputs.routes()
    with CaddyGenerationStore.open(
        runtime / "generations", expected_owner=os.geteuid(), expected_group=os.getegid()
    ) as generations:
        manifest = generations.publish(
            generation_id,
            CaddyGenerationPayload(
                binary, ENVIRONMENT, routes.configuration, routes.route_metadata
            ),
        )
    result = RuntimeMapping(inputs, manifest)
    commit_runtime_mapping(store, result)
    return result


def finish_mapping(store: RestoreStore) -> None:
    current = store.read()
    assert current is not None
    for phase in (RestorePhase.INSTALLED, RestorePhase.VERIFIED):
        current = store.advance(current, phase, {"testPhase": phase.value})
    inventory = seal_provenance(store)
    store.advance(current, RestorePhase.COMPLETE, {"provenanceInventory": inventory})


def test_startup_requires_new_restore_transaction_and_preserves_captured_attempts_until_tls_gate(
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
) -> None:
    journal, trusted, descriptor, binary = setup(capture, configuration, journal, tmp_path)
    original_target = CaddyBackupEvidence.from_dict(descriptor["caddy"]).selected_target
    with CaddyStartupStore.open(
        capture.caddy.root / "intents", expected_owner=os.geteuid()
    ) as startup:
        original_intent = startup.prepare_start(active=original_target, invocation_id="a" * 32)
    descriptor = capture.descriptor()
    journal = replace(
        journal,
        bindings={
            **journal.bindings,
            "backupDescriptor": backup_descriptor_digest(encode_backup_descriptor(descriptor)),
        },
    )
    startup_root = tmp_path / "new-startup"
    startup_root.mkdir(mode=0o700)
    root = capture.roots["recovery"]
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
        CaddyStartupStore.open(startup_root, expected_owner=os.geteuid()) as startup,
    ):
        begin(store, journal)
        current = store.read()
        assert current is not None
        current = store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        proof = mapping(store, repository, trusted, descriptor, binary, capture.caddy.root)
        current = store.advance(
            current, RestorePhase.RUNTIME_PREPARED, {"runtimeMapping": proof.digest}
        )
        active = start_target(NEW, proof.manifest.to_bytes())
        intent = startup.begin_host_restore(candidate=active, restore_id=journal.restore_id)
        intent = startup.mark_restart_required(intent)
        with pytest.raises(HostRestoreError, match="transaction_mismatch"):
            require_restore_startup(intent, active, "b" * 32, root=root, owner=os.geteuid())
        current = store.advance(current, RestorePhase.INSTALLED, {"installed": True})
        with pytest.raises(HostRestoreError, match="transaction_mismatch"):
            require_restore_startup(None, active, "b" * 32, root=root, owner=os.geteuid())
        with pytest.raises(HostRestoreError, match="captured_invocation"):
            require_restore_startup(intent, active, "a" * 32, root=root, owner=os.geteuid())
        require_restore_startup(intent, active, "b" * 32, root=root, owner=os.geteuid())
        intent = startup.prepare_start(active=active, invocation_id="b" * 32)
        startup.commit_success(intent)
        assert startup.read() == intent
        with pytest.raises(HostRestoreError, match="not_durable"):
            complete_restore_startup(store, startup, intent)
        current = store.advance(
            current, RestorePhase.VERIFIED, {"startup": decode_json_object(intent.to_bytes())}
        )
        digest = seal_provenance(store)
        store.advance(current, RestorePhase.COMPLETE, {"provenanceInventory": digest})
        complete_restore_startup(store, startup, intent)
        assert startup.read() is None
    assert (capture.caddy.root / "intents/start.json").read_bytes() == original_intent.to_bytes()


def test_second_restore_backs_up_prior_provenance_and_replays_oldest_runtime_through_both_mappings(  # noqa: PLR0915 - two complete independent generations
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
) -> None:
    journal, trusted, descriptor, binary = setup(capture, configuration, journal, tmp_path)
    root = capture.roots["recovery"]
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
    ):
        begin(store, journal)
        current = store.read()
        assert current is not None
        current = store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        first = mapping(store, repository, trusted, descriptor, binary, capture.caddy.root)
        with repository.publication_transaction() as transaction:
            apply_runtime_mapping(store, transaction, first)
        store.advance(current, RestorePhase.RUNTIME_PREPARED, {"runtimeMapping": first.digest})
        finish_mapping(store)
    capture.caddy.active(NEW)
    # Exercise the actual backup classifier over completed restore provenance.
    second_descriptor = capture.descriptor()
    assert second_descriptor != descriptor
    original_bytes = {path.name: path.read_bytes() for path in root.iterdir()}
    restored = tmp_path / "materialized-prior"
    root.rename(restored)
    root.mkdir(mode=0o700)
    next_restore = "0198d17f-6f4a-7000-8000-000000000081"
    next_generation = "0198d17f-6f4a-7000-8000-000000000082"
    configuration["restoreId"] = next_restore
    policy = cast(dict[str, object], configuration["caddy"])
    policy.update(
        originalOriginPullCaSha256=[hashlib.sha256(value).hexdigest() for value in NEW_CA],
        originPullCaSha256=[hashlib.sha256(value).hexdigest() for value in OLD_CA],
    )
    next_trusted = RestoreInputs.from_bytes(canonical_json_bytes(configuration))
    next_journal = replace(
        journal,
        restore_id=next_restore,
        bindings={
            **journal.bindings,
            "backupDescriptor": backup_descriptor_digest(
                encode_backup_descriptor(second_descriptor)
            ),
            "trustedInputs": next_trusted.digest,
        },
    )
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        StateRepository(
            capture.state.root, expected_owner=os.geteuid(), private_reconciliation=True
        ) as repository,
    ):
        begin(store, next_journal)
        import_prior_provenance(store, restored)
        current = store.read()
        assert current is not None
        current = store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        second = mapping(
            store,
            repository,
            next_trusted,
            second_descriptor,
            binary,
            capture.caddy.root,
            generation_id=next_generation,
            original_ca=NEW_CA,
            current_ca=OLD_CA,
        )
        with repository.publication_transaction() as transaction:
            apply_runtime_mapping(store, transaction, second)
        store.advance(current, RestorePhase.RUNTIME_PREPARED, {"runtimeMapping": second.digest})
        finish_mapping(store)
    proofs = runtime_mappings(root, owner=os.geteuid())
    assert proofs == (first, second)
    oldest = first.inputs.original.tenants[0]
    final = second.inputs.projected.tenants[0]
    assert translate_runtime_request(proofs, oldest.manifest, oldest.observed_state, OLD) == (
        next_generation,
        final.observed_state,
    )
    retained = root / "history" / journal.restore_id
    assert {path.name: path.read_bytes() for path in retained.iterdir()} == original_bytes
    with (
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
        repository.publication_transaction() as transaction,
    ):
        _validate_observed_state(
            transaction, {"tenantId": TENANT}, oldest.manifest, expected=oldest.observed_state
        )
    capture.caddy.active(next_generation)
    capture.descriptor()  # Completed ancestry remains eligible for the next backup.
    (retained / MAPPING_NAME).unlink()
    with pytest.raises(HostRestoreError, match="inventory_incomplete"):
        runtime_mappings(root, owner=os.geteuid())


@pytest.mark.parametrize("suspended", [False, True])
def test_mapping_preserves_every_field_except_active_runtime_reference_and_replays_interruption(
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
    suspended: bool,
) -> None:
    journal, trusted, descriptor, binary = setup(
        capture, configuration, journal, tmp_path, suspended=suspended
    )
    root = capture.roots["recovery"]
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
    ):
        begin(store, journal)
        current = store.read()
        assert current is not None
        current = store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        proof = mapping(store, repository, trusted, descriptor, binary, capture.caddy.root)
        with pytest.raises(HostRestoreError, match="uncommitted"):
            read_runtime_mapping(root, owner=os.geteuid())
        assert read_runtime_mapping(root, owner=os.geteuid(), private_preparation=True) == proof
        before = repository.read(StateRecordPath.tenant_observed(TENANT)).document

        def interrupt(_tenant: str) -> None:
            raise RuntimeError("observation synced")

        with repository.publication_transaction() as transaction:
            with pytest.raises(RuntimeError, match="observation synced"):
                apply_runtime_mapping(store, transaction, proof, failure_hook=interrupt)
            apply_runtime_mapping(store, transaction, proof)
        after = repository.read(StateRecordPath.tenant_observed(TENANT)).document
        assert after == (before if suspended else {**before, "runtimeGenerationId": NEW})
        assert proof.inputs.evidence.selected_target.generation_id == OLD
        assert proof.inputs.original.tenants[0].observed_state == before
        source = proof.inputs.original.tenants[0]
        assert map_runtime_request(proof, TENANT, source.manifest, before, OLD) == (NEW, after)
        require_mapped_current_observation(proof, source.manifest, after)
        unrelated = "0198d17f-6f4a-7000-8000-000000000098"
        assert map_runtime_request(proof, TENANT, source.manifest, before, unrelated) == (
            unrelated,
            after,
        )
        if not suspended:
            with pytest.raises(HostRestoreError, match="unproven"):
                require_mapped_current_observation(
                    proof, source.manifest, {**after, "reconciledAt": "2026-09-01T00:00:00Z"}
                )
        store.advance(current, RestorePhase.RUNTIME_PREPARED, {"runtimeMapping": proof.digest})
        assert read_runtime_mapping(root, owner=os.geteuid()) == proof


def test_normal_replay_translates_only_proven_runtime_and_rechecks_current_observation(
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal, trusted, descriptor, binary = setup(capture, configuration, journal, tmp_path)
    root = capture.roots["recovery"]
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
    ):
        begin(store, journal)
        current = store.read()
        assert current is not None
        current = store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        proof = mapping(store, repository, trusted, descriptor, binary, capture.caddy.root)
        original = proof.inputs.original.tenants[0]
        with repository.publication_transaction() as transaction:
            apply_runtime_mapping(store, transaction, proof)
        store.advance(current, RestorePhase.RUNTIME_PREPARED, {"runtimeMapping": proof.digest})
        runtime = SimpleNamespace(
            using_held_publication_lock=lambda _repository: nullcontext(),
            read_active=lambda: NEW,
            read_generation_route_snapshot=lambda _generation: proof.inputs.projected,
        )
        monkeypatch.setattr(
            entrypoints, "_open_caddy_control_runtime", lambda: nullcontext(runtime)
        )
        with repository.publication_transaction() as transaction:
            _validate_observed_state(
                transaction,
                {"tenantId": TENANT},
                original.manifest,
                expected=original.observed_state,
            )
        assert entrypoints._selected_tenant_runtime_matches(
            repository, TENANT, "both", OLD, original.manifest, original.observed_state
        )
        arbitrary = "0198d17f-6f4a-7000-8000-000000000091"
        assert not entrypoints._selected_tenant_runtime_matches(
            repository, TENANT, "both", arbitrary, original.manifest, original.observed_state
        )
        path = StateRecordPath.tenant_observed(TENANT)
        before = repository.read(path)
        corrupt = {**before.document, "reconciledAt": "2026-09-01T00:00:00Z"}
        repository.compare_and_swap(path, before.revision, corrupt)
        with (
            repository.publication_transaction() as transaction,
            pytest.raises(HostRestoreError, match="unproven"),
        ):
            # A caller supplying current rather than historical observations
            # must not bypass independent mapping validation.
            _validate_observed_state(
                transaction, {"tenantId": TENANT}, original.manifest, expected=corrupt
            )
        assert not entrypoints._selected_tenant_runtime_matches(
            repository, TENANT, "both", NEW, original.manifest, corrupt
        )


@pytest.mark.parametrize(
    "fault",
    [
        "new-trust",
        "old-trust",
        "old-time",
        "manifest",
        "mapping",
        "receipt",
        "arbitrary-observation",
    ],
)
def test_independent_mapping_verification_rejects_provenance_or_runtime_drift(
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
    fault: str,
) -> None:
    journal, trusted, descriptor, binary = setup(capture, configuration, journal, tmp_path)
    root = capture.roots["recovery"]
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
    ):
        begin(store, journal)
        current = store.read()
        assert current is not None
        current = store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        proof = mapping(store, repository, trusted, descriptor, binary, capture.caddy.root)
        if fault == "arbitrary-observation":
            path = StateRecordPath.tenant_observed(TENANT)
            old = repository.read(path)
            repository.compare_and_swap(
                path,
                old.revision,
                {**old.document, "runtimeGenerationId": "0198d17f-6f4a-7000-8000-000000000097"},
            )
            with (
                repository.publication_transaction() as transaction,
                pytest.raises(HostRestoreError),
            ):
                apply_runtime_mapping(store, transaction, proof)
            return
        store.advance(
            current,
            RestorePhase.RUNTIME_PREPARED,
            {
                "runtimeMapping": proof.digest
                if fault != "receipt"
                else {**proof.digest, "value": "f" * 64}
            },
        )
        if fault in {"new-trust", "old-trust", "old-time"}:
            document = decode_json_object(
                (root / PLAN_NAME).read_bytes(), maximum_bytes=MAX_PLAN_BYTES
            )
            if fault == "old-time":
                cast(
                    dict[str, object],
                    cast(list[dict[str, object]], document["tenants"])[0]["observed"],
                )["reconciledAt"] = "2026-09-01T00:00:00Z"
            else:
                document["originPullCa" if fault == "new-trust" else "originalOriginPullCa"] = [
                    "d3Jvbmc="
                ]
            (root / PLAN_NAME).write_bytes(
                canonical_json_bytes(document, maximum_bytes=MAX_PLAN_BYTES)
            )
        elif fault in {"manifest", "mapping"}:
            document = decode_json_object((root / MAPPING_NAME).read_bytes())
            if fault == "mapping":
                cast(dict[str, object], document["inputsDigest"])["value"] = "f" * 64
            else:
                manifest = cast(dict[str, object], document["targetManifest"])
                cast(list[dict[str, object]], manifest["files"])[0]["sha256"] = "f" * 64
            (root / MAPPING_NAME).write_bytes(canonical_json_bytes(document))
        with pytest.raises((HostRestoreError, ValueError)):
            read_runtime_mapping(root, owner=os.geteuid())


def test_runtime_inputs_refuse_reused_generation(
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
) -> None:
    journal, trusted, descriptor, binary = setup(capture, configuration, journal, tmp_path)
    root = capture.roots["recovery"]
    with (
        RestoreStore.locked(root, owner=os.geteuid()) as store,
        StateRepository(capture.state.root, expected_owner=os.geteuid()) as repository,
    ):
        begin(store, journal)
        current = store.read()
        assert current is not None
        store.advance(current, RestorePhase.RECONCILED, {"decisions": []})
        proof = mapping(store, repository, trusted, descriptor, binary, capture.caddy.root)
        document = decode_json_object(proof.inputs.to_bytes(), maximum_bytes=MAX_PLAN_BYTES)
        document["newGenerationId"] = OLD
        with pytest.raises(HostRestoreError, match="reused"):
            RuntimeInputs.from_bytes(canonical_json_bytes(document, maximum_bytes=MAX_PLAN_BYTES))
