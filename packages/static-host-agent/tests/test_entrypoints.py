from __future__ import annotations

import grp
import pwd
import ssl
import subprocess
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent import entrypoints
from lowerduckpond_static_host_agent.caddy_runtime import (
    CADDY_PUBLICATION_LOCK_MODE,
    CADDY_RUNTIME_ROOT_MODE,
)
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartIntent,
    CaddyStartMode,
    CaddyStartPhase,
    start_target,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath

_DISABLED_STATUS = 78
_USAGE_STATUS = 64


def test_disabled_operator_checks_the_gate_before_opening_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    gate = tmp_path / "publication-gate"
    gate.write_text(
        "#!/bin/sh\nprintf 'publication_disabled\\n' >&2\nexit 78\n",
        encoding="utf-8",
    )
    gate.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PUBLICATION_GATE", gate)
    monkeypatch.setattr(entrypoints, "_STATE_ROOT", tmp_path / "absent-state")

    status = entrypoints.operator_main(["--principal", "operator@example.test"])

    assert status == _DISABLED_STATUS
    assert capfd.readouterr().err == "publication_disabled\n"


def test_caddy_bootstrap_and_launcher_reject_unfixed_invocations(
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert entrypoints.caddy_launcher_main(["unexpected"]) == _USAGE_STATUS
    assert entrypoints.caddy_bootstrap_main(["relative", "bad"]) == _USAGE_STATUS
    assert entrypoints.caddy_start_gate_main(["unexpected"]) == 1
    assert entrypoints.caddy_start_verifier_main(["unexpected"]) == 1
    assert entrypoints.caddy_start_recovery_main(["unexpected"]) == 1

    assert capfd.readouterr().err == (
        "invalid_caddy_launcher_invocation\n"
        "invalid_caddy_bootstrap_invocation\n"
        "caddy_start_gate_failed\n"
        "caddy_start_verification_failed\n"
        "caddy_start_recovery_failed\n"
    )


def test_origin_pull_pem_conversion_returns_the_exact_der_bytes() -> None:
    expected = b"review-only-DER-certificate"
    pem = ssl.DER_cert_to_PEM_cert(expected).encode("ascii")

    assert entrypoints._pem_certificate_der(pem) == expected


def test_caddy_control_runtime_opens_the_validated_lock_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[tuple[Path, Path, dict[str, object]]] = []
    expected_runtime = object()

    class RuntimeType:
        @staticmethod
        def open(root: Path, lock: Path, **arguments: object) -> object:
            opened.append((root, lock, arguments))
            return expected_runtime

    monkeypatch.setattr(entrypoints, "CaddyRuntime", RuntimeType)
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=1001),
    )
    monkeypatch.setattr(
        grp,
        "getgrnam",
        lambda _name: SimpleNamespace(gr_gid=1002),
    )

    assert entrypoints._open_caddy_control_runtime() is expected_runtime
    assert opened == [
        (
            entrypoints._CADDY_RUNTIME_ROOT,
            entrypoints._PUBLICATION_LOCK,
            {
                "expected_owner": 0,
                "expected_group": 1002,
                "validation_uid": 1001,
                "validation_gid": 1002,
                "expected_binary_sha256": None,
                "expected_lock_owner": 0,
                "expected_lock_group": 0,
                "root_mode": CADDY_RUNTIME_ROOT_MODE,
                "lock_mode": CADDY_PUBLICATION_LOCK_MODE,
            },
        )
    ]


def test_selected_tenant_runtime_binds_the_active_verified_snapshot(  # noqa: PLR0915
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
    generation_id = "0198d17f-6f4a-7000-8000-000000000001"
    deployment_id = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
    release_tree_digest = {
        "format": "lowerduckpond-release-tree-v1",
        "algorithm": "sha256",
        "value": "c" * 64,
    }
    deployment = {
        "id": deployment_id,
        "releaseTreeDigest": release_tree_digest,
    }
    active = SimpleNamespace(
        manifest={
            "metadata": {"id": tenant_id},
            "spec": {
                "desiredState": "active",
                "desiredDeployment": {"id": deployment_id},
            },
        },
        observed_state={
            "observedState": "active",
            "runtimeGenerationId": generation_id,
        },
        deployment=deployment,
    )
    suspended = SimpleNamespace(
        manifest={
            "metadata": {"id": tenant_id},
            "spec": {
                "desiredState": "suspended",
                "desiredDeployment": {"id": deployment_id},
            },
        },
        observed_state={
            "observedState": "suspended",
            "runtimeGenerationId": None,
        },
        deployment=deployment,
    )
    retained_deployments = {deployment_id: deployment}

    class Runtime:
        tenant = active
        active_generation_id = generation_id

        def __enter__(self) -> Runtime:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def using_held_publication_lock(self, _repository: object) -> nullcontext[None]:
            return nullcontext()

        def read_active(self) -> str:
            return self.active_generation_id

        def read_generation_route_snapshot(self, requested: str) -> SimpleNamespace:
            assert requested == self.active_generation_id
            return SimpleNamespace(platform_namespace={}, tenants=(self.tenant,))

    class Transaction:
        @staticmethod
        def read(path: StateRecordPath) -> SimpleNamespace:
            assert path.tenant_id == tenant_id
            assert path.deployment_id is not None
            return SimpleNamespace(document=retained_deployments[path.deployment_id])

        @staticmethod
        def tenant_deployment_ids(requested: object) -> tuple[str, ...]:
            assert requested == tenant_id
            return tuple(sorted(retained_deployments))

    class Repository:
        @staticmethod
        def publication_transaction(*, blocking: bool) -> nullcontext[object]:
            assert blocking is True
            return nullcontext(Transaction())

    runtime = Runtime()
    repository = Repository()
    authoritative = [active]
    monkeypatch.setattr(entrypoints, "_open_caddy_control_runtime", lambda: runtime)
    monkeypatch.setattr(
        entrypoints,
        "_tenant_release_ids",
        lambda _tenant_id: (deployment_id,),
    )
    measured_digests = {deployment_id: release_tree_digest}
    monkeypatch.setattr(
        entrypoints,
        "measure_release_tree",
        lambda root, **_kwargs: SimpleNamespace(
            digest=SimpleNamespace(to_dict=lambda: measured_digests[root.name])
        ),
    )
    monkeypatch.setattr(
        entrypoints,
        "snapshot_tenant_routes",
        lambda _transaction: SimpleNamespace(
            platform_namespace={},
            tenants=tuple(authoritative),
        ),
    )

    assert entrypoints._selected_tenant_runtime_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        "both",
        generation_id,
        active.manifest,
        active.observed_state,
    )
    assert entrypoints._selected_tenant_release_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        active.manifest,
    )
    assert entrypoints._all_tenant_release_state_matches(
        repository,  # type: ignore[arg-type]
    )
    assert entrypoints._all_tenant_runtime_state_matches(
        repository,  # type: ignore[arg-type]
    )
    assert not entrypoints._selected_tenant_runtime_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        "both",
        "0198d17f-6f4a-7000-8000-000000000002",
        active.manifest,
        active.observed_state,
    )
    runtime.active_generation_id = "0198d17f-6f4a-7000-8000-000000000002"
    assert entrypoints._selected_tenant_runtime_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        "both",
        None,
        active.manifest,
        active.observed_state,
    )
    runtime.active_generation_id = generation_id
    runtime.tenant = suspended
    assert not entrypoints._all_tenant_runtime_state_matches(
        repository,  # type: ignore[arg-type]
    )
    runtime.tenant = active
    measured_digests[deployment_id] = {**release_tree_digest, "value": "d" * 64}
    assert not entrypoints._selected_tenant_release_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        active.manifest,
    )
    assert not entrypoints._all_tenant_release_state_matches(
        repository,  # type: ignore[arg-type]
    )
    measured_digests[deployment_id] = release_tree_digest
    monkeypatch.setattr(
        entrypoints,
        "_tenant_release_ids",
        lambda _tenant_id: (
            deployment_id,
            "0198d17f-6f4a-7000-8000-000000000009",
        ),
    )
    assert not entrypoints._selected_tenant_release_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        active.manifest,
    )
    monkeypatch.setattr(
        entrypoints,
        "_tenant_release_ids",
        lambda _tenant_id: (deployment_id,),
    )
    predecessor_id = "0198d17f-6f4a-7000-8000-000000000009"
    predecessor = {"id": predecessor_id, "releaseTreeDigest": release_tree_digest}
    retained_deployments[predecessor_id] = predecessor
    measured_digests[predecessor_id] = release_tree_digest
    assert not entrypoints._selected_tenant_release_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        active.manifest,
    )
    monkeypatch.setattr(
        entrypoints,
        "_tenant_release_ids",
        lambda _tenant_id: tuple(sorted(retained_deployments)),
    )
    assert entrypoints._selected_tenant_release_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        active.manifest,
    )
    measured_digests[predecessor_id] = {**release_tree_digest, "value": "e" * 64}
    assert not entrypoints._selected_tenant_release_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        active.manifest,
    )
    measured_digests[predecessor_id] = release_tree_digest
    runtime.tenant = suspended
    authoritative[:] = [suspended]
    assert entrypoints._selected_tenant_runtime_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        "absent",
        generation_id,
        suspended.manifest,
        suspended.observed_state,
    )
    assert not entrypoints._selected_tenant_runtime_matches(
        repository,  # type: ignore[arg-type]
        tenant_id,
        "both",
        generation_id,
        suspended.manifest,
        suspended.observed_state,
    )
    assert not entrypoints._selected_tenant_routes_absent(
        repository,  # type: ignore[arg-type]
        tenant_id,
    )
    runtime.tenant = SimpleNamespace(
        manifest={
            "metadata": {"id": "0191e2c4-8f7a-7c3b-8d1e-5f62047a2101"},
            "spec": {"desiredState": "active"},
        },
        observed_state={
            "observedState": "active",
            "runtimeGenerationId": generation_id,
        },
    )
    authoritative[:] = [runtime.tenant]
    assert entrypoints._selected_tenant_routes_absent(
        repository,  # type: ignore[arg-type]
        tenant_id,
    )
    authoritative.append(active)
    assert not entrypoints._selected_tenant_routes_absent(
        repository,  # type: ignore[arg-type]
        tenant_id,
    )


def test_all_tenant_release_validation_remeasures_untouched_tenants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = SimpleNamespace(name="selected")
    untouched = SimpleNamespace(name="untouched")
    measured: list[str] = []

    class Repository:
        @staticmethod
        def publication_transaction(*, blocking: bool) -> nullcontext[object]:
            assert blocking is True
            return nullcontext(object())

    def release_matches(
        _repository: object,
        _transaction: object,
        tenant: SimpleNamespace,
    ) -> bool:
        measured.append(tenant.name)
        return tenant is not untouched

    monkeypatch.setattr(
        entrypoints,
        "snapshot_tenant_routes",
        lambda _transaction: SimpleNamespace(tenants=(selected, untouched)),
    )
    monkeypatch.setattr(entrypoints, "_tenant_release_state_matches", release_matches)

    assert not entrypoints._all_tenant_release_state_matches(
        Repository(),  # type: ignore[arg-type]
    )
    assert measured == ["selected", "untouched"]


def test_deleted_tenant_publication_requires_the_complete_namespace_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = "0198d17f-6f4a-7000-8000-000000000001"
    sites = tmp_path / "sites"
    sites.mkdir()
    transactions: list[bool] = []

    class Repository:
        @staticmethod
        def publication_transaction(*, blocking: bool) -> nullcontext[None]:
            transactions.append(blocking)
            return nullcontext()

    repository = Repository()
    tenant_root = sites / tenant_id
    monkeypatch.setattr(entrypoints, "TENANT_RELEASE_ROOT", str(sites))

    assert entrypoints._deleted_tenant_publication_absent(
        repository,  # type: ignore[arg-type]
        tenant_id,
    )
    tenant_root.mkdir()
    assert not entrypoints._deleted_tenant_publication_absent(
        repository,  # type: ignore[arg-type]
        tenant_id,
    )
    tenant_root.rmdir()
    tenant_root.symlink_to(tmp_path / "missing-target", target_is_directory=True)
    assert not entrypoints._deleted_tenant_publication_absent(
        repository,  # type: ignore[arg-type]
        tenant_id,
    )
    assert transactions == [True, True, True]


def test_caddy_pre_start_gate_uses_the_control_lock_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation_id = "0198d17f-6f4a-7000-8000-000000000001"
    invocation_id = "a" * 32
    prepared: list[tuple[object, str]] = []

    class Manifest:
        @staticmethod
        def to_bytes() -> bytes:
            return b"manifest"

    class Generation:
        manifest = Manifest()

        def __enter__(self) -> Generation:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

    class Runtime:
        def __enter__(self) -> Runtime:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def locked(self) -> nullcontext[None]:
            return nullcontext()

        @staticmethod
        def open_active_verified() -> SimpleNamespace:
            return SimpleNamespace(generation_id=generation_id, generation=Generation())

    class Startup:
        def __enter__(self) -> Startup:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        @staticmethod
        def reconcile_temporaries() -> int:
            return 0

        @staticmethod
        def prepare_start(*, active: object, invocation_id: str) -> None:
            prepared.append((active, invocation_id))

    class StartupType:
        @staticmethod
        def open(_path: Path, *, expected_owner: int) -> Startup:
            assert expected_owner == 0
            return Startup()

    monkeypatch.setattr(entrypoints, "_open_caddy_control_runtime", Runtime)
    monkeypatch.setattr(entrypoints, "CaddyStartupStore", StartupType)
    monkeypatch.setattr(entrypoints, "_systemd_invocation_id", lambda: invocation_id)
    monkeypatch.setattr(
        entrypoints,
        "_open_systemd_caddy_runtime",
        lambda: pytest.fail("ExecStartPre must not require systemd's OpenFile descriptor"),
    )

    assert entrypoints.caddy_start_gate_main([]) == 0
    assert prepared == [(start_target(generation_id, b"manifest"), invocation_id)]


def test_caddy_post_start_verifier_uses_the_control_lock_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation_id = "0198d17f-6f4a-7000-8000-000000000001"
    invocation_id = "b" * 32
    intent = object()
    events: list[object] = []

    class Manifest:
        @staticmethod
        def to_bytes() -> bytes:
            return b"manifest"

    class Generation:
        manifest = Manifest()

        def __enter__(self) -> Generation:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

    generation = Generation()

    class Runtime:
        def __enter__(self) -> Runtime:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def locked(self) -> nullcontext[None]:
            return nullcontext()

        @staticmethod
        def open_active_verified() -> SimpleNamespace:
            return SimpleNamespace(generation_id=generation_id, generation=generation)

    class Startup:
        def __enter__(self) -> Startup:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        @staticmethod
        def reconcile_temporaries() -> int:
            return 0

        @staticmethod
        def require_matching_success(*, active: object, invocation_id: str) -> object:
            events.append((active, invocation_id))
            return intent

        @staticmethod
        def commit_success(committed: object) -> None:
            events.append(committed)

    class StartupType:
        @staticmethod
        def open(_path: Path, *, expected_owner: int) -> Startup:
            assert expected_owner == 0
            return Startup()

    monkeypatch.setattr(entrypoints, "_open_caddy_control_runtime", Runtime)
    monkeypatch.setattr(entrypoints, "CaddyStartupStore", StartupType)
    monkeypatch.setattr(entrypoints, "_systemd_invocation_id", lambda: invocation_id)
    monkeypatch.setattr(entrypoints, "verify_running_caddy", events.append)
    monkeypatch.setattr(
        entrypoints,
        "_open_systemd_caddy_runtime",
        lambda: pytest.fail("ExecStartPost must not require systemd's OpenFile descriptor"),
    )

    assert entrypoints.caddy_start_verifier_main([]) == 0
    assert events == [
        (start_target(generation_id, b"manifest"), invocation_id),
        generation,
        intent,
    ]


def test_caddy_recovery_selects_and_commits_before_queuing_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    candidate = start_target("0198d17f-6f4a-7000-8000-000000000001", b"candidate")
    previous = start_target("0198d17f-6f4a-7000-8000-000000000002", b"previous")
    invocations = tuple(f"{value:032x}" for value in range(3))
    intent = CaddyStartIntent(
        mode=CaddyStartMode.TRANSACTIONAL,
        phase=CaddyStartPhase.CANDIDATE_STARTING,
        candidate=candidate,
        previous=previous,
        candidate_invocations=invocations,
        invocation_id=invocations[-1],
    )

    class Runtime:
        def __enter__(self) -> Runtime:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def locked(self) -> nullcontext[None]:
            return nullcontext()

        def select_active(self, generation_id: str) -> None:
            assert generation_id == previous.generation_id
            order.append("select")

    class Startup:
        def __enter__(self) -> Startup:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def reconcile_temporaries(self) -> int:
            return 0

        def require_rollback_target(self) -> CaddyStartIntent:
            return intent

        def mark_rollback_restart_required(
            self,
            expected: CaddyStartIntent,
        ) -> CaddyStartIntent:
            assert expected == intent
            assert order == ["select"]
            order.append("commit")
            return replace(
                intent,
                phase=CaddyStartPhase.ROLLBACK_RESTART_REQUIRED,
                invocation_id=None,
            )

    class StartupType:
        @staticmethod
        def open(_path: Path, *, expected_owner: int) -> Startup:
            assert expected_owner == 0
            return Startup()

    def run(command: list[str], **_arguments: object) -> SimpleNamespace:
        order.append("reset" if "reset-failed" in command else "start")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(entrypoints, "_open_systemd_caddy_runtime", Runtime)
    monkeypatch.setattr(entrypoints, "CaddyStartupStore", StartupType)
    monkeypatch.setattr(subprocess, "run", run)

    assert entrypoints.caddy_start_recovery_main([]) == 0
    assert order == ["select", "commit", "reset", "start"]


def test_caddy_recovery_releases_an_exhausted_ordinary_retry_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleared: list[bool] = []

    class Runtime:
        def __enter__(self) -> Runtime:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def locked(self) -> nullcontext[None]:
            return nullcontext()

    class Startup:
        def __enter__(self) -> Startup:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def reconcile_temporaries(self) -> int:
            return 0

        def require_rollback_target(self) -> None:
            return None

        def clear_exhausted_ordinary_start(self) -> bool:
            cleared.append(True)
            return True

    class StartupType:
        @staticmethod
        def open(_path: Path, *, expected_owner: int) -> Startup:
            assert expected_owner == 0
            return Startup()

    monkeypatch.setattr(entrypoints, "_open_systemd_caddy_runtime", Runtime)
    monkeypatch.setattr(entrypoints, "CaddyStartupStore", StartupType)

    assert entrypoints.caddy_start_recovery_main([]) == 0
    assert cleared == [True]
