"""Existing-secret rebinding, GET-only execution and shared-reader-only delivery."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import cleanup, connect_action, connect_profile
from scripts.m3_11_unattended import connect_activate as activation
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_activate import activate_controller
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_setup import prepare_controller
from scripts.m3_11_unattended.http import Api, read_only_requests
from scripts.m3_11_unattended.inventory import ConnectInventory, fact, require_confirmation
from scripts.m3_11_unattended.model import LeasePolicy, LifecycleError, digest, stamp

from .test_m3_11_cleanup_workflow import deliver, lease_bundle, select, step, workflow
from .test_m3_11_connect_action import Case
from .test_m3_11_connect_delivery import Client
from .test_m3_11_connect_setup import CANARY
from .test_m3_11_lease_configuration import document

Row = dict[str, Any]
HELPER = "a" * 40


def candidate(bundle: Row, controller: Row | None = None) -> tuple[Row, Row]:
    old, _ = connect_action.bootstrap(
        bundle, helper=str(bundle["configuration"]["helper_revision"])
    )
    updated: Row = copy.deepcopy(controller or document())
    old_document = cast(Row, old.document())
    original_roles = updated["generations"][updated["active_generation"]]
    template = copy.deepcopy(original_roles["cleanup"]["reader"])
    provision = copy.deepcopy(original_roles["provision"])
    provision["generation"]["generation_id"] = old.active_generation
    for name in (
        "targets",
        "journal_vault",
        "active_generation",
        "independent_server_id",
        "migration_sha256",
    ):
        updated[name] = old_document[name]
    updated["generations"] = {old.active_generation: {"provision": provision}}
    for key, roles in old_document["generations"].items():
        shared = copy.deepcopy(roles["cleanup"])
        shared["reader"] = template
        updated["generations"].setdefault(key, {})["cleanup"] = shared
    policy = old.policy.document()
    policy["credential_lifetime_seconds"] = 2 * 24 * 60 * 60
    policy["approval_reference"] = "SYNTHETIC-PROFILE-APPROVAL"
    updated.update(
        helper_revision=HELPER,
        policy=policy,
        approved_policy_sha256=LeasePolicy.parse(policy).sha256,
    )
    config = LeaseConfiguration.parse(updated)
    profile: Row = {
        "format": connect_profile.FORMAT,
        "base_configuration_sha256": digest(connect_profile.projection(old, identities=True)),
        "helper_revision": HELPER,
        "policy": policy,
        "approved_policy_sha256": config.approved_policy_sha256,
        "effective_configuration_sha256": digest(connect_profile.projection(config)),
    }
    return profile, updated


def test_profile_changes_only_helper_policy_and_preserves_original_secret() -> None:
    bundle = lease_bundle()
    before = copy.deepcopy(bundle)
    profile, controller = candidate(bundle)
    selected, public = connect_profile.apply(bundle, profile, helper=HELPER)
    assert bundle == before
    assert selected["server_credentials"] == before["server_credentials"]
    assert CANARY not in json.dumps(public)
    for name in ("helper_revision", "policy", "approved_policy_sha256"):
        before["configuration"][name] = controller[name]
    assert selected == before


@pytest.mark.parametrize(
    "field",
    [
        "base_configuration_sha256",
        "effective_configuration_sha256",
        "approved_policy_sha256",
        "helper_revision",
        "unknown",
    ],
)
def test_profile_mismatch_fails_closed_without_touching_original(field: str) -> None:
    bundle = lease_bundle()
    original = copy.deepcopy(bundle)
    profile, _ = candidate(bundle)
    profile[field] = "f" * (40 if field == "helper_revision" else 64)
    with pytest.raises((LifecycleError, ValueError)):
        connect_profile.apply(bundle, profile, helper=HELPER)
    assert bundle == original


@pytest.mark.parametrize(
    "field", ["helper_revision", "migration_sha256", "targets", "generation", "reader"]
)
def test_public_base_binding_covers_original_scope_generation_and_identity(field: str) -> None:
    bundle = lease_bundle()
    profile, _ = candidate(bundle)
    configured = bundle["configuration"]
    cleanup_role = configured["generations"][configured["active_generation"]]["cleanup"]
    if field == "targets":
        configured["targets"]["archive_bucket"] = "different-synthetic-bucket"
    elif field == "generation":
        cleanup_role["generation"]["rotation_due_at"] = "2099-01-01T00:00:00Z"
    elif field == "reader":
        cleanup_role["reader"]["entry"]["name"] = "different-synthetic-client"
    else:
        configured[field] = "b" * (40 if field == "helper_revision" else 64)
    with pytest.raises((LifecycleError, ValueError)):
        connect_profile.apply(bundle, profile, helper=HELPER)


def test_staging_selects_candidate_without_activating_schedule(tmp_path: Path) -> None:
    bundle = lease_bundle()
    profile, _ = candidate(bundle)
    original = bundle["configuration"]["helper_revision"]
    assert select(tmp_path, BOOTSTRAP=json.dumps(bundle))[1]["helper_revision"] == original
    result, selected = select(
        tmp_path,
        BOOTSTRAP=json.dumps(bundle),
        OPERATION="validate-profile",
        REQUESTED_PROFILE=json.dumps(profile),
    )
    assert result.returncode == 0 and selected["helper_revision"] == HELPER
    assert selected["operation"] == "validate-profile"
    assert "profile" not in selected  # Never put even a malformed supplied document in outputs.
    result, selected = select(
        tmp_path, BOOTSTRAP=json.dumps(bundle), ACTIVE_PROFILE=json.dumps(profile)
    )
    assert result.returncode == 0 and selected["helper_revision"] == HELPER


def test_profile_candidate_cannot_sneak_into_reconcile_or_legacy(tmp_path: Path) -> None:
    profile, _ = candidate(lease_bundle())
    assert select(tmp_path, REQUESTED_PROFILE=json.dumps(profile))[0].returncode != 0
    assert (
        select(tmp_path, OPERATION="validate-profile", REQUESTED_PROFILE=json.dumps(profile))[
            0
        ].returncode
        != 0
    )


def test_unmerged_candidate_is_rejected_before_checkout(tmp_path: Path) -> None:
    bundle = lease_bundle()
    profile, _ = candidate(bundle)
    result, _ = select(
        tmp_path,
        BOOTSTRAP=json.dumps(bundle),
        OPERATION="validate-profile",
        REQUESTED_PROFILE=json.dumps(profile),
        GITHUB_SHA="b" * 40,
    )
    assert result.returncode != 0


def test_actual_private_action_forwards_profile_without_exporting_secret(tmp_path: Path) -> None:
    bundle = lease_bundle()
    profile, _ = candidate(bundle)
    result, selection = select(
        tmp_path,
        BOOTSTRAP=json.dumps(bundle),
        OPERATION="validate-profile",
        REQUESTED_PROFILE=json.dumps(profile),
    )
    assert result.returncode == 0
    received = deliver(tmp_path, selection, bundle, profile=profile)
    assert received["payload"] == {
        "bootstrap": bundle,
        "operation": "validate-profile",
        "profile": profile,
    }
    assert received["bootstrap_in_environment"] is False


def test_public_proposal_cli_emits_no_private_configuration(tmp_path: Path) -> None:
    bundle = lease_bundle()
    profile, controller = candidate(bundle)
    configuration, output = tmp_path / "configuration.json", tmp_path / "profile.json"
    write_private(configuration, controller)
    result = subprocess.run(  # noqa: S603 - native proposal CLI, private synthetic input file
        [
            sys.executable,
            "-m",
            "scripts.m3_11_unattended.connect_profile",
            "--configuration",
            str(configuration),
            "--base-configuration-sha256",
            profile["base_configuration_sha256"],
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0 and read_private(output) == profile
    assert CANARY not in result.stdout + result.stderr + output.read_text()


def test_actual_trusted_history_guard_precedes_dependencies_and_secret_action(
    tmp_path: Path,
) -> None:
    steps = workflow()["jobs"]["connect"]["steps"]
    guard = step("connect", "Require trusted helper history before running checked-out code")
    assert steps.index(guard) < next(
        i for i, row in enumerate(steps) if row["name"] == "Install pinned tools"
    )
    assert steps.index(guard) < next(
        i for i, row in enumerate(steps) if row.get("uses") == "./.github/actions/m3-11-connect"
    )
    environment = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Synthetic",
        "GIT_AUTHOR_EMAIL": "synthetic@example.test",
        "GIT_COMMITTER_NAME": "Synthetic",
        "GIT_COMMITTER_EMAIL": "synthetic@example.test",
    }

    def git(*args: str, data: str = "") -> str:
        result = subprocess.run(  # noqa: S603 - fixed local Git fixture, no remote or hooks
            ["/usr/bin/git", *args],
            cwd=tmp_path,
            env=environment,
            input=data,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return result.stdout.strip()

    git("init", "--quiet")
    tree = git("mktree")
    base = git("commit-tree", tree, data="synthetic base\n")
    main = git("commit-tree", tree, "-p", base, data="synthetic protected main\n")
    unmerged = git("commit-tree", tree, "-p", base, data="synthetic unmerged PR\n")
    for helper, operation, accepted in [
        (base, "confirm", True),
        (main, "validate-profile", True),
        (base, "validate-profile", False),
        (unmerged, "confirm", False),
        (unmerged, "validate-profile", False),
    ]:
        result = subprocess.run(  # noqa: S603 - actual trusted workflow guard, synthetic Git history
            ["/bin/bash", "-euo", "pipefail", "-c", guard["run"]],
            cwd=tmp_path,
            env={
                **environment,
                "HELPER_REVISION": helper,
                "WORKFLOW_REVISION": main,
                "OPERATION": operation,
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert (result.returncode == 0) == accepted
    assert (
        select(tmp_path, OPERATION="validate-profile", BOOTSTRAP=json.dumps(lease_bundle()))[
            0
        ].returncode
        != 0
    )


def test_get_only_validation_never_reconciles_revokes_or_confirms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    profile, _ = candidate(case.bundle, case.config.document())

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("validation reached a reconciliation/publication/credential mutation")

    monkeypatch.setattr(cleanup, "sweep_leases", forbidden)
    monkeypatch.setattr(cleanup, "sweep_legacy", forbidden)
    monkeypatch.setattr(ConnectInventory, "publish", forbidden)
    for roles in case.providers.values():
        for provider in roles.values():
            monkeypatch.setattr(provider, "create", forbidden)
            monkeypatch.setattr(provider, "delete", forbidden)
    before, posts = case.inventory.records(), case.client.posts
    out = tmp_path / "profile-validation"
    out.mkdir(mode=0o700)
    receipt = connect_action.execute(
        {"bootstrap": case.bundle, "profile": profile, "operation": "validate-profile"},
        directory=out,
        helper=HELPER,
    )
    assert receipt["status"] == "ready" and receipt["provider_activity_verified"] is True
    assert receipt["manifest_confirmation_published"] is False
    assert receipt["reconciliation_performed"] is False
    assert case.inventory.records() == before and case.client.posts == posts
    assert not case.server_active and CANARY not in json.dumps(receipt)
    with pytest.raises(LifecycleError, match="confirmation"):
        require_confirmation(
            case.inventory, case.manifest, independent_server_id=case.config.independent_server_id
        )


def test_validation_does_not_report_ready_when_connect_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    profile, _ = candidate(case.bundle, case.config.document())
    case.teardown_failure = True
    out = tmp_path / "validation"
    out.mkdir(mode=0o700)
    with pytest.raises(LifecycleError):
        connect_action.execute(
            {"bootstrap": case.bundle, "profile": profile, "operation": "validate-profile"},
            directory=out,
            helper=HELPER,
        )
    assert not (out / "profile-validation.json").exists()


@pytest.mark.parametrize("kind", ["connect", "provider", "provider-put"])
def test_get_only_guard_blocks_before_any_transport(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("write transport reached")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with read_only_requests(), pytest.raises(LifecycleError, match="read-only"):
        if kind == "connect":
            Connect("https://example.test", "synthetic").request(
                "POST", "/v1/vaults/" + "v" * 26 + "/items", {}
            )
        else:
            api = Api("https://api.digitalocean.com", "synthetic")
            api._request("PUT" if kind == "provider-put" else "DELETE", "/synthetic", None)


def test_controller_only_delivery_retains_native_coverage_and_never_writes_github(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = lease_bundle()
    profile, controller = candidate(bundle)
    prepare_controller(controller, profile, output=tmp_path)
    observed = []

    def validate(config: LeaseConfiguration, **_kwargs: object) -> None:
        config.require_issuance(now=datetime.now(UTC))
        observed.append(config.helper_revision)

    def observations(config: LeaseConfiguration, **_kwargs: object) -> dict[str, object]:
        validate(config)
        return {"status": "ready"}

    monkeypatch.setattr(activation, "activation_observations", observations)
    receipt = activate_controller(tmp_path)
    assert observed == [HELPER] and receipt["independent_confirmation"] == "pending-exact-manifest"
    client = Client()
    client.install_controller(tmp_path)
    transfers = [(program, args, data) for program, args, data in client.calls if data]
    assert len(transfers) == 1 and transfers[0][0] == "ssh"
    assert all(args[:2] != ("secret", "set") for _, args, _ in client.calls)
    assert not (tmp_path / "github-connect.json").exists()
    delivered = json.loads(transfers[0][2])
    assert "server_credentials" not in delivered
    assert delivered == controller
    assert read_private(tmp_path / "profile.json") == profile


def test_controller_only_cannot_skip_native_activation_or_change_profile(tmp_path: Path) -> None:
    profile, controller = candidate(lease_bundle())
    prepare_controller(controller, profile, output=tmp_path)
    client = Client()
    with pytest.raises((LifecycleError, OSError)):
        client.install_controller(tmp_path)
    assert client.calls == []
    profile["effective_configuration_sha256"] = "f" * 64
    write_private(tmp_path / "altered.json", profile)
    with pytest.raises(LifecycleError):
        prepare_controller(controller, profile, output=tmp_path / "altered")


def test_old_closed_lease_remains_compatible_with_changed_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    # A closure already validated by native inventory; profile keeps its original manifest/policy.
    case.inventory.publish(
        fact(
            case.manifest,
            "closed",
            {
                "results": [
                    {
                        "intent_sha256": intent.sha256,
                        "status": "verified",
                        "negative_authentication": "denied",
                    }
                    for intent in case.manifest.intents
                ]
            },
        )
    )
    profile, _ = candidate(case.bundle, case.config.document())
    before = case.inventory.records()
    out = tmp_path / "validation-old-closed"
    out.mkdir(mode=0o700)
    receipt = connect_action.execute(
        {"bootstrap": case.bundle, "profile": profile, "operation": "validate-profile"},
        directory=out,
        helper=HELPER,
    )
    assert receipt["status"] == "ready" and receipt["historical_closed_count"] == 1
    assert case.inventory.records() == before


def test_complete_native_handover_does_not_require_retired_original_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.m3_11_unattended import setup  # noqa: PLC0415 - replace production transport only

    case = Case(tmp_path, monkeypatch)
    bundle = cast(Row, copy.deepcopy(case.bundle))
    old = case.manifest.cleanup
    replacement_id = str(uuid.uuid7())
    roles = bundle["configuration"]["generations"].pop(old.generation_id)
    roles["cleanup"]["generation"]["generation_id"] = replacement_id
    bundle["configuration"]["generations"][replacement_id] = roles
    bundle["configuration"]["active_generation"] = replacement_id
    generation = roles["cleanup"]["generation"]
    for intent in case.manifest.intents:
        credential_id = "synthetic_" + intent.role.replace("-", "_")
        case.inventory.publish(
            fact(
                case.manifest,
                "created:" + intent.role,
                {"intent_sha256": intent.sha256, "credential_id": credential_id},
            )
        )
        case.inventory.publish(
            fact(
                case.manifest,
                "handover:" + intent.role + ":" + replacement_id,
                {
                    "intent_sha256": intent.sha256,
                    "credential_id": credential_id,
                    "previous_generation_sha256": digest(old.document()),
                    "generation": generation,
                    "observed_at": stamp(datetime.now(UTC)),
                },
            )
        )
    profile, controller = candidate(bundle)
    out = tmp_path / "handover"
    prepare_controller(controller, profile, output=out)
    monkeypatch.setattr(setup, "reader", lambda *_args: case.client)
    assert activate_controller(out)["status"] == "ready"
    before, posts = case.inventory.records(), case.client.posts
    receipt = connect_action.execute(
        {"bootstrap": bundle, "profile": profile, "operation": "validate-profile"},
        directory=out,
        helper=HELPER,
    )
    assert receipt["status"] == "ready"
    assert case.inventory.records() == before and case.client.posts == posts


@pytest.mark.parametrize("fault", ["provider-coverage", "legacy-obligations"])
def test_controller_only_real_activation_preserves_native_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    from scripts.m3_11_unattended import setup  # noqa: PLC0415 - replace production transport only
    from scripts.m3_11_unattended.config import LeaseBootstrap  # noqa: PLC0415

    case = Case(tmp_path, monkeypatch)
    profile, controller = candidate(case.bundle, case.config.document())
    out = tmp_path / "controller-native"
    prepare_controller(controller, profile, output=out)
    monkeypatch.setattr(setup, "reader", lambda *_args: case.client)

    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise LifecycleError("synthetic coverage unavailable")

    if fault == "provider-coverage":
        monkeypatch.setattr(LeaseBootstrap, "providers", unavailable)
    else:
        monkeypatch.setattr(
            activation, "sweep_legacy", lambda *_args, **_kwargs: {"status": "unresolved"}
        )
    with pytest.raises(LifecycleError):
        activate_controller(out)
    assert not (out / "controller-activation.json").exists()
