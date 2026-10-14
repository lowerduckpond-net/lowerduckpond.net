"""Execute the merge-time selectors and both pinned action transport contracts.

The legacy JS fixture is byte-for-byte from 0b5b198bf06443e61f01b1f7259fea827f79fc23.
It is test evidence only; deployed legacy code always comes from its existing pin.
No test reads installed secrets, starts Connect, or contacts a provider.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended.connect_setup import assemble
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_connect_setup import independent_reader
from .test_m3_11_lease_configuration import document

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/m3-11-credential-cleanup.yml"
LEGACY = "0b5b198bf06443e61f01b1f7259fea827f79fc23"
CANARY = "synthetic-workflow-private-canary"
Row = dict[str, Any]


def workflow() -> Row:
    # BaseLoader preserves GitHub's `on` key instead of treating it as YAML 1.1 true.
    return cast(Row, yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader))  # noqa: S506 - scalar-only loader


def step(job: str, key: str) -> Row:
    return next(row for row in workflow()["jobs"][job]["steps"] if key in row.values())


def legacy_inputs() -> tuple[Row, Row]:
    return (
        {
            "format": "lowerduckpond-m3-11-connect-bootstrap-v1",
            "targets": {"synthetic": True},
            "journal_vault": "j" * 26,
            "cleanup": {"synthetic": True},
            "token": {"private": CANARY},
            "server_credentials": {"private": CANARY},
            "provider_metadata": {"synthetic": True},
            "checkpoint_token": CANARY,
        },
        {
            "format": "lowerduckpond-m3-11-connect-independent-v1",
            "stage": "active",
            "active_helper": LEGACY,
            "request": {"historical": "preserved"},
            "receipt": {"historical": "preserved"},
        },
    )


def lease_bundle() -> Row:
    configured = document()
    return assemble(
        configured,
        independent_reader(str(configured["independent_server_id"])),
        {"synthetic": CANARY},
    )[1]


def test_default_lease_schedule_selects_confirmation(tmp_path: Path) -> None:
    result, values = select(tmp_path, BOOTSTRAP=json.dumps(lease_bundle()))
    assert result.returncode == 0
    assert values["operation"] == "confirm"


def select(
    tmp_path: Path, job: str = "connect", **overrides: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    bundle, selected = legacy_inputs()
    output = tmp_path / f"{job}-output"
    output.unlink(missing_ok=True)
    environment = {
        "PATH": os.environ["PATH"],
        "BACKEND": "connect",
        "OPERATION": "reconcile",
        "CONFIGURATION": json.dumps(selected),
        "BOOTSTRAP": json.dumps(bundle),
        "LEGACY_HELPER": LEGACY,
        "GITHUB_OUTPUT": str(output),
        **overrides,
    }
    selector = step(job, "selection" if job == "connect" else "backend")
    result = subprocess.run(  # noqa: S603 - execute the committed workflow against synthetic env
        ["/bin/bash", "-euo", "pipefail", "-c", selector["run"]],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    values = (
        dict(line.split("=", 1) for line in output.read_text().splitlines())
        if output.exists()
        else {}
    )
    assert CANARY not in result.stdout + result.stderr + json.dumps(values)
    return result, values


def deliver(tmp_path: Path, selected: dict[str, str], bundle: Row) -> Row:
    action_step = step("connect", "./.github/actions/m3-11-connect")
    environment = {
        "PATH": os.environ["PATH"],
        "ACTIONS_RUNTIME_TOKEN": "synthetic-artifact-token",
    }
    for key, expression in action_step["env"].items():
        match = re.fullmatch(r"\$\{\{ steps.selection.outputs.([a-z_]+) }}", expression)
        if match:
            environment[key] = selected[match[1]]
        elif expression == "${{ secrets.M3_11_CONNECT_BOOTSTRAP }}":
            environment[key] = json.dumps(bundle)
        else:
            assert key == "GH_TOKEN"
            assert (
                expression
                == "${{ steps.selection.outputs.mode == 'legacy' && github.token || '' }}"
            )
            environment[key] = "synthetic-github-token" if selected["mode"] == "legacy" else ""
    receiver = tmp_path / ".venv/bin/python"
    receiver.parent.mkdir(parents=True)
    receiver.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path('received.json').write_text(json.dumps({'payload': json.load(sys.stdin), "
        "'helper': os.environ.get('M3_11_HELPER_REVISION'), "
        "'github': os.environ.get('GH_TOKEN'), 'runtime': os.environ.get('ACTIONS_RUNTIME_TOKEN'), "
        "'bootstrap_in_environment': 'M3_11_CONNECT_BOOTSTRAP' in os.environ}))\n"
        f"print('{CANARY}')\n"
    )
    receiver.chmod(0o700)
    if selected["mode"] == "legacy":
        assert selected["helper_revision"] == LEGACY
        source = ROOT / "tests/infrastructure/fixtures/m3_11_legacy_connect_action.js"
    else:
        source = ROOT / ".github/actions/m3-11-connect/index.js"
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - actual JS action, synthetic private stdin receiver
        [node, str(source)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert CANARY not in result.stdout + result.stderr
    return cast(Row, json.loads((tmp_path / "received.json").read_text()))


def test_merge_keeps_legacy_selection_pin_and_actual_action_contract(tmp_path: Path) -> None:
    bundle, original = legacy_inputs()
    result, selected = select(tmp_path)
    assert result.returncode == 0
    assert selected["mode"] == "legacy" and selected["operation"] == "reconcile"
    assert json.loads(selected["configuration"]) == original
    assert selected["helper_revision"] == LEGACY
    assert select(tmp_path, "reconcile")[1] == {"enabled": "false"}
    received = deliver(tmp_path, selected, bundle)
    assert received["payload"] == {
        "bootstrap": bundle,
        "selection": original,
        "operation": "reconcile",
        "run_sha256": "",
        "dispatch_id": "",
    }
    assert received["helper"] == LEGACY and not received["bootstrap_in_environment"]
    assert received["github"] == "synthetic-github-token"
    assert received["runtime"] == "synthetic-artifact-token"


@pytest.mark.parametrize("operation", ["reconcile", "confirm", "cleanup"])
def test_explicit_new_bundle_selects_its_own_pin_and_new_action_only(
    tmp_path: Path, operation: str
) -> None:
    bundle = lease_bundle()
    result, selected = select(
        tmp_path, BOOTSTRAP=json.dumps(bundle), OPERATION=operation, CONFIGURATION="obsolete-unread"
    )
    assert result.returncode == 0
    assert selected["mode"] == "lease" and selected["configuration"] == ""
    assert selected["helper_revision"] == bundle["configuration"]["helper_revision"]
    assert selected["operation"] == ("confirm" if operation == "reconcile" else operation)
    action.bootstrap(bundle, helper=selected["helper_revision"])
    received = deliver(tmp_path, selected, bundle)
    assert received["payload"] == {"bootstrap": bundle, "operation": selected["operation"]}
    assert received["github"] is None and received["runtime"] is None
    assert not received["bootstrap_in_environment"]


@pytest.mark.parametrize("backend", ["", "service-account", "connect-initializing"])
def test_pre_connect_cleaner_keeps_existing_pin_and_quiet_empty_behavior(
    tmp_path: Path, backend: str
) -> None:
    _bundle, configured = legacy_inputs()
    configured["active_helper"] = "e" * 40
    result, selected = select(
        tmp_path, "reconcile", BACKEND=backend, CONFIGURATION=json.dumps(configured)
    )
    assert result.returncode == 0 and selected["enabled"] == "true"
    assert selected["helper_revision"] == (
        "e" * 40 if backend == "connect-initializing" else LEGACY
    )
    assert selected["quiet_empty"] == str(backend == "connect-initializing").lower()
    result, disabled = select(tmp_path, BACKEND=backend, BOOTSTRAP="not-installed")
    assert result.returncode == 0 and disabled == {"enabled": "false"}


@pytest.mark.parametrize("operation", ["confirm", "cleanup", "witness", "genesis", "discovery"])
def test_legacy_contract_cannot_be_used_for_new_confirmation_or_old_issuance(
    tmp_path: Path, operation: str
) -> None:
    result, selected = select(tmp_path, OPERATION=operation)
    assert result.returncode != 0 and not selected


@pytest.mark.parametrize(
    "overrides",
    [
        {"BACKEND": "unknown"},
        {"BACKEND": "service-account", "OPERATION": "confirm"},
        {"BOOTSTRAP": ""},
        {"BOOTSTRAP": "{private-" + CANARY},
        {"BOOTSTRAP": "[]"},
        {"BOOTSTRAP": "null"},
        {"BOOTSTRAP": '{"format":"unsupported"}'},
        {"BOOTSTRAP": '{"format":"lowerduckpond-m3-11-connect-bootstrap-v1"}'},
        {"CONFIGURATION": "not-json-" + CANARY},
        {"CONFIGURATION": "null"},
    ],
)
def test_invalid_selection_fails_closed_without_private_output(
    tmp_path: Path, overrides: dict[str, str]
) -> None:
    result, selected = select(tmp_path, **overrides)
    assert result.returncode != 0 and not selected
    assert "Installed cleanup selection is invalid" in result.stderr


@pytest.mark.parametrize("fault", ["format", "stage", "helper", "request", "receipt", "extra"])
def test_malformed_legacy_configuration_never_selects_a_helper(tmp_path: Path, fault: str) -> None:
    _bundle, configured = legacy_inputs()
    if fault == "extra":
        configured["unexpected"] = True
    else:
        configured[{"helper": "active_helper"}.get(fault, fault)] = CANARY
    result, selected = select(tmp_path, CONFIGURATION=json.dumps(configured))
    assert result.returncode != 0 and not selected


@pytest.mark.parametrize(
    "fault", ["format", "mode", "helper", "configuration", "credentials", "extra"]
)
def test_malformed_new_selection_cannot_fall_back_to_valid_legacy_configuration(
    tmp_path: Path, fault: str
) -> None:
    bundle = lease_bundle()
    if fault == "configuration":
        bundle["configuration"] = []
    elif fault == "credentials":
        bundle["server_credentials"] = {}
    elif fault == "extra":
        bundle["unexpected"] = True
    else:
        bundle["configuration"][{"helper": "helper_revision"}.get(fault, fault)] = CANARY
    result, selected = select(tmp_path, BOOTSTRAP=json.dumps(bundle))
    assert result.returncode != 0 and not selected


def test_selected_new_helper_validates_full_configuration_before_starting_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = copy.deepcopy(lease_bundle())
    bundle["configuration"]["policy"] = {}
    result, selected = select(tmp_path, BOOTSTRAP=json.dumps(bundle))
    assert result.returncode == 0

    def forbidden(*_args: object) -> None:
        pytest.fail("malformed private configuration must not start Connect or reach providers")

    monkeypatch.setattr(action, "independent_server", forbidden)
    with pytest.raises((LifecycleError, ValueError)):
        action.execute(
            {"bootstrap": bundle, "operation": selected["operation"]},
            directory=tmp_path,
            helper=selected["helper_revision"],
        )


def test_workflow_keeps_cleanup_only_dispatch_and_private_pinned_transport() -> None:
    value = workflow()
    operations = value["on"]["workflow_dispatch"]["inputs"]["operation"]
    assert operations["default"] == "reconcile"
    assert operations["options"] == ["reconcile", "confirm", "cleanup"]
    assert value["on"]["schedule"] == [{"cron": "7 * * * *"}]
    assert value["concurrency"]["cancel-in-progress"] == "false"
    for job, selector in (("reconcile", "backend"), ("connect", "selection")):
        settings = value["jobs"][job]
        assert settings["if"] == "github.ref == 'refs/heads/main'"
        assert settings["environment"] == "m3-11-credential-cleanup"
        checkout = step(job, "Check out the pinned lifecycle helper")
        assert checkout["with"]["ref"] == "${{ steps." + selector + ".outputs.helper_revision }}"
        assert checkout["if"] == f"steps.{selector}.outputs.enabled == 'true'"
        assert checkout["with"]["persist-credentials"] == "false"
        assert step(job, selector)["env"]["OPERATION"] == "${{ inputs.operation || 'reconcile' }}"
    assert value["jobs"]["connect"]["permissions"] == {
        "contents": "read",
        "actions": "read",
        "statuses": "write",
    }
    assert step("connect", "selection")["env"] == {
        "BACKEND": "${{ vars.M3_11_CLEANUP_BACKEND }}",
        "OPERATION": "${{ inputs.operation || 'reconcile' }}",
        "CONFIGURATION": "${{ vars.M3_11_CONNECT_CONFIGURATION }}",
        "BOOTSTRAP": "${{ secrets.M3_11_CONNECT_BOOTSTRAP }}",
        "IMPORT_BRIDGE": "${{ vars.M3_11_LEGACY_IMPORT_BRIDGE }}",
    }
    legacy_command = step("reconcile", "Reconcile and verify outstanding credentials")["run"]
    assert "--actor github" in legacy_command and "--quiet-empty" in legacy_command
    assert "--journal-cache-output" in legacy_command
    fixture = ROOT / "tests/infrastructure/fixtures/m3_11_legacy_connect_action.js"
    assert (
        hashlib.sha256(fixture.read_bytes()).hexdigest()
        == "8c046450e48222b409795f7680c71684fd9a3164dbb9759cb7a4909865f41199"
    )


def bridge_binding() -> Row:
    return {"revision": "b" * 40, "journal_vault": "j" * 26, "migration_sha256": "a" * 64}


@pytest.mark.parametrize("fault", ["vault", "revision", "migration", "extra", "helper"])
def test_import_bridge_requires_explicit_exact_bindings(tmp_path: Path, fault: str) -> None:
    binding = bridge_binding()
    _, configuration = legacy_inputs()
    if fault == "vault":
        binding["journal_vault"] = "x" * 26
    elif fault == "revision":
        binding["revision"] = "main"
    elif fault == "migration":
        binding["migration_sha256"] = "a" * 63
    elif fault == "extra":
        binding["unreviewed"] = True
    else:
        configuration["active_helper"] = "c" * 40
    result, _ = select(
        tmp_path, IMPORT_BRIDGE=json.dumps(binding), CONFIGURATION=json.dumps(configuration)
    )
    assert result.returncode != 0


def test_explicit_bridge_keeps_legacy_pin_separate_and_new_delivery_does_not_inherit_it(
    tmp_path: Path,
) -> None:
    result, selected = select(tmp_path, IMPORT_BRIDGE=json.dumps(bridge_binding()))
    assert result.returncode == 0
    assert selected["helper_revision"] == LEGACY
    assert selected["checkout_path"] == "legacy-helper"
    assert selected["bridge_revision"] == "b" * 40
    assert selected["bridge_vault"] == "j" * 26
    assert selected["bridge_migration"] == "a" * 64
    assert selected["import_bridge"] == "true"
    assert step("connect", "Install locked dependencies")["working-directory"] == (
        "${{ steps.selection.outputs.checkout_path }}"
    )
    result, selected = select(
        tmp_path, BOOTSTRAP=json.dumps(lease_bundle()), IMPORT_BRIDGE=json.dumps(bridge_binding())
    )
    assert result.returncode == 0
    assert selected["import_bridge"] == "false" and selected["checkout_path"] == "."


@pytest.mark.parametrize("bad_binding", [False, True])
def test_bridge_action_preserves_private_stdin_checkpoint_runtime_and_legacy_cwd(
    tmp_path: Path,
    bad_binding: bool,
) -> None:
    bundle, configuration = legacy_inputs()
    root = tmp_path / "legacy-helper"
    receiver = root / ".venv/bin/python"
    receiver.parent.mkdir(parents=True)
    receiver.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "Path('received.json').write_text(json.dumps({'payload': json.load(sys.stdin), "
        "'arguments': sys.argv[1:], 'cwd': os.getcwd(), "
        "'helper': os.environ['M3_11_HELPER_REVISION'], "
        "'github': os.environ['GH_TOKEN'], 'runtime': os.environ['ACTIONS_RUNTIME_TOKEN'], "
        "'private_env': any(k in os.environ for k in "
        "['M3_11_CONNECT_BOOTSTRAP', 'M3_11_CONNECT_CONFIGURATION'])}))\n"
        f"print('{CANARY}')\n"
    )
    receiver.chmod(0o700)
    node = shutil.which("node")
    assert node is not None
    source = ROOT / ".github/actions/m3-11-legacy-import-bridge/index.js"
    result = subprocess.run(  # noqa: S603 - real action with synthetic child and credentials
        [node, str(source)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
        env={
            "PATH": os.environ["PATH"],
            "RUNNER_TEMP": str(tmp_path / "private"),
            "M3_11_LEGACY_ROOT": str(root),
            "M3_11_HELPER_REVISION": LEGACY,
            "M3_11_BRIDGE_VAULT": "j" * 26,
            "M3_11_BRIDGE_MIGRATION": "bad" if bad_binding else "a" * 64,
            "M3_11_CONNECT_OPERATION": "reconcile",
            "M3_11_CONNECT_BOOTSTRAP": json.dumps(bundle),
            "M3_11_CONNECT_CONFIGURATION": json.dumps(configuration),
            "GH_TOKEN": "synthetic-github",
            "ACTIONS_RUNTIME_TOKEN": "synthetic-runtime",
        },
    )
    assert CANARY not in result.stdout + result.stderr
    if bad_binding:
        assert result.returncode != 0 and not (root / "received.json").exists()
        return
    assert result.returncode == 0
    received = json.loads((root / "received.json").read_text())
    assert received == {
        "payload": {
            "bootstrap": bundle,
            "selection": configuration,
            "operation": "reconcile",
            "run_sha256": "",
            "dispatch_id": "",
        },
        "arguments": [
            str(ROOT / "scripts/m3_11_unattended/legacy_import_reader.py"),
            "--legacy-root",
            str(root),
            "--journal-vault",
            "j" * 26,
            "--migration-sha256",
            "a" * 64,
            "--actor",
            "github",
            "--receipt",
            str(tmp_path / "private/m3-11-import-reader/observation.json"),
        ],
        "cwd": str(root),
        "helper": LEGACY,
        "github": "synthetic-github",
        "runtime": "synthetic-runtime",
        "private_env": False,
    }
