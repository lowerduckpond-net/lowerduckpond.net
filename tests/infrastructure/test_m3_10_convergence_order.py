from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
CANDIDATE = "c" * 64
PRECEDING = "4e32c4a88d729b371b8cd5da96e5fedbc9f30266acb0984599c1d645939bef85"


def executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\nset -euo pipefail\n" + body + "\n")
    path.chmod(0o755)


@pytest.fixture
def runner(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    wrapper = scripts / "configure-production"
    wrapper.write_bytes((ROOT / "scripts/configure-production").read_bytes())
    wrapper.chmod(0o755)
    (scripts / "m3-10-convergence-state").write_bytes(
        (ROOT / "scripts/m3-10-convergence-state").read_bytes()
    )
    (scripts / "m3-10-completed-host-preflight").write_bytes(
        (ROOT / "scripts/m3-10-completed-host-preflight").read_bytes()
    )
    commands = tmp_path / "commands"
    executable(
        commands / "git",
        """case "$*" in
        *branch*) echo main;;
        *rev-parse*) echo "$TEST_SOURCE";;
    esac""",
    )
    executable(commands / "ssh-keygen", "exit 0")
    executable(
        commands / "ssh",
        """case "$*" in
        *" completed-host")
            echo completed-host-preflight >>"$TEST_LOG"
            exit "$TEST_HOST_STATUS";;
        *"-- check "*)
            echo completion-check >>"$TEST_LOG"
            remote_command=${!#}
            [[ ${remote_command##* } == "$TEST_COMPLETED_SOURCE" ]] || exit 1
            exit "$TEST_COMPLETED_STATUS";;
        *"-- clear "*) echo completion-clear >>"$TEST_LOG";;
        *"-- record "*) echo completion-record >>"$TEST_LOG";;
        *) printf "/opt/lowerduckpond/static-host-agent/%s\\n" "$TEST_SELECTED";;
    esac""",
    )
    executable(
        commands / "tofu",
        """case "$*" in
        *output*) echo fixture-value;;
    esac""",
    )
    executable(
        commands / "uv",
        """case "$*" in
        *read_production_ansible_inventory*) echo 192.0.2.1;;
        *scripts.check_m3_10_provider*)
            [[ "$*" == *"--allow-existing-archives"* ]] || exit 99
            echo provider-policy >>"$TEST_LOG"
            exit "$TEST_PROVIDER_STATUS";;
        *scripts.check_m3_10_host_firewall*)
            echo firewall >>"$TEST_LOG"
            exit "$TEST_FIREWALL_STATUS";;
        *scripts.m3_10_qualification_report*)
            echo verify-report >>"$TEST_LOG"
            exit "$TEST_VERIFY_STATUS";;
        *ldp-m3-archive*credential-check*)
            echo scoped-current-credentials >>"$TEST_LOG"
            exit "$TEST_CREDENTIAL_STATUS";;
        *ldp-m3-archive*acceptance*)
            echo current-credentials >>"$TEST_LOG"
            exit "$TEST_CREDENTIAL_STATUS";;
        *ldp-m3-archive*verify-report*)
            echo current-credential-report >>"$TEST_LOG"
            exit "$TEST_CREDENTIAL_REPORT_STATUS";;
        *ansible-playbook*)
            echo ansible >>"$TEST_LOG"
            [[ "$TEST_ANSIBLE_STATUS" == 0 ]] || exit "$TEST_ANSIBLE_STATUS"
            echo 'host: ok=1 changed=0 unreachable=0 failed=0';;
        *) exit 99;;
    esac""",
    )
    executable(
        scripts / "preflight-m3-6-production",
        'echo general-preflight >>"$TEST_LOG"; exit "$TEST_GENERAL_STATUS"',
    )
    for script, label, status in (
        ("check-m3-6-operator-identity", "operator-identity", "TEST_IDENTITY_STATUS"),
        ("preflight-m3-dark-host-production", "dark-host-preflight", "TEST_DARK_HOST_STATUS"),
    ):
        executable(scripts / script, f'echo {label} >>"$TEST_LOG"; exit "${{{status}}}"')
    executable(
        scripts / "preflight-m3-10-production",
        '''echo m3-10-preflight >>"$TEST_LOG"
    exit "$TEST_PREFLIGHT_STATUS"''',
    )
    executable(scripts / "build-static-host-agent", f"printf '%s\\n' '{CANDIDATE}'")
    key = tmp_path / "admin-key"
    key.touch(mode=0o600)
    environment = {
        "PATH": str(commands) + ":" + os.environ["PATH"],
        "TEST_LOG": str(tmp_path / "calls"),
        "TEST_SELECTED": PRECEDING,
        "TEST_SOURCE": "0" * 40,
        "TEST_COMPLETED_SOURCE": "0" * 40,
        "TEST_GENERAL_STATUS": "0",
        "TEST_IDENTITY_STATUS": "0",
        "TEST_DARK_HOST_STATUS": "0",
        "TEST_HOST_STATUS": "0",
        "TEST_VERIFY_STATUS": "0",
        "TEST_PROVIDER_STATUS": "0",
        "TEST_FIREWALL_STATUS": "0",
        "TEST_PREFLIGHT_STATUS": "0",
        "TEST_COMPLETED_STATUS": "1",
        "TEST_ANSIBLE_STATUS": "0",
        "TEST_CREDENTIAL_STATUS": "0",
        "TEST_CREDENTIAL_REPORT_STATUS": "0",
        "ANSIBLE_PRIVATE_KEY_FILE": str(key),
        "ADMIN_SOURCE_CIDRS_JSON": '["192.0.2.1/32"]',
        "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED": "true",
        "CADDY_ORIGIN_PULL_CA_PATHS_JSON": '["/private/ca.pem"]',
        "M3_10_QUALIFICATION_REPORT": str(tmp_path / "report.json"),
        "M3_10_ARCHIVE_CREDENTIAL_BACKUP_CONFIRMED": "true",
    }
    for name in (
        "CADDY_CLOUDFLARE_API_TOKEN",
        "OPENTOFU_ENCRYPTION_PASSPHRASE",
        "OPENTOFU_STATE_ACCESS_KEY_ID",
        "OPENTOFU_STATE_BUCKET",
        "OPENTOFU_STATE_SECRET_ACCESS_KEY",
        "RESTIC_PASSWORD",
        "SPACES_REGION",
        "STATIC_OPERATOR_PRINCIPAL",
        "STATIC_OPERATOR_PUBLIC_KEY",
    ):
        environment[name] = "fixture-value"
    return wrapper, environment


def run(runner: tuple[Path, dict[str, str]]) -> tuple[int, list[str]]:
    wrapper, environment = runner
    outcome = subprocess.run(  # noqa: S603 - copied wrapper and fixed local command doubles
        [str(wrapper)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    path = Path(environment["TEST_LOG"])
    return outcome.returncode, path.read_text().splitlines() if path.exists() else []


@pytest.mark.parametrize(
    "missing", ["M3_10_QUALIFICATION_REPORT", "M3_10_ARCHIVE_CREDENTIAL_BACKUP_CONFIRMED"]
)
def test_upgrade_never_reaches_ansible_without_required_evidence(
    runner: tuple[Path, dict[str, str]], missing: str
) -> None:
    runner[1].pop(missing)
    status, calls = run(runner)
    assert status != 0
    assert calls == ["general-preflight"]


@pytest.mark.parametrize("failure", ["TEST_VERIFY_STATUS", "TEST_PREFLIGHT_STATUS"])
def test_failed_live_evidence_or_preflight_stops_before_first_mutation(
    runner: tuple[Path, dict[str, str]], failure: str
) -> None:
    runner[1][failure] = "1"
    status, calls = run(runner)
    assert status != 0
    assert "ansible" not in calls


def test_verified_upgrade_checks_report_and_preflight_before_any_convergence(
    runner: tuple[Path, dict[str, str]],
) -> None:
    status, calls = run(runner)
    assert status == 0
    assert calls == [
        "general-preflight",
        "verify-report",
        "m3-10-preflight",
        "current-credentials",
        "current-credential-report",
        "completion-clear",
        "ansible",
        "ansible",
        "ansible",
        "completion-record",
    ]


def test_completed_reconfiguration_uses_history_safe_host_gate(
    runner: tuple[Path, dict[str, str]],
) -> None:
    runner[1]["TEST_SELECTED"] = CANDIDATE
    runner[1]["TEST_COMPLETED_STATUS"] = "0"
    runner[1].pop("M3_10_QUALIFICATION_REPORT")
    # The legacy empty-state preflight fails once any tenant or audit history exists.
    runner[1]["TEST_GENERAL_STATUS"] = "1"
    status, calls = run(runner)
    assert status == 0
    assert calls == [
        "completion-check",
        "operator-identity",
        "dark-host-preflight",
        "completed-host-preflight",
        "provider-policy",
        "firewall",
        "scoped-current-credentials",
        "completion-clear",
        "ansible",
        "ansible",
        "ansible",
        "completion-record",
    ]


@pytest.mark.parametrize("failure", ["missing-report", "expired-report", "partial-host"])
def test_selected_but_incomplete_candidate_retains_the_full_gate(
    runner: tuple[Path, dict[str, str]], failure: str
) -> None:
    runner[1]["TEST_SELECTED"] = CANDIDATE
    if failure == "missing-report":
        runner[1].pop("M3_10_QUALIFICATION_REPORT")
    elif failure == "expired-report":
        runner[1]["TEST_VERIFY_STATUS"] = "1"
    else:
        runner[1]["TEST_PREFLIGHT_STATUS"] = "1"
    status, calls = run(runner)
    assert status != 0
    assert "completion-check" in calls
    assert "ansible" not in calls
    assert "completion-clear" not in calls
    assert "completion-record" not in calls


def test_interrupted_convergence_never_records_completion(
    runner: tuple[Path, dict[str, str]],
) -> None:
    runner[1]["TEST_ANSIBLE_STATUS"] = "1"
    status, calls = run(runner)
    assert status != 0
    assert "completion-clear" in calls
    assert "completion-record" not in calls


@pytest.mark.parametrize(
    "completed,failure",
    [
        (False, "TEST_CREDENTIAL_STATUS"),
        (False, "TEST_CREDENTIAL_REPORT_STATUS"),
        (True, "TEST_CREDENTIAL_STATUS"),
    ],
)
def test_current_runtime_keys_must_pass_even_after_prior_qualification(
    runner: tuple[Path, dict[str, str]], completed: bool, failure: str
) -> None:
    if completed:
        runner[1]["TEST_SELECTED"] = CANDIDATE
        runner[1]["TEST_COMPLETED_STATUS"] = "0"
    runner[1][failure] = "1"
    status, calls = run(runner)
    assert status != 0
    assert ("scoped-current-credentials" if completed else "current-credentials") in calls
    assert "completion-clear" not in calls
    assert "ansible" not in calls


@pytest.mark.parametrize("failure", ["missing-report", "expired-report", "partial-host"])
def test_same_artifact_with_new_deployment_source_cannot_reuse_completion(
    runner: tuple[Path, dict[str, str]], failure: str
) -> None:
    runner[1]["TEST_SELECTED"] = CANDIDATE
    runner[1]["TEST_COMPLETED_STATUS"] = "0"
    runner[1]["TEST_SOURCE"] = "1" * 40
    if failure == "missing-report":
        runner[1].pop("M3_10_QUALIFICATION_REPORT")
    elif failure == "expired-report":
        runner[1]["TEST_VERIFY_STATUS"] = "1"
    else:
        runner[1]["TEST_PREFLIGHT_STATUS"] = "1"
    status, calls = run(runner)
    assert status != 0
    assert "completion-check" in calls
    assert "scoped-current-credentials" not in calls
    assert "ansible" not in calls
    assert "completion-clear" not in calls
    assert "completion-record" not in calls


@pytest.mark.parametrize("failure", ["TEST_PROVIDER_STATUS", "TEST_FIREWALL_STATUS"])
def test_completed_candidate_still_requires_live_provider_and_firewall_policy(
    runner: tuple[Path, dict[str, str]], failure: str
) -> None:
    runner[1]["TEST_SELECTED"] = CANDIDATE
    runner[1]["TEST_COMPLETED_STATUS"] = "0"
    runner[1][failure] = "1"
    status, calls = run(runner)
    assert status != 0
    assert "provider-policy" in calls
    assert "scoped-current-credentials" not in calls
    assert "ansible" not in calls
    assert "completion-clear" not in calls
    assert "completion-record" not in calls


@pytest.mark.parametrize(
    "failure", ["TEST_IDENTITY_STATUS", "TEST_DARK_HOST_STATUS", "TEST_HOST_STATUS"]
)
def test_completed_host_must_pass_identity_build_and_nonempty_state_integrity(
    runner: tuple[Path, dict[str, str]], failure: str
) -> None:
    runner[1]["TEST_SELECTED"] = CANDIDATE
    runner[1]["TEST_COMPLETED_STATUS"] = "0"
    runner[1][failure] = "1"
    status, calls = run(runner)
    assert status != 0
    assert "general-preflight" not in calls
    assert "completion-clear" not in calls
    assert "ansible" not in calls


def test_incomplete_candidate_checks_completion_before_strict_empty_state_gate(
    runner: tuple[Path, dict[str, str]],
) -> None:
    runner[1]["TEST_SELECTED"] = CANDIDATE
    runner[1]["TEST_GENERAL_STATUS"] = "1"
    status, calls = run(runner)
    assert status != 0
    assert calls == ["completion-check", "general-preflight"]
