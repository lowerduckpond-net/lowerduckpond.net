from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
IDENTITY_CHECKER = (REPOSITORY_ROOT / "scripts/check-m3-6-operator-identity").resolve()
PREFLIGHT = (REPOSITORY_ROOT / "scripts/preflight-m3-6-production").resolve()
DARK_HOST_PREFLIGHT = (REPOSITORY_ROOT / "scripts/preflight-m3-dark-host-production").resolve()
CONFIGURE = (REPOSITORY_ROOT / "scripts/configure-production").resolve()
SSH_KEYGEN = shutil.which("ssh-keygen")
INPUT_ERROR_STATUS = 2


def create_key(tmp_path: Path, name: str, key_type: str = "ed25519") -> tuple[Path, str]:
    assert SSH_KEYGEN is not None
    private_key = tmp_path / name
    result = subprocess.run(  # noqa: S603 -- fixed test-only key generator.
        [
            SSH_KEYGEN,
            "-q",
            "-t",
            key_type,
            "-N",
            "",
            "-C",
            name,
            "-f",
            os.fspath(private_key),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return private_key, private_key.with_suffix(".pub").read_text(encoding="ascii").strip()


def check_identity(
    admin_key: Path,
    operator_public_key: str,
    principal: str = "operator@example.test",
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "STATIC_OPERATOR_PRINCIPAL": principal,
            "STATIC_OPERATOR_PUBLIC_KEY": operator_public_key,
        }
    )
    return subprocess.run(  # noqa: S603 -- reviewed absolute repository helper.
        [os.fspath(IDENTITY_CHECKER), os.fspath(admin_key)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_operator_identity_gate_accepts_a_distinct_ed25519_key(tmp_path: Path) -> None:
    admin_key, _ = create_key(tmp_path, "admin")
    _, operator_public_key = create_key(tmp_path, "operator")

    result = check_identity(admin_key, operator_public_key)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "M3.6 dedicated operator identity inputs passed.\n"


def test_operator_identity_gate_refuses_admin_key_reuse(tmp_path: Path) -> None:
    admin_key, admin_public_key = create_key(tmp_path, "admin")

    result = check_identity(admin_key, admin_public_key)

    assert result.returncode == INPUT_ERROR_STATUS
    assert "must not reuse" in result.stderr


@pytest.mark.parametrize(
    "principal",
    ["", "contains a space", ".starts-with-punctuation", "x" * 129],
)
def test_operator_identity_gate_refuses_invalid_principals(
    tmp_path: Path,
    principal: str,
) -> None:
    admin_key, _ = create_key(tmp_path, "admin")
    _, operator_public_key = create_key(tmp_path, "operator")

    result = check_identity(admin_key, operator_public_key, principal)

    assert result.returncode == INPUT_ERROR_STATUS
    assert "STATIC_OPERATOR_PRINCIPAL" in result.stderr


def test_operator_identity_gate_refuses_non_ed25519_keys(tmp_path: Path) -> None:
    admin_key, _ = create_key(tmp_path, "admin")
    _, operator_public_key = create_key(tmp_path, "operator", "rsa")

    result = check_identity(admin_key, operator_public_key)

    assert result.returncode == INPUT_ERROR_STATUS
    assert "STATIC_OPERATOR_PUBLIC_KEY" in result.stderr


def test_operator_identity_gate_refuses_tab_separated_key(tmp_path: Path) -> None:
    admin_key, _ = create_key(tmp_path, "admin")
    _, operator_public_key = create_key(tmp_path, "operator")

    result = check_identity(admin_key, operator_public_key.replace(" ", "\t", 1))

    assert result.returncode == INPUT_ERROR_STATUS
    assert "STATIC_OPERATOR_PUBLIC_KEY" in result.stderr


def test_production_convergence_repeats_the_m3_6_preflight() -> None:
    preflight = PREFLIGHT.read_text(encoding="utf-8")
    dark_host_preflight = DARK_HOST_PREFLIGHT.read_text(encoding="utf-8")
    configure = CONFIGURE.read_text(encoding="utf-8")

    assert '"${repository_root}/scripts/preflight-m3-dark-host-production"' in preflight
    assert '"${repository_root}/scripts/check-m3-6-operator-identity"' in preflight
    assert '"${repository_root}/scripts/preflight-m3-6-production"' in configure
    assert "--allow-exact-failed-caddy-recovery" in configure
    assert "--allow-exact-failed-caddy-recovery" in preflight
    assert "--allow-exact-failed-caddy-recovery" in dark_host_preflight
    assert '"${repository_root}/scripts/preflight-m3-dark-host-production"' not in configure
    assert "-o IdentitiesOnly=yes" in preflight
    assert "-o IdentitiesOnly=yes" in dark_host_preflight
    assert "expected_state_inventory=" in preflight
    assert "expected_authorization_inventory=" in preflight
    assert "export.lock | intake.lock | publication.lock | tenant-state.lock" in preflight
    assert "regular\\ empty\\ file:root:root:600:1:0" in preflight
    assert "expected_locks=" not in preflight
    assert "generation_root=/etc/caddy/generations" in preflight
    assert 'generation_status=$("${generation_check}")' in preflight
    assert "39f28840373363b9f3b4fa446f05d64b2a30d8904bbfbe7e989bd7f5bd9989fb" in preflight
    assert "3709daa0fd2465a73ae6b0c7dd0d6137cf0ec747e11e5e670df084113265d43b" in preflight
    assert "pending)" in preflight
    assert "the pending Caddy transaction has no durable intent" in preflight
    assert "/etc/caddy/generations\\|root:caddy:750" not in preflight
    for property_name, expected_value in (
        ("LoadState", "loaded"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
    ):
        assert (
            f"systemctl show --value --property={property_name} caddy.service) == {expected_value}"
        ) in dark_host_preflight
    assert "ActiveState=failed\\nSubState=failed\\nResult=start-limit-hit\\nNRestarts=0" in (
        dark_host_preflight
    )
    assert "the Caddy recovery unit is not in its exact quiescent state" in dark_host_preflight
    assert "systemctl list-jobs --no-legend --plain" in dark_host_preflight
    assert 'caddy.service" || $2 == "caddy-recovery.service"' in dark_host_preflight


@pytest.mark.parametrize("script", [PREFLIGHT, DARK_HOST_PREFLIGHT])
def test_production_preflights_refuse_unknown_recovery_modes(script: Path) -> None:
    result = subprocess.run(  # noqa: S603 -- reviewed absolute repository helper.
        [os.fspath(script), "--unknown-recovery-mode"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"]},
    )

    assert result.returncode == INPUT_ERROR_STATUS
    assert "Usage:" in result.stderr
