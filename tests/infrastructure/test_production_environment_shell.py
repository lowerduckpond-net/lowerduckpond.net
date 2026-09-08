from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
ENVIRONMENT_SHELL = (REPOSITORY_ROOT / "scripts/production-environment-shell").resolve()
CONTRACT_NAMES = (
    "ADMIN_SOURCE_CIDRS_JSON",
    "ANSIBLE_PRIVATE_KEY_FILE",
    "CADDY_CLOUDFLARE_API_TOKEN",
    "CADDY_ORIGIN_PULL_CA_PATHS_JSON",
    "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED",
    "OPENTOFU_ENCRYPTION_PASSPHRASE",
    "OPENTOFU_STATE_ACCESS_KEY_ID",
    "OPENTOFU_STATE_BUCKET",
    "OPENTOFU_STATE_SECRET_ACCESS_KEY",
    "RESTIC_PASSWORD",
    "SPACES_REGION",
    "STATIC_OPERATOR_PRINCIPAL",
    "STATIC_OPERATOR_PUBLIC_KEY",
)
INPUT_ERROR_STATUS = 2
INTERRUPTED_STATUS = 130
BASH = "/usr/bin/bash"


def complete_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "ADMIN_SOURCE_CIDRS_JSON": '["192.0.2.1/32"]',
            "ANSIBLE_PRIVATE_KEY_FILE": "/private/admin-key",
            "CADDY_CLOUDFLARE_API_TOKEN": "caddy-secret-value",
            "CADDY_ORIGIN_PULL_CA_PATHS_JSON": '["/private/ca.pem"]',
            "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED": "false",
            "OPENTOFU_ENCRYPTION_PASSPHRASE": "state-passphrase-value",
            "OPENTOFU_STATE_ACCESS_KEY_ID": "state-access-key-value",
            "OPENTOFU_STATE_BUCKET": "production-state-bucket",
            "OPENTOFU_STATE_SECRET_ACCESS_KEY": "state-secret-key-value",
            "RESTIC_PASSWORD": "restic-password-value",
            "SPACES_REGION": "nyc3",
            "STATIC_OPERATOR_PRINCIPAL": "production-static-operator",
            "STATIC_OPERATOR_PUBLIC_KEY": "ssh-ed25519 test-only-public-key",
        }
    )
    return environment


def scrub_contract(environment: dict[str, str]) -> dict[str, str]:
    for name in CONTRACT_NAMES:
        environment.pop(name, None)
    return environment


def test_complete_contract_is_available_only_to_the_child_command() -> None:
    environment = complete_environment()
    command = (
        "import json, os, pathlib; "
        "print(json.dumps({name: os.environ[name] for name in "
        + repr(CONTRACT_NAMES)
        + "}, sort_keys=True)); "
        "print(pathlib.Path.cwd())"
    )

    result = subprocess.run(  # noqa: S603 -- fixed reviewed repository helper.
        [os.fspath(ENVIRONMENT_SHELL), "--", sys.executable, "-c", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert '"CADDY_CLOUDFLARE_API_TOKEN": "caddy-secret-value"' in result.stdout
    assert result.stdout.rstrip().endswith(os.fspath(REPOSITORY_ROOT))


def test_missing_values_are_prompted_without_echoing_secrets(tmp_path: Path) -> None:
    operator_public_key = tmp_path / "operator.pub"
    operator_public_key.write_text("ssh-ed25519 test-only-public-key\n", encoding="ascii")
    answers = "\n".join(
        (
            "/private/admin-key",
            '["192.0.2.1/32"]',
            "caddy-secret-value",
            "false",
            "/private/ca.pem",
            "",
            "state-access-key-value",
            "state-secret-key-value",
            "state-passphrase-value",
            "production-state-bucket",
            "restic-password-value",
            "",
            "",
            os.fspath(operator_public_key),
            "",
        )
    )
    assertion = """
        [[ ${ADMIN_SOURCE_CIDRS_JSON} == '["192.0.2.1/32"]' ]]
        [[ ${CADDY_ORIGIN_PULL_CA_PATHS_JSON} == '["/private/ca.pem"]' ]]
        [[ ${SPACES_REGION} == nyc3 ]]
        [[ ${STATIC_OPERATOR_PRINCIPAL} == production-static-operator ]]
        [[ ${STATIC_OPERATOR_PUBLIC_KEY} == 'ssh-ed25519 test-only-public-key' ]]
        printf 'child-contract: PASS\\n'
    """

    result = subprocess.run(  # noqa: S603 -- fixed reviewed repository helper.
        [os.fspath(ENVIRONMENT_SHELL), "--", "bash", "-c", assertion],
        input=answers,
        check=False,
        capture_output=True,
        text=True,
        env=scrub_contract(os.environ.copy()),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "child-contract: PASS\n"
    for secret in (
        "caddy-secret-value",
        "state-access-key-value",
        "state-secret-key-value",
        "state-passphrase-value",
        "restic-password-value",
    ):
        assert secret not in result.stderr


def test_incomplete_prompt_fails_without_running_the_child() -> None:
    result = subprocess.run(  # noqa: S603 -- fixed reviewed repository helper.
        [os.fspath(ENVIRONMENT_SHELL), "--", "bash", "-c", "exit 99"],
        input="/private/admin-key\n",
        check=False,
        capture_output=True,
        text=True,
        env=scrub_contract(os.environ.copy()),
    )

    assert result.returncode == INTERRUPTED_STATUS
    assert "interrupted or incomplete" in result.stderr


@pytest.mark.parametrize("value", ["", "yes", "False", "0"])
def test_enforcement_requires_an_explicit_boolean(value: str) -> None:
    environment = complete_environment()
    environment["CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED"] = value
    standard_input = "" if value else "\n"

    result = subprocess.run(  # noqa: S603 -- fixed reviewed repository helper.
        [os.fspath(ENVIRONMENT_SHELL), "--", "true"],
        input=standard_input,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == INPUT_ERROR_STATUS
    assert "must be exactly true or false" in result.stderr


def test_public_key_file_read_is_bounded(tmp_path: Path) -> None:
    oversized_key = tmp_path / "operator.pub"
    oversized_key.write_bytes(b"x" * 1025)
    environment = complete_environment()
    environment.pop("STATIC_OPERATOR_PUBLIC_KEY")

    result = subprocess.run(  # noqa: S603 -- fixed reviewed repository helper.
        [os.fspath(ENVIRONMENT_SHELL), "--", "true"],
        input=f"{oversized_key}\n",
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == INPUT_ERROR_STATUS
    assert "unsafe size" in result.stderr


def test_xtrace_is_disabled_before_secrets_are_read() -> None:
    environment = complete_environment()

    result = subprocess.run(  # noqa: S603 -- fixed reviewed shell and helper.
        [BASH, "-x", os.fspath(ENVIRONMENT_SHELL), "--", "true"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert "caddy-secret-value" not in result.stderr
    assert "state-secret-key-value" not in result.stderr
