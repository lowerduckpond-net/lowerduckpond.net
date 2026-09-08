from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
LOADER = (REPOSITORY_ROOT / "scripts/load-production-environment").resolve()
CONFIGURE = (REPOSITORY_ROOT / "scripts/configure-production").resolve()
BASH = shutil.which("bash")
OPENSSL = "/usr/bin/openssl"
SSH_KEYGEN = shutil.which("ssh-keygen")
INPUT_ERROR_STATUS = 2
USAGE_ERROR_STATUS = 64

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


def _create_key(
    tmp_path: Path,
    name: str,
    *,
    encrypted: bool = True,
) -> tuple[Path, Path]:
    assert SSH_KEYGEN is not None
    private_key = tmp_path / name
    result = subprocess.run(  # noqa: S603 -- fixed test-only key generator.
        [
            SSH_KEYGEN,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "test-" + "passphrase" if encrypted else "",
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
    return private_key, private_key.with_suffix(".pub")


def _create_ca(tmp_path: Path) -> Path:
    ca_key = tmp_path / "production-origin-pull-ca.key"
    ca_path = tmp_path / "production-origin-pull-ca.pem"
    result = subprocess.run(  # noqa: S603 -- fixed test-only OpenSSL executable.
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1825",
            "-subj",
            "/CN=production-loader-test-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            os.fspath(ca_key),
            "-out",
            os.fspath(ca_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return ca_path


def _fixture_environment(tmp_path: Path) -> dict[str, str]:
    admin_key, _ = _create_key(tmp_path, "admin")
    _, operator_public_key_path = _create_key(tmp_path, "operator")
    ca_path = _create_ca(tmp_path)
    return {
        "ADMIN_SOURCE_CIDRS_JSON": '["192.0.2.10/32"]',
        "ANSIBLE_PRIVATE_KEY_FILE": os.fspath(admin_key),
        "CADDY_CLOUDFLARE_API_TOKEN": "caddy-token-with-valid-shape-0001",
        "CADDY_ORIGIN_PULL_CA_PATHS_JSON": json.dumps([os.fspath(ca_path)]),
        "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED": "true",
        "OPENTOFU_ENCRYPTION_PASSPHRASE": "state-passphrase-test-only-00000000",
        "OPENTOFU_STATE_ACCESS_KEY_ID": "state-access-key-test-only",
        "OPENTOFU_STATE_BUCKET": "production-state-test-bucket",
        "OPENTOFU_STATE_SECRET_ACCESS_KEY": "state-secret-key-test-only",
        "RESTIC_PASSWORD": "restic-password-test-only-0000000000",
        "SPACES_REGION": "nyc3",
        "STATIC_OPERATOR_PRINCIPAL": "production-static-operator",
        "STATIC_OPERATOR_PUBLIC_KEY": operator_public_key_path.read_text(encoding="ascii").strip(),
    }


def _source_loader(
    environment: dict[str, str],
    *,
    standard_input: str = "",
    command: str = 'source "$1"; loader_status=$?; printf "status=%s\\n" "$loader_status"',
) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    return subprocess.run(  # noqa: S603 -- fixed Bash and reviewed repository helper.
        [BASH, "-c", command, "bash", os.fspath(LOADER)],
        input=standard_input,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_loader_must_be_sourced() -> None:
    result = subprocess.run(  # noqa: S603 -- reviewed absolute repository helper.
        [os.fspath(LOADER)],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"]},
    )

    assert result.returncode == USAGE_ERROR_STATUS
    assert result.stdout == ""
    assert result.stderr == ("Source this helper: source scripts/load-production-environment\n")


def test_loader_contract_matches_production_convergence() -> None:
    configure = CONFIGURE.read_text(encoding="utf-8")
    match = re.search(r"required_environment=\(\n(?P<body>.*?)\n\)", configure, re.DOTALL)

    assert match is not None
    assert tuple(match.group("body").split()) == CONTRACT_NAMES


def test_loader_reuses_a_complete_valid_environment(tmp_path: Path) -> None:
    contract = _fixture_environment(tmp_path)
    environment = {"PATH": os.environ["PATH"], **contract}
    print_contract = """
source "$1"
loader_status=$?
printf 'status=%s\\n' "$loader_status"
for name in ${CONTRACT_NAMES}; do
    printf '%s=%s\\n' "$name" "${!name}"
done
""".replace("${CONTRACT_NAMES}", " ".join(CONTRACT_NAMES))

    result = _source_loader(environment, command=print_contract)

    assert result.returncode == 0, result.stderr
    assert "status=0\n" in result.stdout
    for name, value in contract.items():
        assert f"{name}={value}\n" in result.stdout


def test_loader_prompts_for_missing_values_and_derives_file_inputs(tmp_path: Path) -> None:
    contract = _fixture_environment(tmp_path)
    admin_key = contract["ANSIBLE_PRIVATE_KEY_FILE"]
    ca_path = json.loads(contract["CADDY_ORIGIN_PULL_CA_PATHS_JSON"])[0]
    _, operator_public_key_path = _create_key(tmp_path, "prompted-operator")
    secrets = (
        contract["CADDY_CLOUDFLARE_API_TOKEN"],
        contract["OPENTOFU_STATE_ACCESS_KEY_ID"],
        contract["OPENTOFU_STATE_SECRET_ACCESS_KEY"],
        contract["OPENTOFU_ENCRYPTION_PASSPHRASE"],
        contract["RESTIC_PASSWORD"],
    )
    answers = "\n".join(
        (
            admin_key,
            contract["ADMIN_SOURCE_CIDRS_JSON"],
            contract["CADDY_CLOUDFLARE_API_TOKEN"],
            "true",
            ca_path,
            "",
            contract["OPENTOFU_STATE_ACCESS_KEY_ID"],
            contract["OPENTOFU_STATE_SECRET_ACCESS_KEY"],
            contract["OPENTOFU_ENCRYPTION_PASSPHRASE"],
            contract["OPENTOFU_STATE_BUCKET"],
            contract["RESTIC_PASSWORD"],
            "",
            "",
            os.fspath(operator_public_key_path),
            "",
        )
    )
    inspect_derived_values = """
source "$1"
loader_status=$?
printf 'status=%s\\n' "$loader_status"
printf 'enforcement=%s\\n' "$CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED"
printf 'region=%s\\n' "$SPACES_REGION"
printf 'principal=%s\\n' "$STATIC_OPERATOR_PRINCIPAL"
printf 'ca=%s\\n' "$CADDY_ORIGIN_PULL_CA_PATHS_JSON"
"""

    result = _source_loader(
        {"PATH": os.environ["PATH"]},
        standard_input=answers,
        command=inspect_derived_values,
    )

    assert result.returncode == 0, result.stderr
    assert "status=0\n" in result.stdout
    assert "enforcement=true\n" in result.stdout
    assert "region=nyc3\n" in result.stdout
    assert "principal=production-static-operator\n" in result.stdout
    assert f"ca={json.dumps([ca_path], separators=(',', ':'))}\n" in result.stdout
    for secret in secrets:
        assert secret not in result.stdout
        assert secret not in result.stderr


def test_loader_suspends_xtrace_while_handling_the_contract(tmp_path: Path) -> None:
    contract = _fixture_environment(tmp_path)
    environment = {"PATH": os.environ["PATH"], **contract}
    command = """
set -x
source "$1"
loader_status=$?
case $- in
    *x*) xtrace_status=on ;;
    *) xtrace_status=off ;;
esac
set +x
printf 'status=%s xtrace=%s\n' "$loader_status" "$xtrace_status"
"""

    result = _source_loader(environment, command=command)

    assert result.returncode == 0, result.stderr
    assert "status=0 xtrace=on\n" in result.stdout
    for name in (
        "ADMIN_SOURCE_CIDRS_JSON",
        "CADDY_CLOUDFLARE_API_TOKEN",
        "OPENTOFU_ENCRYPTION_PASSPHRASE",
        "OPENTOFU_STATE_ACCESS_KEY_ID",
        "OPENTOFU_STATE_SECRET_ACCESS_KEY",
        "RESTIC_PASSWORD",
    ):
        assert contract[name] not in result.stdout
        assert contract[name] not in result.stderr


@pytest.mark.parametrize(
    "cidrs",
    [
        '["0.0.0.0/0"]',
        '["::/0"]',
        '["not-a-cidr"]',
        '["192.0.2.10/24"]',
        '["192.0.2.10/32", "192.0.2.10/32"]',
    ],
)
def test_loader_refuses_unsafe_administrative_source_cidrs(
    tmp_path: Path,
    cidrs: str,
) -> None:
    contract = _fixture_environment(tmp_path)
    contract["ADMIN_SOURCE_CIDRS_JSON"] = cidrs

    result = _source_loader({"PATH": os.environ["PATH"], **contract})

    assert result.returncode == 0
    assert result.stdout == "status=2\n"
    assert "Production environment input validation failed" in result.stderr


def test_loader_refuses_a_non_certificate_ca_file(tmp_path: Path) -> None:
    contract = _fixture_environment(tmp_path)
    invalid_ca = tmp_path / "not-a-ca.pem"
    invalid_ca.write_text("not a certificate\n", encoding="ascii")
    contract["CADDY_ORIGIN_PULL_CA_PATHS_JSON"] = json.dumps([os.fspath(invalid_ca)])

    result = _source_loader({"PATH": os.environ["PATH"], **contract})

    assert result.returncode == 0
    assert result.stdout == "status=2\n"
    assert "failed the production certificate policy" in result.stderr


def test_loader_refuses_duplicate_ca_certificate_identities(tmp_path: Path) -> None:
    contract = _fixture_environment(tmp_path)
    original_ca = Path(json.loads(contract["CADDY_ORIGIN_PULL_CA_PATHS_JSON"])[0])
    duplicate_ca = tmp_path / "duplicate-ca.pem"
    original_pem = original_ca.read_bytes()
    duplicate_ca.write_bytes(original_pem + b"\n")
    assert duplicate_ca.read_bytes() != original_pem
    contract["CADDY_ORIGIN_PULL_CA_PATHS_JSON"] = json.dumps(
        [os.fspath(original_ca), os.fspath(duplicate_ca)]
    )

    result = _source_loader({"PATH": os.environ["PATH"], **contract})

    assert result.returncode == 0
    assert result.stdout == "status=2\n"
    assert "origin-pull CA certificates must be distinct" in result.stderr


def test_loader_refuses_an_administrative_public_key_path(tmp_path: Path) -> None:
    contract = _fixture_environment(tmp_path)
    _, admin_public_key = _create_key(tmp_path, "wrong-admin-input")
    contract["ANSIBLE_PRIVATE_KEY_FILE"] = os.fspath(admin_public_key)

    result = _source_loader({"PATH": os.environ["PATH"], **contract})

    assert result.returncode == 0
    assert result.stdout == "status=2\n"
    assert "does not contain private-key material" in result.stderr


def test_loader_requires_an_explicit_origin_pull_enforcement_choice(tmp_path: Path) -> None:
    contract = _fixture_environment(tmp_path)
    contract.pop("CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED")

    result = _source_loader(
        {"PATH": os.environ["PATH"], **contract},
        standard_input="\n",
    )

    assert result.returncode == 0
    assert result.stdout == "status=2\n"
    assert "exactly true or false" in result.stderr


@pytest.mark.parametrize(
    ("name", "value", "error"),
    [
        ("CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED", "yes", "exactly true or false"),
        ("OPENTOFU_ENCRYPTION_PASSPHRASE", "short", "at least 32"),
        ("SPACES_REGION", "sfo3", "exactly nyc3"),
        ("RESTIC_PASSWORD", "short", "at least 32"),
    ],
)
def test_loader_returns_without_terminating_the_shell_or_partially_exporting(
    tmp_path: Path,
    name: str,
    value: str,
    error: str,
) -> None:
    contract = _fixture_environment(tmp_path)
    contract[name] = value
    environment = {"PATH": os.environ["PATH"], **contract}
    environment.pop("ADMIN_SOURCE_CIDRS_JSON")
    command = """
source "$1"
loader_status=$?
printf 'after-source=%s\\n' "$loader_status"
if [[ -v ADMIN_SOURCE_CIDRS_JSON ]]; then
    printf 'partial-export=yes\\n'
else
    printf 'partial-export=no\\n'
fi
"""

    result = _source_loader(
        environment,
        standard_input='["192.0.2.10/32"]\n',
        command=command,
    )

    assert result.returncode == 0
    assert result.stdout == "after-source=2\npartial-export=no\n"
    assert error in result.stderr
