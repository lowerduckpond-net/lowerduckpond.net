"""Synthetic operator assembly: no live login, provider access or durable publication."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import connect_setup
from scripts.m3_11_unattended import operator_assemble as assembly
from scripts.m3_11_unattended.config import DO_READ_SCOPES, LeaseConfiguration
from scripts.m3_11_unattended.connect_action import bootstrap
from scripts.m3_11_unattended.connect_auth import claims
from scripts.m3_11_unattended.connect_configuration import reader_access
from scripts.m3_11_unattended.connect_delivery import MAX_SECRET_BYTES
from scripts.m3_11_unattended.model import LifecycleError, digest, instant, stamp

from .test_m3_11_connect_auth import token
from .test_m3_11_connect_setup import independent_reader
from .test_m3_11_lease_configuration import document, mapping

SERVER_SECRET = "SYNTHETIC-INDEPENDENT-MASTER-CANARY"  # noqa: S105 - synthetic test only
EXPECTED_READS = 10
DIRECTORY_MODE, FILE_MODE = 0o700, 0o600


def receipt_fixture() -> tuple[dict[str, object], FakeOperator]:
    """Truthful upper bounds, with no invented historical fingerprint or UI time."""
    manifest, operator = fixture()
    manifest["format"] = "lowerduckpond-m3-11-operator-inputs-v3"
    manifest["runtime_revision"] = "e" * 40
    for raw in mapping(manifest["providers"]).values():
        observation = mapping(mapping(raw)["digitalocean_observation"])
        created, received = observation.pop("token_created_at"), observation.pop("observed_at")
        observation.pop("token_sha256")
        observation["receipt_evidence"] = {
            "basis": "operator-confirmed-replacement",
            "created_no_later_than": created,
            "creation_receipt": "synthetic-created-receipt",
            "scope_confirmation_received_at": received,
            "scope_receipt": "synthetic-scope-receipt",
            "replacement_reference": observation["token_reference"],
            "confirmation_applies_to_replacement": True,
        }
    return manifest, operator


def test_receipt_evidence_needs_no_invented_exact_times_or_historical_hash() -> None:
    manifest, operator = receipt_fixture()
    checked = assembly.validate(manifest, now=datetime.now(UTC))
    assert checked == manifest
    assert not operator.calls


def test_receipt_assembly_uses_one_explicit_runtime_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, operator = receipt_fixture()

    # Checkout inspection is an external process boundary; real binding is tested separately.
    def git(_root: Path, *arguments: str) -> bytes:
        if arguments == ("rev-parse", "HEAD"):
            return str(manifest["runtime_revision"]).encode()
        if arguments == ("rev-parse", "--is-shallow-repository"):
            return b"false"
        if arguments[0] == "show":
            return json.dumps(
                {
                    "format": "lowerduckpond-qualification-revocations-v1",
                    "sources": [],
                    "artifacts": [],
                    "reports": [],
                    "input_digests": [],
                }
            ).encode()
        assert arguments == ("status", "--porcelain", "--untracked-files=all")
        return b""

    monkeypatch.setattr("scripts.production_qualification_inputs.git", git)
    config, _independent, attestations = assembly.documents(
        manifest, cast(connect_setup.Operator, operator)
    )
    assert config["helper_revision"] == manifest["runtime_revision"]
    for role, attestation in attestations.items():
        observation = mapping(
            mapping(mapping(manifest["providers"])[role])["digitalocean_observation"]
        )
        assert "receipt" in str(attestation["principal_context"])
        assert "observed_at" not in observation and "token_sha256" not in observation
        assert (
            attestation["token_sha256"]
            == hashlib.sha256(
                operator.secrets[str(observation["token_reference"])].encode()
            ).hexdigest()
        )


class FakeOperator:
    def __init__(self, manifest: dict[str, object], configured: dict[str, object]) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.expected_account = str(manifest["onepassword_account_id"])
        self.secrets: dict[str, str] = {}
        self.native: dict[str, dict[str, object]] = {}
        for name, raw in configured.items():
            reader = mapping(raw)
            entry, metadata = mapping(reader["entry"]), mapping(reader["metadata"])
            client = mapping(mapping(manifest["clients"])[name])
            self.secrets[str(client["reference"])] = str(entry["token"])
            server = str(entry["server"])
            native = self.native.setdefault(server, {"server": metadata["server"], "tokens": []})
            cast(list[object], native["tokens"]).extend(cast(list[object], metadata["tokens"]))
        for role, raw in mapping(manifest["providers"]).items():
            refs = mapping(mapping(raw)["references"])
            for key in assembly.PROVIDER_KEYS.values():
                self.secrets[str(refs[key])] = "SYNTHETIC-PROVIDER-CANARY-" + role + "-" + key
        self.failure: Exception | None = None

    def command(self, *arguments: str) -> bytes:
        self.calls.append(arguments)
        if self.failure is not None:
            raise self.failure
        assert "--account" in arguments and self.expected_account in arguments
        if arguments[0] == "whoami":
            return b'{"account_uuid":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}'
        if arguments[0] == "read":
            assert arguments[-1] == "--no-newline"
            return self.secrets[arguments[1]].encode()
        if arguments[:3] == ("connect", "server", "get"):
            return json.dumps(self.native[arguments[3]]["server"]).encode()
        assert arguments[:4] == ("connect", "token", "list", "--server")
        return json.dumps(self.native[arguments[4]]["tokens"]).encode()


def fixture() -> tuple[dict[str, object], FakeOperator]:
    original = document()
    generation_id = str(original["active_generation"])
    roles = mapping(mapping(original["generations"])[generation_id])
    configured = {role: mapping(value)["reader"] for role, value in roles.items()}
    configured["production"] = mapping(original["production"])["connect"]
    configured["independent_cleanup"] = independent_reader(str(original["independent_server_id"]))
    first = mapping(mapping(roles["cleanup"])["generation"])
    now = datetime.now(UTC).replace(microsecond=0)
    policy = mapping(original["policy"])
    policy.update(credential_lifetime_seconds=1209600, cleanup_reserve_seconds=604800)
    manifest: dict[str, object] = {
        "format": assembly.FORMAT,
        "purpose": "initial-legacy-migration",
        "onepassword_account_id": "A" * 26,
        "targets": original["targets"],
        "vaults": mapping(configured["cleanup"])["vaults"],
        "shared_url": "https://connect.example.test",
        "shared_server_id": "S" * 26,
        "independent_server_id": original["independent_server_id"],
        "policy": policy,
        "approved_policy_sha256": digest(policy),
        "generation_id": generation_id,
        "introduced_at": first["introduced_at"],
        "rotation_due_at": first["rotation_due_at"],
        "principals": first["principals"],
        "migration_sha256": original["migration_sha256"],
        "clients": {},
        "providers": {},
        "production_references": mapping(original["production"])["references"],
    }
    for index, (name, raw) in enumerate(configured.items()):
        reader = mapping(raw)
        entry = mapping(reader["entry"])
        native = cast(list[dict[str, object]], mapping(reader["metadata"])["tokens"])[0]
        entry["name"] = native["name"] = "synthetic-" + name
        mapping(manifest["clients"])[name] = {
            "reference": f"op://{'o' * 26}/{chr(97 + index) * 26}/password",
            "name": entry["name"],
            "expires_at": entry["expires_at"],
        }
    for role, raw in roles.items():
        existing = mapping(raw)
        scopes = (
            DO_READ_SCOPES
            | {"spaces_key:delete"}
            | ({"spaces_key:create_credentials"} if role == "provision" else set())
        )
        mapping(manifest["providers"])[role] = {
            "references": existing["references"],
            "expires_at": mapping(existing["generation"])["expires_at"],
            "digitalocean_observation": {
                "principal": "synthetic-team-a",
                "scopes": sorted(scopes),
                "observed_at": stamp(now),
                "attested_by": "synthetic-operator",
                "principal_context": "synthetic approved console team",
                "generation_id": generation_id,
                "token_reference": mapping(existing["references"])["digitalocean"],
                "token_sha256": hashlib.sha256(
                    ("SYNTHETIC-PROVIDER-CANARY-" + role + "-digitalocean").encode()
                ).hexdigest(),
                "token_created_at": first["introduced_at"],
            },
        }
    return manifest, FakeOperator(manifest, configured)


def test_assembly_retains_signed_deadline_with_later_native_expiry() -> None:
    manifest, operator = fixture()
    signed_expiries = {}
    for role, raw in mapping(manifest["clients"]).items():
        client = mapping(raw)
        ref = str(client["reference"])
        payload = claims(operator.secrets[ref])
        payload["aud"] = [payload["aud"]]
        expiry = instant(client["expires_at"]) - timedelta(seconds=1)
        payload["exp"] = int(expiry.timestamp())
        operator.secrets[ref] = token({}, payload)
        client["expires_at"] = stamp(expiry)
        signed_expiries[role] = expiry
    config, independent, _attestations = assembly.documents(
        manifest, cast(connect_setup.Operator, operator)
    )
    controller, _github = connect_setup.assemble(config, independent, {"synthetic": SERVER_SECRET})
    parsed = LeaseConfiguration.parse(controller)
    for role, configured in parsed.generations[parsed.active_generation].items():
        assert instant(configured.generation.connect_expires_at) == signed_expiries[role]
    assert parsed.production is not None
    _, production_access = reader_access(parsed.production["connect"])
    assert production_access.expires_at == signed_expiries["production"]
    assert all(
        instant(mapping(raw)["expires_at"]) == signed_expiries[role]
        for role, raw in mapping(manifest["clients"]).items()
    )


def inputs(tmp_path: Path, manifest: dict[str, object]) -> tuple[Path, Path]:
    tmp_path.chmod(0o700)
    source = tmp_path / "manifest.json"
    write_private(source, manifest)
    credentials = tmp_path / "retained-server.json"
    write_private(credentials, {"private-master": SERVER_SECRET})
    return source, credentials


def test_private_assembly_separates_readers_and_leaves_originals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest, operator = fixture()
    source, credentials = inputs(tmp_path, manifest)
    original = source.read_bytes(), credentials.read_bytes()
    monkeypatch.setattr(assembly, "Operator", lambda: operator)
    output = tmp_path / "staged"
    assembly.run(assembly.load_manifest(source), credentials=credentials, output=output)
    controller = LeaseConfiguration.load(output / "controller-connect.json")
    independent_raw = read_private(output / "github-connect.json")
    independent, server = bootstrap(independent_raw, helper=assembly.HELPER)
    assert server == {"private-master": SERVER_SECRET}
    assert independent.mode == "cleanup-only" and independent.production is None
    assert controller.mode == "controller"
    assert SERVER_SECRET not in (output / "controller-connect.json").read_text()
    for name, client in mapping(manifest["clients"]).items():
        token = operator.secrets[str(mapping(client)["reference"])]
        assert (token in (output / "controller-connect.json").read_text()) == (
            name != "independent_cleanup"
        )
        assert (token in (output / "github-connect.json").read_text()) == (
            name == "independent_cleanup"
        )
    for value in operator.secrets.values():
        assert not any(value in argument for call in operator.calls for argument in call)
        if value.startswith("SYNTHETIC-PROVIDER"):
            assert all(value not in path.read_text() for path in output.iterdir())
    assert len([call for call in operator.calls if call[0] == "read"]) == EXPECTED_READS
    assert original == (source.read_bytes(), credentials.read_bytes())
    assert output.stat().st_mode & 0o777 == DIRECTORY_MODE
    assert all(path.stat().st_mode & 0o777 == FILE_MODE for path in output.iterdir())
    assert read_private(output / "assembly-receipt.json")["status"] == "staged-only"
    assert read_private(output / "assembly-receipt.json")["operator_inputs_sha256"] == digest(
        manifest
    )
    for role in ("provision", "cleanup"):
        attestation = read_private(output / (role + "-digitalocean-attestation.json"))
        generation = controller.generations[controller.active_generation][role].generation
        assert attestation["token_sha256"] == generation.fingerprints["spaces"]
        assert attestation["generation_id"] == generation.generation_id
    assert capsys.readouterr() == ("", "")


def test_check_reads_no_credentials_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest, _ = fixture()
    source, _credentials = inputs(tmp_path, manifest)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    monkeypatch.setattr(assembly, "Operator", lambda: pytest.fail("op invoked in check"))
    monkeypatch.setattr(sys, "argv", ["assembler", "check", "--manifest", str(source)])
    assert assembly.main() == 0
    assert "credentials were not read" in capsys.readouterr().out
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir()}


def test_observation_before_token_creation_is_rejected() -> None:
    manifest, _operator = fixture()
    observed = mapping(
        mapping(mapping(manifest["providers"])["cleanup"])["digitalocean_observation"]
    )
    observed["observed_at"] = stamp(instant(manifest["introduced_at"]) - timedelta(seconds=1))
    with pytest.raises(LifecycleError, match="observation"):
        assembly.validate(manifest, now=datetime.now(UTC))


def test_changed_token_cannot_reuse_console_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, operator = fixture()
    refs = mapping(mapping(mapping(manifest["providers"])["cleanup"])["references"])
    operator.secrets[str(refs["digitalocean"])] = "SYNTHETIC-DIFFERENT-TOKEN"
    source, credentials = inputs(tmp_path, manifest)
    output = tmp_path / "staged"
    monkeypatch.setattr(assembly, "Operator", lambda: operator)
    with pytest.raises(LifecycleError, match="observation"):
        assembly.run(assembly.load_manifest(source), credentials=credentials, output=output)
    assert not list(output.iterdir())


@pytest.mark.parametrize("role", ["provision", "cleanup"])
@pytest.mark.parametrize("fault", ["generation", "reference", "future", "missing-hash", "v1"])
def test_observation_provenance_is_checked_without_reading_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, fault: str
) -> None:
    manifest, _operator = fixture()
    observed = mapping(mapping(mapping(manifest["providers"])[role])["digitalocean_observation"])
    if fault == "generation":
        observed["generation_id"] = "0198d17f-6f4a-7000-8000-000000000099"
    elif fault == "reference":
        observed["token_reference"] = str(observed["token_reference"]) + "-old"
    elif fault == "future":
        observed["observed_at"] = stamp(datetime.now(UTC) + timedelta(days=1))
    elif fault == "missing-hash":
        del observed["token_sha256"]
    else:
        manifest["format"] = "lowerduckpond-m3-11-operator-inputs-v1"
    source, _credentials = inputs(tmp_path, manifest)
    monkeypatch.setattr(assembly, "Operator", lambda: pytest.fail("invalid input read credentials"))
    with pytest.raises((LifecycleError, ValueError)):
        assembly.load_manifest(source)


def test_valid_token_observation_remains_usable_when_assembly_is_later(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, operator = fixture()
    now = datetime.now(UTC)
    for role in ("provision", "cleanup"):
        observed = mapping(
            mapping(mapping(manifest["providers"])[role])["digitalocean_observation"]
        )
        observed["token_created_at"] = stamp(now - timedelta(days=8))
        observed["observed_at"] = stamp(now - timedelta(days=7))
    source, credentials = inputs(tmp_path, manifest)
    output = tmp_path / "staged"
    monkeypatch.setattr(assembly, "Operator", lambda: operator)
    assembly.run(assembly.load_manifest(source), credentials=credentials, output=output)
    for role in ("provision", "cleanup"):
        attestation = read_private(output / (role + "-digitalocean-attestation.json"))
        assert attestation["verified_at"] == stamp(now - timedelta(days=7))
    assert read_private(output / "assembly-receipt.json")["status"] == "staged-only"


@pytest.mark.parametrize("fault", ["permissions", "symlink", "hardlink", "duplicate"])
def test_manifest_refuses_unsafe_or_ambiguous_files(tmp_path: Path, fault: str) -> None:
    manifest, _ = fixture()
    source, _ = inputs(tmp_path, manifest)
    if fault == "permissions":
        source.chmod(0o644)
    elif fault == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(source)
        source = link
    elif fault == "hardlink":
        os.link(source, tmp_path / "second.json")
    else:
        source.write_text('{"format": "first", "format": "second"}')
    with pytest.raises((ValueError, RuntimeError, OSError)):
        assembly.load_manifest(source)


@pytest.mark.parametrize("fault", ["runtime-vault", "account", "expiry", "grant", "provider-reuse"])
def test_wrong_access_never_produces_ready_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    manifest, operator = fixture()
    if fault == "runtime-vault":
        mapping(mapping(manifest["clients"])["provision"])["reference"] = (
            f"op://{'v' * 26}/{'i' * 26}/password"
        )
    elif fault == "account":
        manifest["onepassword_account_id"] = "B" * 26
        operator.expected_account = "B" * 26
    elif fault in {"expiry", "grant"}:
        native = cast(list[dict[str, object]], operator.native["S" * 26]["tokens"])[0]
        if fault == "expiry":
            native["expires_at"] = "2026-01-01T00:00:00Z"
        else:
            native["vaults"] = []
    else:
        roles = mapping(manifest["providers"])
        refs = [mapping(mapping(roles[role])["references"]) for role in ("provision", "cleanup")]
        operator.secrets[str(refs[1]["digitalocean"])] = operator.secrets[
            str(refs[0]["digitalocean"])
        ]
    source, credentials = inputs(tmp_path, manifest)
    monkeypatch.setattr(assembly, "Operator", lambda: operator)
    output = tmp_path / "staged"
    with pytest.raises((ValueError, RuntimeError)):
        assembly.run(assembly.load_manifest(source), credentials=credentials, output=output)
    assert not (output / "assembly-receipt.json").exists()
    assert not (output / "controller-connect.json").exists()


@pytest.mark.parametrize(
    "failure",
    [RuntimeError(SERVER_SECRET), UnicodeError(SERVER_SECRET), KeyboardInterrupt(SERVER_SECRET)],
)
def test_cli_sanitizes_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: BaseException,
) -> None:
    manifest, _ = fixture()
    source, credentials = inputs(tmp_path, manifest)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(assembly, "run", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "assembler",
            "assemble",
            "--manifest",
            str(source),
            "--server-credentials",
            str(credentials),
            "--output",
            str(tmp_path / "new"),
        ],
    )
    assert assembly.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert SERVER_SECRET not in captured.err and "Traceback" not in captured.err
    assert "retain original access" in captured.err


def test_existing_destination_is_never_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, _ = fixture()
    source, credentials = inputs(tmp_path, manifest)
    output = tmp_path / "staged"
    output.mkdir(mode=0o700)
    retained = output / "original"
    retained.write_text(SERVER_SECRET)
    monkeypatch.setattr(
        assembly, "Operator", lambda: pytest.fail("read before destination refusal")
    )
    with pytest.raises(LifecycleError):
        assembly.run(assembly.load_manifest(source), credentials=credentials, output=output)
    assert retained.read_text() == SERVER_SECRET


def test_native_failure_output_and_automation_auth_never_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda *_args, **_kwargs: "/synthetic/op")

    def fail(_argv: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        environment = cast(dict[str, str], kwargs["env"])
        assert (
            not {"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN"}
            & environment.keys()
        )
        assert kwargs["capture_output"] is True and kwargs["check"] is False
        return subprocess.CompletedProcess(
            ["op"], 1, SERVER_SECRET.encode(), SERVER_SECRET.encode()
        )

    monkeypatch.setattr(subprocess, "run", fail)
    operator = connect_setup.Operator(
        environment={
            "PATH": "/synthetic",
            "OP_SERVICE_ACCOUNT_TOKEN": SERVER_SECRET,
            "OP_CONNECT_HOST": SERVER_SECRET,
            "OP_CONNECT_TOKEN": SERVER_SECRET,
        }
    )
    with pytest.raises(LifecycleError) as error:
        operator.command("read", "op://metadata-only/reference/password")
    assert SERVER_SECRET not in str(error.value)


def test_example_declares_unknowns_instead_of_fabricating_expiries() -> None:
    path = assembly.ROOT / "docs/operations/m3-11-operator-inputs.example.json"
    raw = json.loads(path.read_text())
    with pytest.raises((ValueError, RuntimeError)):
        assembly.validate(raw, now=datetime.now(UTC))
    for role in ("provision", "cleanup"):
        expiries = raw["providers"][role]["expires_at"]
        assert expiries["spaces"] == (
            "<approved UTC operational cutoff; record native expiry precision in principal_context>"
        )
        for provider in ("cloudflare-account", "cloudflare-user"):
            assert expiries[provider] == "<exact native UTC expiry>"


def test_cli_native_boundary_success_is_silent_about_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest, fake = fixture()
    source, credentials = inputs(tmp_path, manifest)
    output = tmp_path / "staged"
    monkeypatch.setattr(shutil, "which", lambda *_args, **_kwargs: "/synthetic/op")

    def native(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[0] == "/synthetic/op" and kwargs["capture_output"] is True
        return subprocess.CompletedProcess(argv, 0, fake.command(*argv[1:]), b"")

    monkeypatch.setattr(subprocess, "run", native)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "assembler",
            "assemble",
            "--manifest",
            str(source),
            "--server-credentials",
            str(credentials),
            "--output",
            str(output),
        ],
    )
    assert assembly.main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "staged only" in captured.out
    assert all(secret not in captured.out for secret in [SERVER_SECRET, *fake.secrets.values()])
    assert not (output / "activation.json").exists()


def test_partial_write_is_retained_without_success_receipt_or_secret_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest, fake = fixture()
    source, credentials = inputs(tmp_path, manifest)
    output = tmp_path / "staged"
    monkeypatch.setattr(assembly, "Operator", lambda: fake)

    def interrupted(_path: Path, _value: object) -> None:
        raise OSError(SERVER_SECRET)

    monkeypatch.setattr(assembly, "write_private", interrupted)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "assembler",
            "assemble",
            "--manifest",
            str(source),
            "--server-credentials",
            str(credentials),
            "--output",
            str(output),
        ],
    )
    assert assembly.main() == 1
    assert (output / "controller-connect.json").exists()
    assert (output / "github-connect.json").exists()
    assert not (output / "assembly-receipt.json").exists()
    captured = capsys.readouterr()
    assert SERVER_SECRET not in captured.err and captured.out == ""
    assert read_private(credentials) == {"private-master": SERVER_SECRET}


@pytest.mark.parametrize(
    "fault",
    [
        "public-parent",
        "linked-parent",
        "public-credentials",
        "linked-credentials",
        "metadata-alias",
    ],
)
def test_unsafe_local_inputs_fail_before_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    manifest, _ = fixture()
    source, credentials = inputs(tmp_path, manifest)
    output = tmp_path / "staged"
    if fault == "public-parent":
        tmp_path.chmod(0o755)
    elif fault == "linked-parent":
        link = tmp_path / "linked"
        link.symlink_to(tmp_path, target_is_directory=True)
        output = link / "staged"
    elif fault == "public-credentials":
        credentials.chmod(0o644)
    elif fault == "linked-credentials":
        link = tmp_path / "credentials-link"
        link.symlink_to(credentials)
        credentials = link
    else:
        refs = mapping(mapping(mapping(manifest["providers"])["cleanup"])["references"])
        refs["digitalocean_metadata"] = refs["digitalocean"]
        source.write_text(json.dumps(manifest))
    monkeypatch.setattr(assembly, "Operator", lambda: pytest.fail("op read unsafe local input"))
    with pytest.raises((ValueError, RuntimeError, OSError)):
        assembly.run(assembly.load_manifest(source), credentials=credentials, output=output)


def test_oversized_independent_bundle_cannot_be_reported_as_staged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, fake = fixture()
    source, credentials = inputs(tmp_path, manifest)
    credentials.write_text(json.dumps({"private-master": "x" * MAX_SECRET_BYTES}))
    output = tmp_path / "staged"
    monkeypatch.setattr(assembly, "Operator", lambda: fake)
    with pytest.raises(LifecycleError, match="delivery limit"):
        assembly.run(assembly.load_manifest(source), credentials=credentials, output=output)
    assert not list(output.iterdir())


@pytest.mark.parametrize("failure", ["timeout", "oversize", "invalid-secret"])
def test_native_errors_never_print_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    manifest, fake = fixture()
    source, credentials = inputs(tmp_path, manifest)
    monkeypatch.setattr(shutil, "which", lambda *_args, **_kwargs: "/synthetic/op")

    def native(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if argv[1] != "read":
            return subprocess.CompletedProcess(argv, 0, fake.command(*argv[1:]), b"")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, 90, output=SERVER_SECRET, stderr=SERVER_SECRET)
        raw = SERVER_SECRET.encode() * (100000 if failure == "oversize" else 1) + b"\x00"
        return subprocess.CompletedProcess(argv, 0, raw, SERVER_SECRET.encode())

    monkeypatch.setattr(subprocess, "run", native)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "assembler",
            "assemble",
            "--manifest",
            str(source),
            "--server-credentials",
            str(credentials),
            "--output",
            str(tmp_path / "new"),
        ],
    )
    assert assembly.main() == 1
    captured = capsys.readouterr()
    assert captured.out == "" and SERVER_SECRET not in captured.err
    assert "Traceback" not in captured.err
