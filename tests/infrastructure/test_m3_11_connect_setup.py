"""Bootstrap setup must be scoped, resumable, private and free of provider calls."""

# ruff: noqa: PLR2004 - explicit security boundary counts and modes

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import connect_setup as setup
from scripts.m3_11_unattended.model import LifecycleError
from scripts.m3_11_unattended.production import REFERENCES

CANARY = "connect-setup-secret-canary"
VAULTS = {"provision": "a" * 26, "cleanup": "b" * 26, "production": "c" * 26, "journal": "d" * 26}
SERVERS = {"shared": "s" * 26, "cleanup": "i" * 26}


def manifest() -> dict[str, object]:
    refs = {key: f"op://{VAULTS[key]}/{'e' * 26}/credential" for key in VAULTS}
    return {
        "format": "lowerduckpond-m3-11-setup-v1",
        "targets": {
            "region": "nyc3",
            "archive_bucket": "test-archive",
            "backup_bucket": "test-backup",
            "account_id": "1" * 32,
            "zone_id": "2" * 32,
            "tenant_zone_id": "3" * 32,
            "user_id": "4" * 32,
        },
        "journal_vault": VAULTS["journal"],
        **{
            role: dict.fromkeys(
                ("digitalocean", "digitalocean_metadata", "cloudflare_account", "cloudflare_user"),
                refs[role],
            )
            for role in ("provision", "cleanup")
        },
        "production": {"references": dict.fromkeys(REFERENCES, refs["production"])},
    }


def jwt(identifier: str, *, delta: timedelta = timedelta(days=7)) -> str:
    claim = {"jti": identifier, "exp": int((datetime.now(UTC) + delta).timestamp())}
    body = base64.urlsafe_b64encode(json.dumps(claim).encode()).decode().rstrip("=")
    return "header." + body + "." + CANARY


class Operator(setup.Operator):
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.tokens = 0
        self.servers = 0
        self.fail_role: str | None = None
        self.fail_server = False
        self.token_delta = timedelta(days=7)

    def command(self, *arguments: str, cwd: Path | None = None) -> bytes:
        self.calls.append(arguments)
        if arguments[:3] == ("connect", "server", "get"):
            selected = "shared" if arguments[3] in ("shared", SERVERS["shared"]) else "cleanup"
            return json.dumps({"id": SERVERS[selected]}).encode()
        if arguments[:3] == ("connect", "server", "create"):
            assert cwd is not None
            assert (cwd / "creation-intent.json").is_file()
            self.servers += 1
            if self.fail_server:
                raise LifecycleError("injected server failure")
            write_private(cwd / "1password-credentials.json", {"server-secret": CANARY})
            return b'{"id":"independent-server"}'
        if arguments[:3] == ("connect", "token", "create"):
            self.tokens += 1
            if self.fail_role is not None and arguments[3].endswith(self.fail_role):
                raise LifecycleError("injected token response loss")
            return jwt(arguments[3], delta=self.token_delta).encode()
        return b"[]"


def run(operator: Operator, root: Path, value: dict[str, object] | None = None) -> None:
    setup.prepare(
        operator,
        manifest() if value is None else value,
        url="https://connect.example.test",
        server="shared",
        output=root,
    )


def test_roles_independent_identity_and_private_outputs(tmp_path: Path) -> None:
    operator = Operator()
    run(operator, tmp_path)
    controller = read_private(tmp_path / "controller-connect.json")
    cleanup = read_private(tmp_path / "github-connect.json")
    assert operator.tokens == 4
    assert operator.servers == 1
    assert CANARY not in json.dumps(controller["manifest"])
    assert "production" not in cleanup
    assert "OPENTOFU_ENCRYPTION_PASSPHRASE" not in json.dumps(cleanup)
    assert VAULTS["provision"] not in json.dumps(cleanup)
    assert VAULTS["production"] not in json.dumps(cleanup)
    creates = [call for call in operator.calls if call[:3] == ("connect", "token", "create")]
    assert all("--expires-in=7d" in call for call in creates)
    assert [part for part in creates[2] if part.endswith(",r")] == [VAULTS["production"] + ",r"]
    assert not any(part.endswith(",rw") for part in creates[2])
    independent_grants = [
        call[-1]
        for call in operator.calls
        if call[:3] == ("connect", "vault", "grant") and call[4] != SERVERS["shared"]
    ]
    assert set(independent_grants) == {VAULTS["cleanup"], VAULTS["journal"]}
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in tmp_path.rglob("*.json"))
    assert all(
        "digitalocean.com" not in str(call) and "cloudflare.com" not in str(call)
        for call in operator.calls
    )


def test_successful_setup_resumes_without_issuing_more_credentials(tmp_path: Path) -> None:
    operator = Operator()
    run(operator, tmp_path)
    before = {path: path.read_bytes() for path in tmp_path.rglob("*.json")}
    run(operator, tmp_path)
    assert operator.tokens == 4
    assert operator.servers == 1
    assert all(path.read_bytes() == original for path, original in before.items())


def test_native_uppercase_server_identity_is_pinned_and_reused_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Native op 2.33.0 server metadata reported by the operator: id is an
    # uppercase 26-character string; metadata keys differ from vault records.
    monkeypatch.setitem(SERVERS, "shared", "S" * 26)
    monkeypatch.setitem(SERVERS, "cleanup", "I" * 26)
    operator = Operator()
    run(operator, tmp_path)
    run(operator, tmp_path)
    assert read_private(tmp_path / "shared.server-identity.json")["id"] == "S" * 26
    assert read_private(tmp_path / "provision.token.json")["server"] == "S" * 26
    assert read_private(tmp_path / "github-cleanup.token.json")["server"] == "I" * 26
    assert operator.tokens == 4
    assert operator.servers == 1
    assert ("connect", "server", "get", "S" * 26, "--format=json") in operator.calls


def test_lost_response_reconciles_exact_intent_without_recreating(tmp_path: Path) -> None:
    operator = Operator()
    operator.fail_role = "cleanup"
    with pytest.raises(LifecycleError, match="response loss"):
        run(operator, tmp_path)
    assert operator.tokens == 2
    assert read_private(tmp_path / "cleanup.intent.json")["grants"] == [
        VAULTS["cleanup"] + ",r",
        VAULTS["journal"] + ",rw",
    ]
    operator.fail_role = None
    with pytest.raises(LifecycleError, match="reconciliation"):
        run(operator, tmp_path)
    assert operator.tokens == 2
    assert list(tmp_path.glob("cleanup.reconciliation-*.json"))


def test_interrupted_independent_server_preserves_other_tokens(tmp_path: Path) -> None:
    operator = Operator()
    operator.fail_server = True
    with pytest.raises(LifecycleError, match="server failure"):
        run(operator, tmp_path)
    operator.fail_server = False
    with pytest.raises(LifecycleError, match="unresolved"):
        run(operator, tmp_path)
    assert operator.servers == 1
    assert operator.tokens == 3


def test_bad_lifetime_retains_returned_token_and_intent(tmp_path: Path) -> None:
    operator = Operator()
    operator.token_delta = timedelta(days=90)
    with pytest.raises(LifecycleError, match="lifetime"):
        run(operator, tmp_path)
    assert (tmp_path / "provision.intent.json").is_file()
    assert CANARY in str(read_private(tmp_path / "provision.token.json")["token"])
    with pytest.raises(LifecycleError, match="lifetime"):
        run(operator, tmp_path)
    assert operator.tokens == 1


def test_changed_setup_inputs_fail_before_any_grant(tmp_path: Path) -> None:
    operator = Operator()
    run(operator, tmp_path)
    before = len(operator.calls)
    changed = manifest() | {"journal_vault": "f" * 26}
    with pytest.raises(LifecycleError, match="inputs changed"):
        run(operator, tmp_path, changed)
    assert len(operator.calls) == before


@pytest.mark.parametrize(
    "url",
    [
        "http://connect.test",
        "https://token@connect.test",
        "https://connect.test/path",
        "https://connect.test?token=x",
    ],
)
def test_unsafe_endpoint_is_rejected_before_setup(tmp_path: Path, url: str) -> None:
    with pytest.raises(LifecycleError, match="HTTPS"):
        setup.prepare(Operator(), manifest(), url=url, server="shared", output=tmp_path)


def test_normal_operator_auth_does_not_inherit_service_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: "/example/op")
    op = setup.Operator(
        environment={
            "PATH": os.environ["PATH"],
            "OP_SERVICE_ACCOUNT_TOKEN": CANARY,
            "OP_CONNECT_HOST": "https://other.test",
            "OP_CONNECT_TOKEN": CANARY,
        }
    )
    assert not any(key.startswith("OP_") for key in op.environment)


@pytest.mark.parametrize("claims", [[], None, {"exp": True}, {"exp": "tomorrow"}, {"exp": -1}])
def test_malformed_or_expired_native_claims_fail_closed(claims: object) -> None:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    with pytest.raises(LifecycleError):
        setup.token_receipt("header." + body + "." + CANARY, now=datetime.now(UTC))


def test_op_diagnostics_do_not_expose_failed_cli_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: "/example/op")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: subprocess.CompletedProcess(
            args=[], returncode=1, stdout=CANARY.encode(), stderr=CANARY.encode()
        ),
    )
    with pytest.raises(LifecycleError) as caught:
        setup.Operator().command("connect", "token", "list", "--server", "test")
    assert CANARY not in str(caught.value)
    assert CANARY not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("stderr", "hint"),
    [
        ("You are not currently signed in", "sign-in required"),
        ("Rate limit exceeded", "request allowance unavailable"),
        ("unknown flag: --example", "unsupported CLI operation"),
        ("Could not be found", "requested object not found"),
        ("unexpected native error", "native command rejected"),
    ],
)
def test_failed_commands_identify_operation_without_exporting_native_text(
    monkeypatch: pytest.MonkeyPatch, stderr: str, hint: str
) -> None:
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: "/example/op")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: subprocess.CompletedProcess(
            args=[], returncode=17, stdout=CANARY.encode(), stderr=(stderr + CANARY).encode()
        ),
    )
    with pytest.raises(LifecycleError) as caught:
        setup.Operator().command("connect", "server", "get", CANARY, "--format=json")
    message = str(caught.value)
    assert "Connect server inspection" in message
    assert "exit 17" in message
    assert hint in message
    assert CANARY not in message
    assert setup.operation((CANARY,)) == "1Password operation"


def test_read_only_diagnosis_never_retries_an_uncertain_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    saved = tmp_path / "provision.intent.json"
    write_private(saved, {"private-canary": CANARY})
    before = saved.read_bytes()
    monkeypatch.setattr(setup, "manifest", lambda *_args: manifest())
    operator = Operator()
    setup.diagnose(
        operator, reference="test", expected_sha256="test", server="shared", output=tmp_path
    )
    output = capsys.readouterr().out
    assert "Saved provision.intent.json: present" in output
    assert "Saved provision.token.json: absent" in output
    assert "Operator sign-in: OK" in output
    assert CANARY not in output
    assert saved.read_bytes() == before
    assert operator.calls == [
        ("whoami", "--format=json"),
        ("connect", "server", "get", "shared", "--format=json"),
    ]


def test_diagnosis_reports_retained_files_even_when_login_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: "/example/op")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: subprocess.CompletedProcess(
            args=[], returncode=1, stdout=CANARY.encode(), stderr=b"not currently signed in"
        ),
    )
    with pytest.raises(LifecycleError, match=r"operator sign-in check.*sign-in required"):
        setup.diagnose(
            setup.Operator(),
            reference="test",
            expected_sha256="test",
            server="shared",
            output=tmp_path,
        )
    output = capsys.readouterr().out
    assert "Saved provision.intent.json: absent" in output
    assert "Read-only diagnosis complete" not in output
    assert CANARY not in output


def test_foreign_vault_and_untrusted_output_fail_before_issuing(tmp_path: Path) -> None:
    operator = Operator()
    value = manifest()
    value["production"] = {
        "references": {"some_other_secret": f"op://{'c' * 26}/{'e' * 26}/password"}
    }
    with pytest.raises(LifecycleError, match="production-check"):
        run(operator, tmp_path, value)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(LifecycleError, match="private directory"):
        run(operator, link)
    assert operator.calls == []
