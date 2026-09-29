"""Only explicitly selected, previously observed disposable challenges may be retired."""

from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import time
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_debug_dns as controller
from scripts import m3_11_debug_dns_probe as guest
from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe
from scripts.m3_11_dns_witness import DnsWitness
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes


@pytest.fixture
def wanted(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    nonce = str(uuid.uuid7())
    monkeypatch.setattr(probe, "_guard", Mock(return_value={"nonce": nonce}))
    monkeypatch.setattr(probe, "_closed", Mock())
    monkeypatch.setattr(probe, "_inactive", Mock())
    monkeypatch.setattr(guest, "_stored_tls", Mock())
    monkeypatch.setattr(guest, "_clean_dependencies", Mock())
    monkeypatch.setattr(
        probe, "_read", Mock(return_value=b"CLOUDFLARE_API_TOKEN=" + b"a" * 40 + b"\n")
    )
    return [
        {
            "zone_id": f"{number:032x}",
            "id": f"{number + 2:032x}",
            "name": f"_acme-challenge.m3-11-{uuid.UUID(nonce).hex}.{domain}",
            "type": "TXT",
            "content": '"' + "A" * 43 + '"',
        }
        for number, domain in enumerate(("lowerduckpond.net", "lowerduckpond.com"), 1)
    ]


def provider(wanted: list[dict[str, str]], method: str, path: str, *_: object) -> object:
    for item in wanted:
        if path == "/zones/" + item["zone_id"]:
            return {"id": item["zone_id"], "name": item["name"].split(".", 2)[2]}
        if path == f"/zones/{item['zone_id']}/dns_records/{item['id']}":
            return (
                {key: item[key] for key in guest.FIELDS} if method == "GET" else {"id": item["id"]}
            )
    raise AssertionError("unexpected provider request")


def test_guest_deletes_only_exact_preflighted_records_while_issuer_stopped(
    wanted: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    request = Mock(side_effect=lambda *args: provider(wanted, *args))
    monkeypatch.setattr(guest, "_request", request)
    result = guest.retire("context", wanted)
    assert result == {"retired_records": 2, "qualification_authority": "none"}
    assert [call.args[0] for call in request.call_args_list] == ["GET"] * 4 + ["DELETE"] * 2
    assert all(
        call.args[1].endswith(item["id"])
        for call, item in zip(request.call_args_list[-2:], wanted, strict=True)
    )


@pytest.mark.parametrize(
    "fault",
    [
        "foreign-name",
        "id",
        "content",
        "type",
        "duplicate",
        "zone",
        "changed",
        "running",
        "unissued",
    ],
)
def test_guest_refuses_foreign_changed_or_active_challenges_before_deleting(
    wanted: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    actual = [dict(item) for item in wanted]
    if fault == "foreign-name":
        wanted[0]["name"] = "_acme-challenge.production.lowerduckpond.net"
    elif fault in {"id", "content", "type"}:
        wanted[0][fault] = "foreign"
    elif fault == "duplicate":
        wanted.append(wanted[0])
    elif fault == "changed":
        actual[1]["content"] = '"' + "B" * 43 + '"'
    elif fault == "zone":
        actual[0]["name"] = "_acme-challenge.foreign.invalid"
    elif fault == "running":
        monkeypatch.setattr(probe, "_inactive", Mock(side_effect=ValueError("running")))
    else:
        monkeypatch.setattr(guest, "_stored_tls", Mock(side_effect=ValueError("unissued")))
    request = Mock(side_effect=lambda *args: provider(actual, *args))
    monkeypatch.setattr(guest, "_request", request)
    with pytest.raises(ValueError):
        guest.retire("context", wanted)
    assert all(call.args[0] == "GET" for call in request.call_args_list)


@pytest.mark.parametrize("fault", ["none", "unobserved", "context", "kind", "leftover", "provider"])
def test_controller_requires_prior_failed_cleanup_and_retains_deletion_receipts(
    tmp_path: Path, wanted: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    root = tmp_path
    coordinates = tuple(
        (item["name"].split(".", 2)[2], item["zone_id"], item["name"]) for item in wanted
    )
    context, names = (
        {"fixture": "original"},
        {"nonce": str(uuid.UUID(wanted[0]["name"].split(".")[1].removeprefix("m3-11-")))},
    )
    write_private(root / "combined-context.json", dict(context))
    write_private(root / "combined-names.json", dict(names))
    client = Mock()
    witness = DnsWitness(
        root,
        client,
        hashlib.sha256(canonical_bytes(context)).hexdigest(),
        hashlib.sha256(canonical_bytes(names)).hexdigest(),
        coordinates,
    )
    old = root / "diagnostic-dns" / uuid.uuid7().hex
    old.mkdir(mode=0o700, parents=True)
    witness.output_directory = old
    client.get_collection.side_effect = [
        [{key: item[key] for key in guest.FIELDS}] for item in wanted
    ]
    with pytest.raises(ValueError, match="not empty"):
        witness.require_absent("cleanup")
    if fault in {"context", "kind"}:
        value = read_private(old / "0000.json")
        value["context_sha256" if fault == "context" else "kind"] = "foreign"
        (old / "0000.json").write_bytes(canonical_bytes(value))
    original = (old / "0000.json").read_bytes()
    current = old.with_name(uuid.uuid7().hex)
    current.mkdir(mode=0o700)
    witness = replace(witness, output_directory=current, sequence=0)
    monkeypatch.setattr(controller, "require_original_unchanged", Mock())
    # One of the known records was already removed in a partial previous cleanup.
    if fault == "unobserved":
        wanted[0]["content"] = '"' + "B" * 43 + '"'
    client.get_collection.side_effect = [
        [{key: wanted[0][key] for key in guest.FIELDS}],
        [],
        [],
        [],
    ]
    if fault == "leftover":
        client.get_collection.side_effect = [
            [{key: wanted[0][key] for key in guest.FIELDS}],
            [],
            [{key: wanted[0][key] for key in guest.FIELDS}],
            [],
        ]
    call = Mock(return_value={"retired_records": 1, "qualification_authority": "none"})
    if fault == "provider":
        call.side_effect = ValueError("delete response lost")
    directory = root / "diagnostic-dns-retirements" / current.name
    if fault != "none":
        with pytest.raises(ValueError):
            controller.retire(witness, call)
        if fault in {"unobserved", "context", "kind"}:
            call.assert_not_called()
        else:
            assert (directory / "plan.json").exists()
        assert not (directory / "result.json").exists()
        assert (old / "0000.json").read_bytes() == original
        return
    result = controller.retire(witness, call)
    call.assert_called_once_with("diagnostic_retire_dns", expected=[wanted[0]])
    assert result["retired_records"] == 1
    assert read_private(directory / "result.json") == result
    assert read_private(directory / "plan.json")["records"] == [wanted[0]]
    assert (old / "0000.json").read_bytes() == original


@pytest.mark.parametrize(
    "status,body",
    [(302, b""), (403, b"private-canary"), (200, b"private-canary"), (200, b'{"success":false}')],
)
def test_provider_errors_and_redirects_do_not_expose_credentials(
    monkeypatch: pytest.MonkeyPatch, status: int, body: bytes
) -> None:
    connection = Mock()
    connection.getresponse.return_value.status = status
    connection.getresponse.return_value.read.return_value = body
    factory = Mock(return_value=connection)
    context = object()
    trust = Mock(return_value=context)
    monkeypatch.setattr(ssl, "create_default_context", trust)
    monkeypatch.setattr(http.client, "HTTPSConnection", factory)
    monkeypatch.setattr(time, "monotonic", lambda: 1)
    with pytest.raises(ValueError) as error:
        guest._request("DELETE", "/fixed", "credential-canary", 10)
    assert "canary" not in str(error.value)
    factory.assert_called_once_with("api.cloudflare.com", timeout=9, context=context)
    trust.assert_called_once_with(cafile=policy.INPUTS / "roots.pem")
    connection.close.assert_called_once()


def test_provider_success_and_deadline_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = Mock()
    connection.getresponse.return_value.status = 200
    connection.getresponse.return_value.read.return_value = json.dumps(
        {"success": True, "result": {"id": "record"}}
    ).encode()
    factory = Mock(return_value=connection)
    monkeypatch.setattr(ssl, "create_default_context", Mock())
    monkeypatch.setattr(http.client, "HTTPSConnection", factory)
    monkeypatch.setattr(time, "monotonic", lambda: 1)
    assert guest._request("GET", "/fixed", "token", 10) == {"id": "record"}
    factory.reset_mock()
    with pytest.raises(TimeoutError):
        guest._request("GET", "/fixed", "token", 1)
    factory.assert_not_called()


@pytest.mark.parametrize("private", [False, True])
def test_clean_resolver_is_bound_only_inside_a_private_mount_namespace(
    monkeypatch: pytest.MonkeyPatch, private: bool
) -> None:
    original_stat = Path.stat
    monkeypatch.setattr(
        Path,
        "stat",
        lambda path, **kwargs: (
            Mock(st_ino=1 if str(path) == "/proc/self/ns/mnt" or not private else 2)
            if str(path) in {"/proc/self/ns/mnt", "/proc/1/ns/mnt"}
            else original_stat(path, **kwargs)
        ),
    )
    command = Mock()
    monkeypatch.setattr(guest, "require_command", command)
    if not private:
        with pytest.raises(ValueError, match="private mount namespace"):
            guest._clean_dependencies()
        command.assert_not_called()
    else:
        guest._clean_dependencies()
        assert [call.args[0][-1] for call in command.call_args_list] == [
            "/etc/hosts",
            "/etc/resolv.conf",
        ]
