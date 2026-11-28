"""Scope and first-failure checks for running one exact leased dark playbook."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import m3_12_canary_playbook as playbook
from scripts.m3_11_playbook_recap import COUNTERS
from scripts.m3_11_production_converge import HOST
from scripts.m3_11_production_session import Logs, Result
from scripts.m3_12_contracts import ValidationError, digest, encode
from scripts.m3_12_successor import stage_configuration

from .test_m3_12_contracts import fixture_time, proof, uuid


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "repeat-changed",
        "wrong-intent",
        "failed",
        "stale",
        "missing-runtime",
        "native",
        "native-commit-changed",
    ],
)
def test_dark_playbook_preserves_exact_pending_command(  # noqa: PLR0915 - the same bound receipt through controller and native RPC
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    tmp_path.chmod(0o700)
    artifact = tmp_path / "candidate.tar"
    artifact.write_bytes(b"approved bytes")
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    token = proof("fixture lease")
    runner = tmp_path / "ansible-playbook"
    if fault != "missing-runtime":
        runner.touch(mode=0o700)
    action = playbook.DarkPass(
        proof("transaction"),
        uuid(4),
        token,
        artifact,
        sha,
        tmp_path / "identity",
        tmp_path / "signer",
        tmp_path / "known_hosts",
        runner,
    )
    intent = encode(
        {
            "format": "lowerduckpond-m3-12-phase-receipt-v1",
            "transactionSha256": action.transaction_sha256,
            "previousSha256": proof("previous"),
            "phase": "dark-repeat",
            "transition": "started",
            "stageConfigurationSha256": digest(
                stage_configuration(
                    "dark-repeat", proof("different") if fault == "wrong-intent" else sha
                )
            ),
            "publicationView": "dark",
            "invocationId": action.invocation,
            "leaseSha256": hashlib.sha256(token.encode()).hexdigest(),
            "recordedAt": fixture_time(5),
            "evidenceSha256": proof("evidence"),
        }
    )
    calls: list[bytes] = []
    operations: list[str] = []
    observations = iter([intent, b"other" if fault == "stale" else intent])

    def local_runner(
        logs: Logs, name: str, argv: list[str], *, environment: dict[str, str], data: bytes = b""
    ) -> Result:
        operations.append(name)
        if name.startswith("first-canary-"):
            assert fault.startswith("native")
            assert argv[0] == "/usr/bin/ssh" and f"ldp-admin@{playbook.SSH_TARGET}" in argv
            assert "ForwardAgent=no" in argv and "--expand-environment=no" in argv[-1]
            assert f" {name} {token}" in argv[-1]
            assert "LDP_M3_12_LEASE_TOKEN" not in environment
            stdout, stderr = logs.paths(name)
            if name == "first-canary-finish-dark":
                assert data == calls[0]
                row = playbook.decode(intent, "phase-receipt")
                row.update(
                    transition="committed",
                    previousSha256=(
                        proof("changed head")
                        if fault == "native-commit-changed"
                        else hashlib.sha256(intent).hexdigest()
                    ),
                )
                stdout.write_bytes(encode(row))
            else:
                assert name == "first-canary-pending-dark" and not data
                stdout.write_bytes(intent)
            return Result(0, stdout, stderr)
        assert argv[0] == str(runner)
        assert name == "ansible-site" and "--limit" in argv and HOST in argv
        directory = logs.directory
        variables = json.loads((directory / "variables.json").read_bytes())
        assert variables["static_publication_enabled"] is False
        assert variables["static_host_agent_artifact_sha256"] == sha
        assert "DIGITALOCEAN_TOKEN" not in environment and "SSH_AUTH_SOCK" not in environment
        inventory = json.loads((directory / "inventory.json").read_bytes())
        host = inventory["all"]["children"]["hosting_nodes"]["hosts"][HOST]
        assert host["ansible_connection"] == "ldp_m3_12"
        assert host["ansible_host"] == playbook.SSH_TARGET
        assert "ForwardAgent=no" in host["ansible_ssh_common_args"]
        assert "StrictHostKeyChecking=yes" in host["ansible_ssh_common_args"]
        assert token not in str(inventory) and token not in repr(action)
        context = environment["LDP_M3_11_PLAYBOOK_CONTEXT"]
        assert context == hashlib.sha256(intent).hexdigest()
        counters = dict.fromkeys(COUNTERS, 0)
        counters.update(ok=1, changed=int(fault == "repeat-changed"))
        raw = encode(
            {
                "format": "lowerduckpond-m3-11-playbook-recap-v1",
                "context_sha256": context,
                "hosts": {HOST: counters},
            }
        )
        report = directory / "recap.json"
        report.write_bytes(raw)
        report.chmod(0o600)
        calls.append(raw)
        return Result(int(fault == "failed"), directory / "stdout", directory / "stderr")

    monkeypatch.setattr(Logs, "run", local_runner)
    if fault.startswith("native"):
        if fault == "native-commit-changed":
            with pytest.raises(ValidationError, match="first-canary-playbook-commit-changed"):
                playbook.complete_pending(action, tmp_path, {})
        else:
            assert playbook.complete_pending(action, tmp_path, {})["transition"] == "committed"
        assert operations == [
            "first-canary-pending-dark",
            "first-canary-pending-dark",
            "ansible-site",
            "first-canary-pending-dark",
            "first-canary-finish-dark",
        ]
        return
    if fault != "none":
        with pytest.raises(
            (ValidationError, ValueError), match=r"first-canary-playbook|not idempotent"
        ):
            playbook.run(action, intent, tmp_path, {}, lambda: next(observations))
        assert len(calls) == int(fault not in {"wrong-intent", "missing-runtime"})
        return
    assert playbook.run(action, intent, tmp_path, {}, lambda: next(observations)) == calls[0]
