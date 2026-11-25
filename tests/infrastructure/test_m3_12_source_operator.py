"""Exercise the one-target source command and both sides of its action lease."""

from __future__ import annotations

import io
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from lowerduckpond_static_host_agent import droplet_enrollment, source_bootstrap

from infrastructure.test_m3_12_droplet_adapters import adapter, endpoint
from infrastructure.test_m3_12_droplet_journey import fixture as fixture  # noqa: PLC0414
from infrastructure.test_m3_12_droplet_journey import proof
from infrastructure.test_m3_12_droplet_journey import records as records  # noqa: PLC0414
from infrastructure.test_m3_12_source_bootstrap import handoff as handoff  # noqa: PLC0414
from scripts import m3_11_production_lease as lease
from scripts import m3_12_droplet_action as action
from scripts import m3_12_source_operator as operator
from scripts.m3_12_contracts import Document, ValidationError, digest, encode
from scripts.m3_12_diagnostic_store import Attempt, publish, read
from scripts.m3_12_disposable_routing import POLICY_FORMAT
from scripts.m3_12_droplet_scope import ReviewedJourney
from scripts.m3_12_droplet_ssh import Endpoint
from scripts.m3_12_successor import stage_configuration


def test_stale_lease_and_swapped_host_refuse_before_the_first_action(
    handoff: tuple[Document, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, authority, _ = handoff
    owner = os.geteuid()
    artifact = document["artifactSha256"]
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    path = runtime / "lease"
    path.mkdir(mode=0o700)
    cgroup = tmp_path / "cgroup"
    cgroup.write_text(f"0::/system.slice/{action.UNIT}\n")
    monkeypatch.setattr(action, "CGROUP", cgroup)
    monkeypatch.setattr(action, "LEASE", path)
    calls = []

    def shell(command: list[str]) -> int:
        calls.append(command)
        return 0

    monkeypatch.setattr(action.subprocess, "call", shell)
    source_bootstrap.receive(encode(document), artifact, owner=owner)
    with lease.controller(path, owner=owner, drain=lambda: None) as token:
        receipt = runtime.joinpath(*action._lease_record(token))
        receipt.write_bytes(encode({"handoffSha256": digest(document)}))
        receipt.chmod(0o600)
        payload = stage_configuration("dark-staging", artifact)
        with lease.action(path, owner=owner, token=token):
            monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(encode(payload))))
            assert action.dispatch(artifact, "gate", [token], owner=owner) == 0
            payload["publication_enabled"] = True
            monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(encode(payload))))
            with pytest.raises(ValidationError, match="droplet-source-stage-inputs-changed"):
                action.dispatch(artifact, "gate", [token], owner=owner)
        assert action.dispatch(artifact, "action", [token, "site-first-task"], owner=owner) == 0
        with monkeypatch.context() as swapped:
            seen = droplet_enrollment.host_identity(owner)
            seen["machineSha256"] = proof("foreign host")
            swapped.setattr(droplet_enrollment, "host_identity", lambda _: seen)
            with pytest.raises(ValidationError, match="droplet-enrollment-changed"):
                action.dispatch(artifact, "action", [token, "wrong-host-task"], owner=owner)
    with pytest.raises(ValueError, match="controller was superseded"):
        action.dispatch(artifact, "action", [token, "stale-lease-task"], owner=owner)
    assert calls == [["/bin/sh", "-c", "site-first-task"]]
    assert (authority / "source-bootstrap.json").read_bytes() == encode(document)


def test_operator_command_is_bound_to_exact_private_review_and_existing_site(  # noqa: PLR0915 - complete operator witness
    fixture: tuple[Attempt, Document, ReviewedJourney],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt, scope, original = fixture
    artifact = tmp_path / "candidate.tar"
    artifact.write_bytes(b"test artifact")
    ca = tmp_path / "origin-ca.pem"
    ca.write_bytes(b"test certificate")
    scope["candidate"]["hostAgentSha256"] = operator._digest(artifact)
    policy = {
        "format": POLICY_FORMAT,
        "runId": scope["runId"],
        "invocationId": scope["invocationId"],
        "platform": scope["resources"]["edge"]["platform"]["source"]["name"],
        "tenantScope": scope["resources"]["edge"]["tenant"]["source"]["name"],
        "tenants": [],
    }
    scope["sitePolicySha256"] = digest(policy)
    updated = replace(
        original,
        manifest_sha256=digest(scope),
        site_policy_sha256=digest(policy),
        candidate=encode(scope["candidate"]),
    )
    adapter((attempt, scope, updated), "dark-stage")
    source = endpoint(tmp_path, scope, "source")
    review = {
        "format": operator.FORMAT,
        "manifestSha256": updated.manifest_sha256,
        "predecessor": [
            {"name": name, "raw": raw.decode("ascii")} for name, raw in updated.predecessor_records
        ],
        "predecessorBootstrapSha256": updated.predecessor_bootstrap_sha256,
        "sitePolicy": policy,
        "sitePolicySha256": updated.site_policy_sha256,
        "candidate": scope["candidate"],
        "observedResources": scope["resources"],
        "productionExclusions": json.loads(updated.production_exclusions),
        "hostPublicKey": source.host_public_key.decode("ascii"),
        "originPullCaSha256": [operator._digest(ca)],
        "backupNodeName": "fixture-source",
        "operatorPublicKey": "synthetic",
        "operatorPrincipal": "fixture",
    }
    publish(attempt.directory, "source-operator.json", review)
    host = scope["resources"]["hosts"]["source"]
    observed_state = {"artifactSha256": None, "launchPresent": False, "publication": "dark"}

    def probe(args: list[str], **_options: object) -> bytes:
        assert "StrictHostKeyChecking=yes" in args and args[-2].endswith(source.provider.ipv4)
        return encode(
            {
                "format": "lowerduckpond-m3-12-droplet-observation-v1",
                "metadata": {"dropletId": source.provider.droplet_id, "ipv4": source.provider.ipv4},
                "hostIdentity": {
                    key: host["enrollment"][key]
                    for key in ("hostKeySha256", "machineSha256", "systemUuidSha256")
                },
                "bootSha256": proof("operator boot"),
                "state": observed_state,
            }
        )

    @contextmanager
    def owner(bound: Endpoint, known_hosts: Path, sealed: Document) -> Iterator[str]:
        assert bound == source and known_hosts.is_file()
        assert sealed["artifactSha256"] == scope["candidate"]["hostAgentSha256"]
        assert sealed["routing"]["sourceTargetSha256"] == digest(host["target"])
        yield "1" * 64

    calls = []

    def ansible(
        arguments: list[str], *, env: dict[str, str], **_options: object
    ) -> CompletedProcess[bytes]:
        calls.append(arguments)
        assert arguments[-1] == str(operator.CONFIG / "playbooks/site.yml")
        assert arguments[arguments.index("--limit") + 1] == "m312-source"
        inventory = json.loads(Path(arguments[2]).read_bytes())
        assert inventory["hosting_nodes"]["hosts"]["m312-source"]["ansible_connection"] == (
            "ldp_m3_12_droplet"
        )
        variables = json.loads(Path(arguments[-2][1:]).read_bytes())
        assert variables["static_publication_enabled"] is False
        assert env["LDP_M3_12_DROPLET_LEASE_TOKEN"] == "1" * 64
        assert "ANSIBLE_SKIP_TAGS" not in env
        report = Path(env["LDP_M3_11_PLAYBOOK_RECEIPT"])
        report.write_bytes(
            encode(
                {
                    "format": "lowerduckpond-m3-11-playbook-recap-v1",
                    "context_sha256": env["LDP_M3_11_PLAYBOOK_CONTEXT"],
                    "hosts": {
                        "m312-source": dict.fromkeys(
                            (
                                "ok",
                                "changed",
                                "failures",
                                "unreachable",
                                "skipped",
                                "rescued",
                                "ignored",
                            ),
                            0,
                        )
                        | {"ok": 1}
                    },
                }
            )
        )
        report.chmod(0o600)
        observed_state["artifactSha256"] = variables["static_host_agent_artifact_sha256"]
        return CompletedProcess(arguments, 0)

    monkeypatch.setattr(operator, "_owner", owner)
    monkeypatch.setattr(operator, "bounded_command", probe)
    monkeypatch.setattr(operator.subprocess, "run", ansible)
    for name in operator.CREDENTIALS:
        monkeypatch.setenv(name, "synthetic-per-scope-input")
    monkeypatch.setenv("ANSIBLE_SKIP_TAGS", "source-preflight")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "source-operator",
            str(attempt.directory),
            "--review-sha256",
            digest(review),
            "--identity-file",
            str(source.identity_file),
            "--artifact",
            str(artifact),
            "--ca",
            str(ca),
        ],
    )
    assert operator.main() == 0
    result = read(attempt.directory, "source-converge-result.json")
    assert result["ownerReleased"] is True
    assert result["sourceTargetSha256"] == digest(host["target"])
    assert result["stateKey"] == host["stateKey"]
    assert b"synthetic-per-scope-input" not in encode(result)
    with pytest.raises(SystemExit):
        operator.main()
    assert len(calls) == 1
