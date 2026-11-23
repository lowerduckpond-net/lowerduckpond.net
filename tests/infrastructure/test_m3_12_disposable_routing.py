"""Synthetic P4 allocation, fence and browser continuity witnesses."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlsplit

import pytest
from lowerduckpond_static_host_agent.caddy_routes import build_platform_only_caddy_routes
from lowerduckpond_static_host_agent.host_restore_inputs import ROUTING_INPUT, RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    DROPLET_BINDING,
    DROPLET_SCOPE_FORMAT,
)
from lowerduckpond_static_host_agent.installed_routing import PROJECTION, ROLE, cutover_filename
from playwright.async_api import Browser, Page

from infrastructure.test_m3_12_droplet_adapters import Captures, adapter, endpoint
from infrastructure.test_m3_12_droplet_controller import recovery_policy
from infrastructure.test_m3_12_droplet_journey import fixture as fixture  # noqa: PLC0414
from infrastructure.test_m3_12_droplet_journey import proof
from infrastructure.test_m3_12_droplet_journey import records as records  # noqa: PLC0414
from scripts import m3_12_droplet_observe as guest
from scripts.m3_12_contracts import Document, ValidationError, digest, encode
from scripts.m3_12_diagnostic_store import Attempt
from scripts.m3_12_disposable_routing import (
    POLICY_FORMAT,
    RESTORE_PHASES,
    PreparedRouting,
    RoutingEndpoint,
    prepare_installed_routing_delivery,
    prepare_projected_routes,
    prepare_routing,
    verify_cutover,
)
from scripts.m3_12_droplet_native import AdapterInputs
from scripts.m3_12_droplet_observe import (
    BROWSER_FORMAT,
    BROWSER_QUERY,
    FENCE_FORMAT,
    FORMAT,
    _browser_log_matches,
    _restore_firewall,
)
from scripts.m3_12_droplet_scope import ReviewedJourney
from scripts.m3_12_droplet_ssh import REMOTE_PROBE, Endpoint
from scripts.m3_12_routing_browser import (
    browser_continuity,
    fresh_restored_response,
    remember_browser,
)

TENANT = "01997763-4600-7000-8000-000000000001"


@dataclass
class Pair:
    inputs: AdapterInputs
    source: PreparedRouting
    restore: PreparedRouting
    receipt: Document
    endpoint: Endpoint


@pytest.fixture
def pair(  # noqa: PLR0915 - full enrolled source and restore proof
    fixture: tuple[Attempt, Document, ReviewedJourney],
    tmp_path: Path,
) -> Pair:
    attempt, scope, review = fixture
    policy = {
        "format": POLICY_FORMAT,
        "runId": scope["runId"],
        "invocationId": scope["invocationId"],
        "platform": "source.platform.example",
        "tenantScope": "source.tenant.example",
        "tenants": [
            {
                "tenantId": TENANT,
                "origin": "https://t-" + TENANT.replace("-", "") + ".source.tenant.example",
            }
        ],
    }
    raw = encode(policy)
    scope["sitePolicySha256"] = digest(policy)
    hosts = scope["resources"]["hosts"]
    for role, machine in (("source", "a" * 32), ("restore", "b" * 32)):
        host = hosts[role]
        host["enrollment"]["machineSha256"] = proof(machine)
        host["target"]["enrollmentSha256"] = digest(host["enrollment"])
    review = replace(
        review,
        manifest_sha256=digest(scope),
        site_policy_sha256=digest(policy),
        observed_resources=encode(scope["resources"]),
    )
    native_policy, fence = recovery_policy(attempt)
    original_fence = json.loads(fence)
    native_policy[DROPLET_BINDING] = {
        "format": DROPLET_SCOPE_FORMAT,
        "runId": scope["runId"],
        "sourceTargetSha256": digest(hosts["source"]["target"]),
        "destinationTargetSha256": digest(hosts["restore"]["target"]),
        "sourceLaunchReceiptSha256": None,
    }
    captures = Captures(attempt, scope)
    captures.evidence["backup-fence"] = {"sourceFence": sha256(fence).hexdigest()}
    destination_inputs = adapter((attempt, scope, review), "restore", captures)
    source_inputs = AdapterInputs(
        attempt,
        encode(scope),
        review,
        (attempt.directory / "journey-backup-fence-intent.json").read_bytes(),
    )
    source = endpoint(tmp_path, scope, "source")
    destination = endpoint(tmp_path, scope, "restore")
    chosen = {source.provider.ipv4: "source", destination.provider.ipv4: "restore"}
    boots = {role: proof(f"{role} boot") for role in chosen.values()}
    overlap = False
    requests: list[str] = []

    def wire(arguments: list[str], **_kwargs: object) -> bytes:
        assert "StrictHostKeyChecking=yes" in arguments
        ipv4 = arguments[-2].removeprefix("ldp-admin@")
        role = chosen[ipv4]
        requests.append(role)
        host = hosts[role]
        seen = {
            "format": FORMAT,
            "metadata": {"dropletId": host["target"]["droplet"]["dropletId"], "ipv4": ipv4},
            "hostIdentity": {
                name: host["enrollment"][name]
                for name in ("machineSha256", "systemUuidSha256", "hostKeySha256")
            },
            "bootSha256": boots[role],
            "state": {
                "artifactSha256": scope["candidate"]["hostAgentSha256"],
                "launchPresent": True,
                "publication": "dark",
            },
        }
        if arguments[-1] == REMOTE_PROBE:
            return encode(seen)
        assert arguments[-1] == f"{REMOTE_PROBE} --restore-fence"
        return encode(
            {
                "format": FENCE_FORMAT,
                "observation": seen,
                "gateSha256": original_fence["sourceGateDigest"]["value"],
                "ingressClosed": not overlap,
                "caddyInactive": role == "source" and not overlap,
            }
        )

    with pytest.raises(ValidationError, match="droplet-journey-adapter-intent-changed"):
        prepare_routing(destination_inputs, source, raw, wire)
    with pytest.raises(ValidationError, match="droplet-routing-policy-changed"):
        prepare_routing(
            source_inputs, source, encode({**policy, "invocationId": scope["runId"]}), wire
        )
    with pytest.raises(ValidationError, match="droplet-routing-policy-changed"):
        prepare_routing(
            source_inputs, source, encode({**policy, "tenantScope": "unowned.example"}), wire
        )
    assert requests == []
    src = prepare_routing(source_inputs, source, raw, wire)
    dst = prepare_routing(destination_inputs, destination, raw, wire)
    assert src.policy == dst.policy
    assert src.target_sha256 != dst.target_sha256
    restored = RestoreInputs.from_bytes(
        encode({**native_policy, ROUTING_INPUT: src.policy.document()})
    )

    def cutover(*, from_host: PreparedRouting = src, to_host: PreparedRouting = dst) -> Document:
        return verify_cutover(
            RoutingEndpoint(source_inputs, source, from_host),
            RoutingEndpoint(destination_inputs, destination, to_host),
            policy_raw=raw,
            restore=restored,
            fence=fence,
            execute=wire,
        )

    dark = build_platform_only_caddy_routes(
        origin_pull_ca_der=(b"synthetic CA",), origin_pull_required=True
    )
    projected_source = prepare_projected_routes(source_inputs, src, raw, dark)
    assert prepare_installed_routing_delivery(source_inputs, src, raw) == {
        ROLE: encode(src.policy.role_document("source")),
        PROJECTION: encode(src.policy.document()),
    }
    with pytest.raises(ValidationError, match="droplet-routing-cutover-missing"):
        prepare_projected_routes(destination_inputs, dst, raw, dark)
    receipt = cutover()
    assert prepare_installed_routing_delivery(destination_inputs, dst, raw, cutover=receipt) == {
        ROLE: encode(dst.policy.role_document("restore")),
        cutover_filename(dst.boot_sha256): encode(receipt),
    }
    assert (
        prepare_projected_routes(destination_inputs, dst, raw, dark, cutover=receipt)
        == projected_source
    )
    with pytest.raises(ValidationError, match="droplet-routing-source-fenced"):
        prepare_projected_routes(source_inputs, src, raw, dark)
    with pytest.raises(ValidationError, match="droplet-routing-cutover-binding-changed"):
        prepare_projected_routes(
            destination_inputs,
            replace(dst, boot_sha256=proof("unexpected restore reboot")),
            raw,
            dark,
            cutover=receipt,
        )
    overlap = True
    with pytest.raises(ValidationError, match="droplet-routing-fence-unproven"):
        cutover()
    overlap = False
    with pytest.raises(ValidationError, match="droplet-routing-cutover-binding-changed"):
        cutover(to_host=replace(dst, target_sha256=src.target_sha256))
    boots["source"] = proof("rebooted source")
    with pytest.raises(ValidationError, match="droplet-routing-fence-host-changed"):
        cutover()
    return Pair(destination_inputs, src, dst, receipt, destination)


def test_same_projection_and_fence_survive_the_handoff(pair: Pair) -> None:
    assert pair.source.policy.sha256 == pair.restore.policy.sha256 == pair.receipt["routingSha256"]
    assert pair.source.policy.document()["tenants"] == pair.restore.policy.document()["tenants"]


class TestPage:
    __test__ = False

    def __init__(self, url: str) -> None:
        self.url = url
        self.marker = None
        self.visits: list[str] = []

    async def evaluate(self, expression: str, argument: object) -> object:
        if "setItem" in expression:
            assert isinstance(argument, list)
            self.marker = argument[1]
        return self.marker

    async def goto(self, url: str, **_arguments: object) -> TestPage:
        self.visits.append(url)
        self.url = url
        return self

    @property
    def status(self) -> int:
        return 200

    async def body(self) -> bytes:
        return b"retained synthetic tenant bytes"


class TestBrowser:
    __test__ = False

    def __init__(self) -> None:
        self.page = TestPage("about:blank")
        self.closed = False

    async def new_context(self, **options: object) -> TestBrowser:
        assert options["service_workers"] == "block"
        assert options["ignore_https_errors"] is False
        return self

    async def new_page(self) -> TestPage:
        return self.page

    async def close(self) -> None:
        self.closed = True


def test_browser_local_state_and_fresh_restored_host_are_separate(pair: Pair) -> None:
    origin = pair.source.policy.expected_origin(TENANT)
    existing = TestPage(origin + "/")
    fresh = TestBrowser()
    fresh_wrong = TestBrowser()

    async def exercise() -> None:
        receiver = RoutingEndpoint(pair.inputs, pair.endpoint, pair.restore)
        continuity = await remember_browser(cast(Page, existing), pair.source, TENANT)
        original = await browser_continuity(continuity, receiver, TENANT, cutover=pair.receipt)
        assert original == {"origin": origin, "sameBrowserContinuity": True}
        assert existing.visits == [origin + "/"]
        other_attempt = replace(pair.restore.policy, invocation_id=pair.restore.policy.run_id)
        with pytest.raises(ValidationError, match="droplet-routing-cutover-binding-changed"):
            await browser_continuity(
                continuity,
                replace(receiver, prepared=replace(pair.restore, policy=other_attempt)),
                TENANT,
                cutover=pair.receipt,
            )
        assert existing.visits == [origin + "/"]
        assert fresh.page.url == "about:blank"

        scope, _ = pair.inputs.open(RESTORE_PHASES)
        hosts = scope["resources"]["hosts"]

        def wire(arguments: list[str], **_kwargs: object) -> bytes:
            assert "StrictHostKeyChecking=yes" in arguments
            assert arguments[-2] == f"ldp-admin@{pair.endpoint.provider.ipv4}"
            operation, hostname, request = arguments[-1].removeprefix(REMOTE_PROBE + " ").split()
            assert operation == "--browser-request"
            assert f"https://{hostname}" == origin
            page = fresh_wrong.page if fresh.closed else fresh.page
            marker = parse_qs(urlsplit(page.url).query)
            assert marker == {BROWSER_QUERY: [request]}
            enrolled = hosts["restore"]["enrollment"]
            return encode(
                {
                    "format": BROWSER_FORMAT,
                    "requestId": request,
                    "origin": origin,
                    "observation": {
                        "format": FORMAT,
                        "metadata": {
                            "dropletId": pair.endpoint.provider.droplet_id,
                            "ipv4": pair.endpoint.provider.ipv4,
                        },
                        "hostIdentity": {
                            "machineSha256": (
                                hosts["source"]["enrollment"]["machineSha256"]
                                if fresh.closed
                                else enrolled["machineSha256"]
                            ),
                            "systemUuidSha256": enrolled["systemUuidSha256"],
                            "hostKeySha256": enrolled["hostKeySha256"],
                        },
                        "bootSha256": pair.restore.boot_sha256,
                        "state": {
                            "artifactSha256": scope["candidate"]["hostAgentSha256"],
                            "launchPresent": True,
                            "publication": "enabled",
                        },
                    },
                }
            )

        proof_row = await fresh_restored_response(
            cast(Browser, fresh),
            receiver,
            TENANT,
            cutover=pair.receipt,
            expected_body_sha256=proof("retained synthetic tenant bytes"),
            execute=wire,
        )
        assert proof_row["cutoverSha256"] == digest(pair.receipt)

        with pytest.raises(ValidationError, match="droplet-browser-restored-host-unproven"):
            await fresh_restored_response(
                cast(Browser, fresh_wrong),
                receiver,
                TENANT,
                cutover=pair.receipt,
                expected_body_sha256=proof("retained synthetic tenant bytes"),
                execute=wire,
            )
        assert fresh.page.url != fresh_wrong.page.url
        assert fresh.closed and fresh_wrong.closed

    asyncio.run(exercise())


def test_browser_correlates_one_native_tls_request_and_excludes_unrelated_rows() -> None:
    marker = "c" * 32
    hostname = f"t-{TENANT.replace('-', '')}.source.tenant.example"
    request = {
        "host": hostname,
        "method": "GET",
        "uri": f"/?{BROWSER_QUERY}={marker}",
        "tls": {"version": 772},
        "headers": {"User-Agent": ["unretained synthetic metadata"]},
    }
    access = {"logger": "http.log.access.log0", "status": 200, "request": request}

    def entry(service: str, observed: Document) -> str:
        return json.dumps({"_SYSTEMD_UNIT": service, "MESSAGE": json.dumps(observed)})

    candidate = entry("caddy.service", access)
    assert _browser_log_matches(candidate, hostname, marker)
    assert not _browser_log_matches(candidate, hostname, "d" * 32)
    assert not _browser_log_matches(candidate, "another.example", marker)
    assert not _browser_log_matches(candidate + "\n" + candidate, hostname, marker)
    assert not _browser_log_matches(entry("other.service", access), hostname, marker)
    assert not _browser_log_matches(
        entry("caddy.service", {**access, "request": {**request, "tls": None}}),
        hostname,
        marker,
    )


def _native_firewall() -> Document:
    base = {"family": "inet", "table": "lowerduckpond_restore"}
    return {
        "nftables": [
            {"metainfo": {"version": "fixture"}},
            {"table": {"family": "inet", "name": "lowerduckpond_restore", "handle": 1}},
            {
                "chain": {
                    **base,
                    "name": "input",
                    "type": "filter",
                    "hook": "input",
                    "prio": -200,
                    "policy": "accept",
                }
            },
            {
                "rule": {
                    **base,
                    "chain": "input",
                    "expr": [
                        {
                            "match": {
                                "op": "!=",
                                "left": {"meta": {"key": "iifname"}},
                                "right": "lo",
                            }
                        },
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                "right": {"set": [80, 443]},
                            }
                        },
                        {"drop": None},
                    ],
                }
            },
        ],
    }


def test_exact_native_firewall_projection_rejects_missing_or_changed_rules() -> None:
    row = _native_firewall()
    assert _restore_firewall(row)
    row["nftables"].pop()
    assert not _restore_firewall(row)


def test_reboot_fence_observation_requires_original_completed_restore_and_closed_rule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = tmp_path / "host-restore.json"
    gate_path = tmp_path / "restore-gate.json"
    restore_id = TENANT
    recorded = {"schema": guest.JOURNAL_FORMAT, "restoreId": restore_id, "phase": "complete"}
    journal.write_bytes(encode(recorded))
    journal.chmod(0o600)
    kernel_rule = _native_firewall()
    monkeypatch.setattr(guest, "JOURNAL", journal)
    monkeypatch.setattr(guest, "RESTORE_GATE", gate_path)
    monkeypatch.setattr(guest, "observe", lambda _owner: {"bootSha256": proof("destination boot")})
    monkeypatch.setattr(
        guest,
        "_command",
        lambda command, *_argv: json.dumps(kernel_rule) if command.endswith("/nft") else "inactive",
    )
    with pytest.raises(ValueError, match="droplet-restore-gate-missing"):
        guest.fence_status(os.geteuid())
    with pytest.raises(ValueError, match="droplet-restore-completion-changed"):
        guest.fence_status(os.geteuid(), completed_restore_id=str(0))
    result = guest.fence_status(os.geteuid(), completed_restore_id=restore_id)
    gate_path.write_bytes(encode({"schema": guest.RESTORE_GATE_FORMAT, "restoreId": restore_id}))
    gate_path.chmod(0o600)
    assert result == guest.fence_status(os.geteuid())
    assert result["ingressClosed"] is True
    kernel_rule["nftables"].pop()
    assert (
        guest.fence_status(os.geteuid(), completed_restore_id=restore_id)["ingressClosed"] is False
    )
