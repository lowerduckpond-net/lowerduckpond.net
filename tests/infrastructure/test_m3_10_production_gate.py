from __future__ import annotations

import copy
import os
import subprocess
from pathlib import Path
from typing import cast

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import ArchiveQualificationError

from scripts.check_m3_7_production_edge import CloudflareClient
from scripts.check_m3_10_provider import (
    GateError,
    PolicyClient,
    check_edge,
    check_storage,
    expected_rules,
)

ROOT = Path(__file__).parents[2]
EXPECTED = "4e32c4a88d729b371b8cd5da96e5fedbc9f30266acb0984599c1d645939bef85"


class Storage:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.responses: dict[str, object] = {
            "get_bucket_acl": {
                "Owner": {"ID": "owner"},
                "Grants": [
                    {
                        "Grantee": {"Type": "CanonicalUser", "ID": "owner"},
                        "Permission": "FULL_CONTROL",
                    }
                ],
            },
            "get_bucket_policy": "NoSuchBucketPolicy",
            "get_bucket_lifecycle_configuration": "NoSuchLifecycleConfiguration",
            "get_bucket_versioning": {"Status": "Enabled"},
            "list_objects_v2": {"IsTruncated": False},
            "list_object_versions": {"IsTruncated": False},
            "list_multipart_uploads": {"IsTruncated": False},
        }

    def __getattr__(self, name: str) -> object:
        def operation(**arguments: object) -> object:
            self.calls.append(name)
            assert arguments["Bucket"] == "archive-fixture"
            if name.startswith("list_"):
                assert arguments["Prefix"] == ""
            response = self.responses[name]
            if isinstance(response, str):
                raise ClientError(
                    {
                        "Error": {"Code": response},
                        "ResponseMetadata": {
                            "HTTPStatusCode": 404 if response.startswith("NoSuch") else 403
                        },
                    },
                    name,
                )
            return response

        return operation


def test_storage_gate_reads_every_accounting_view_without_mutation() -> None:
    storage = Storage()
    check_storage(cast(PolicyClient, storage), bucket="archive-fixture")
    assert storage.calls == list(storage.responses)


@pytest.mark.parametrize(
    ("operation", "response"),
    [
        ("get_bucket_acl", {"Owner": {"ID": "owner"}, "Grants": []}),
        ("get_bucket_policy", "AccessDenied"),
        ("get_bucket_policy", {"Policy": "{}"}),
        ("get_bucket_lifecycle_configuration", "AccessDenied"),
        ("get_bucket_lifecycle_configuration", {"Rules": [{"Status": "Enabled"}]}),
        ("get_bucket_versioning", {"Status": "Suspended"}),
        ("list_objects_v2", {"Contents": [{"Key": "unknown"}]}),
        ("list_object_versions", {"Versions": [{"Key": "unknown", "VersionId": "v1"}]}),
        ("list_object_versions", {"DeleteMarkers": [{"Key": "unknown", "VersionId": "v1"}]}),
        ("list_multipart_uploads", {"Uploads": [{"Key": "unknown", "UploadId": "u1"}]}),
    ],
)
def test_storage_gate_fails_on_ambiguous_or_nonempty_state(
    operation: str, response: object
) -> None:
    storage = Storage()
    storage.responses[operation] = response
    with pytest.raises((GateError, ArchiveQualificationError)):
        check_storage(cast(PolicyClient, storage), bucket="archive-fixture")
    assert all(name.startswith(("get_", "list_")) for name in storage.calls)


@pytest.mark.parametrize(
    "grantee", [{"Type": "Group", "URI": "AllUsers"}, {"Type": "CanonicalUser", "ID": "other"}]
)
def test_storage_gate_rejects_public_and_foreign_grants(grantee: dict[str, str]) -> None:
    storage = Storage()
    storage.responses["get_bucket_acl"] = {
        "Owner": {"ID": "owner"},
        "Grants": [{"Grantee": grantee, "Permission": "FULL_CONTROL"}],
    }
    with pytest.raises(GateError, match="private owner"):
        check_storage(cast(PolicyClient, storage), bucket="archive-fixture")


class Edge:
    def __init__(self) -> None:
        self.responses: dict[str, object] = {
            "": {"name": "lowerduckpond.net"},
            "/dns_records": [
                {"name": name, "type": "A", "content": "192.0.2.1", "proxied": True, "ttl": 1}
                for name in ("lowerduckpond.net", "*.lowerduckpond.net")
            ],
            "/settings/ssl": {"value": "strict"},
            "/settings/always_online": {"value": "off"},
            "/settings/always_use_https": {"value": "off"},
            "/origin_tls_client_auth/settings": {"enabled": True},
            "/origin_tls_client_auth/hostnames": [],
            "/origin_tls_client_auth": [{"id": "b" * 32, "status": "active"}],
            "/rulesets": [
                {"kind": "zone", "phase": phase} for phase in expected_rules("lowerduckpond.net")
            ],
            **{
                f"/rulesets/phases/{phase}/entrypoint": {"rules": [rule]}
                for phase, rule in expected_rules("lowerduckpond.net").items()
            },
        }

    def get(self, path: str) -> object:
        assert path.startswith("/zones/" + "a" * 32)
        return self.responses[path.removeprefix("/zones/" + "a" * 32)]

    def get_collection(self, path: str) -> object:
        return self.get(path)

    def get_cursor_collection(self, path: str) -> object:
        return self.get(path)

    def get_aop_setting(self, zone: str) -> object:
        return self.get(f"/zones/{zone}/origin_tls_client_auth/settings")


def edge_gate(edge: Edge) -> None:
    check_edge(
        cast(CloudflareClient, edge),
        zone_id="a" * 32,
        certificate_id="b" * 32,
        domain="lowerduckpond.net",
        origin="192.0.2.1",
    )


def test_enforced_edge_passes_unchanged() -> None:
    edge_gate(Edge())


@pytest.mark.parametrize(
    ("path", "response"),
    [
        ("", {"name": "other.invalid"}),
        ("/dns_records", []),
        ("/settings/ssl", {"value": "full"}),
        ("/settings/always_online", {"value": "on"}),
        ("/origin_tls_client_auth/settings", {"enabled": False}),
        ("/origin_tls_client_auth/hostnames", [{"hostname": "override"}]),
        ("/origin_tls_client_auth", [{"id": "c" * 32, "status": "active"}]),
        ("/rulesets/phases/http_request_cache_settings/entrypoint", {"rules": []}),
    ],
)
def test_edge_gate_refuses_policy_drift(path: str, response: object) -> None:
    edge = Edge()
    edge.responses[path] = response
    with pytest.raises(GateError):
        edge_gate(edge)


@pytest.mark.parametrize("phase", list(expected_rules("lowerduckpond.net")))
def test_edge_gate_refuses_extra_rules_and_changed_actions(phase: str) -> None:
    edge = Edge()
    rule = copy.deepcopy(expected_rules("lowerduckpond.net")[phase])
    edge.responses[f"/rulesets/phases/{phase}/entrypoint"] = {"rules": [rule, rule]}
    with pytest.raises(GateError):
        edge_gate(edge)
    rule["action"] = "skip"
    edge.responses[f"/rulesets/phases/{phase}/entrypoint"] = {"rules": [rule]}
    with pytest.raises(GateError):
        edge_gate(edge)


@pytest.fixture
def host_tree(tmp_path: Path) -> Path:
    for directory in (
        "opt/lowerduckpond/static-host-agent",
        "etc/caddy/intents",
        "etc/caddy/routes.d",
        "usr/local/libexec/lowerduckpond",
        "bin",
    ):
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)
    install = tmp_path / "opt/lowerduckpond/static-host-agent"
    (install / EXPECTED).mkdir()
    (install / "current").symlink_to(EXPECTED)
    for name, body in {
        "usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact": "exit 0",
        "usr/local/libexec/lowerduckpond/check-caddy-generation": (
            "function check() { echo current; }\n"
            "check \\\n    --origin-pull-required \\\n    fixture"
        ),
        "bin/systemctl": 'if [ "$1" = is-active ]; then exit 0; fi',
    }.items():
        path = tmp_path / name
        path.write_text("#!/bin/bash\n" + body + "\n")
        path.chmod(0o755)
    source = (ROOT / "scripts/m3-10-host-preflight").read_text()
    for prefix in ("/opt/", "/etc/", "/var/", "/run/", "/usr/local/"):
        source = source.replace(prefix, str(tmp_path) + prefix)
    (tmp_path / "probe").write_text(source)
    return tmp_path


def host_gate(tree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed local fixture, never production paths
        ["/bin/bash", str(tree / "probe")],
        env={"PATH": str(tree / "bin") + ":" + os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=False,
    )


def test_host_gate_accepts_only_the_preceding_empty_host(host_tree: Path) -> None:
    outcome = host_gate(host_tree)
    assert outcome.returncode == 0, outcome.stderr


@pytest.mark.parametrize(
    "path",
    [
        "etc/caddy/intents/start.json",
        "etc/caddy/routes.d/tenant",
        "etc/lowerduckpond/archive",
        "run/lowerduckpond-archive",
        "var/lib/lowerduckpond/static/platform/archive-quarantine.json",
    ],
)
def test_host_gate_refuses_pending_or_partially_installed_state(host_tree: Path, path: str) -> None:
    unexpected = host_tree / path
    unexpected.parent.mkdir(parents=True, exist_ok=True)
    unexpected.touch()
    assert host_gate(host_tree).returncode != 0


def test_host_gate_refuses_candidate_digest(host_tree: Path) -> None:
    install = host_tree / "opt/lowerduckpond/static-host-agent"
    (install / ("c" * 64)).mkdir()
    (install / "current").unlink()
    (install / "current").symlink_to("c" * 64)
    outcome = host_gate(host_tree)
    assert outcome.returncode != 0
    assert "recorded M3.9" in outcome.stderr


@pytest.mark.parametrize("mode", ["comment", "staged"])
def test_host_gate_refuses_comment_only_or_staged_origin_pull(host_tree: Path, mode: str) -> None:
    checker = host_tree / "usr/local/libexec/lowerduckpond/check-caddy-generation"
    body = checker.read_text()
    if mode == "comment":
        body = body.replace("    --origin-pull-required", "# --origin-pull-required")
    else:
        body += "# --origin-pull-staged\n"
    checker.write_text(body)
    assert host_gate(host_tree).returncode != 0


@pytest.mark.parametrize(
    "phase", ["http_request_redirect", "http_request_origin", "http_response_headers_transform"]
)
def test_edge_gate_rejects_unexpected_zone_ruleset_phases(phase: str) -> None:
    edge = Edge()
    inventory = cast(list[dict[str, object]], edge.responses["/rulesets"])
    inventory.append({"kind": "zone", "phase": phase})
    with pytest.raises(GateError, match="phases"):
        edge_gate(edge)


def test_edge_gate_distinguishes_available_managed_rulesets_from_zone_entrypoints() -> None:
    edge = Edge()
    inventory = cast(list[dict[str, object]], edge.responses["/rulesets"])
    inventory.append({"kind": "managed", "phase": "http_request_firewall_managed"})
    edge_gate(edge)


@pytest.mark.parametrize("malformed", ["missing", "duplicate", "unknown-kind"])
def test_edge_gate_requires_an_exact_zone_phase_inventory(malformed: str) -> None:
    edge = Edge()
    inventory = cast(list[dict[str, object]], edge.responses["/rulesets"])
    if malformed == "missing":
        inventory.pop()
    elif malformed == "duplicate":
        inventory[-1] = inventory[0]
    else:
        inventory.append({"kind": "unrecognized", "phase": "http_request_origin"})
    with pytest.raises(GateError):
        edge_gate(edge)
