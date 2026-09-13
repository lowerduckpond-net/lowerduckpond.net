from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import urllib.request
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import ArchiveQualificationError
from lowerduckpond_static_host_agent.archive_remote import RemoteVersion

from scripts import check_m3_10_provider as provider
from scripts.check_m3_7_production_edge import CloudflareClient, ProductionEdgePreflightError
from scripts.check_m3_10_provider import (
    GateError,
    PolicyClient,
    check_edge,
    check_storage,
    expected_rules,
)
from scripts.m3_10_page_rules import PageRulesClient

from .test_m3_7_production_gate import _certificate_fixture, _CloudflareResponse

ROOT = Path(__file__).parents[2]
ARCHIVE_KEY = "archives/0198d17f-6f4a-7000-8000-000000000003.zip"
BOUND_VERSION = RemoteVersion(ARCHIVE_KEY, "v1", 4096, False)
INVENTORY_SNAPSHOTS = 2
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

        self.object_acl: object = copy.deepcopy(self.responses["get_bucket_acl"])
        self.acl_requests: list[dict[str, object]] = []

    def __getattr__(self, name: str) -> object:
        def operation(**arguments: object) -> object:
            self.calls.append(name)
            assert arguments["Bucket"] == "archive-fixture"
            if name.startswith("list_"):
                assert arguments["Prefix"] == ""
            if name == "get_object_acl":
                self.acl_requests.append(arguments)
                response = self.object_acl
            else:
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
    def __init__(self, ca_path: Path, leaf: dict[str, str]) -> None:
        self.ca_path = ca_path
        self.now = datetime.now(UTC)
        self.responses: dict[str, object] = {
            "": {
                "id": "a" * 32,
                "account": {"id": "e" * 32},
                "name": "lowerduckpond.net",
                "status": "active",
                "paused": False,
            },
            "/dns_records": [
                {"name": name, "type": "A", "content": "192.0.2.1", "proxied": True, "ttl": 1}
                for name in ("lowerduckpond.net", "*.lowerduckpond.net")
            ],
            "/settings/ssl": {"value": "strict"},
            "/settings/always_online": {"value": "off"},
            "/settings/always_use_https": {"value": "off"},
            "/origin_tls_client_auth/settings": {"enabled": True},
            "/origin_tls_client_auth/hostnames": [],
            "/origin_tls_client_auth": [{**leaf, "id": "b" * 32}],
            "/workers/routes": [],
            "/pagerules": [],
            "/rulesets": [
                {"kind": "zone", "phase": phase} for phase in expected_rules("lowerduckpond.net")
            ],
            **{
                f"/rulesets/phases/{phase}/entrypoint": {"rules": [rule]}
                for phase, rule in expected_rules("lowerduckpond.net").items()
            },
        }

    def get(self, path: str) -> object:
        if path == "/accounts/" + "e" * 32 + "/tokens/verify":
            return {"id": "f" * 32, "status": "active"}
        assert path.startswith("/zones/" + "a" * 32)
        return self.responses[path.removeprefix("/zones/" + "a" * 32)]

    def get_collection(self, path: str) -> object:
        assert not path.endswith(("/workers/routes", "/pagerules"))  # non-paginated endpoints
        return self.get(path)

    def get_cursor_collection(self, path: str) -> object:
        return self.get(path)

    def get_aop_setting(self, zone: str) -> object:
        return self.get(f"/zones/{zone}/origin_tls_client_auth/settings")


@pytest.fixture(scope="module")
def edge_certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, str]]:
    return _certificate_fixture(tmp_path_factory.mktemp("m3-10-edge"))


@pytest.fixture
def edge(edge_certificate: tuple[Path, dict[str, str]]) -> Edge:
    return Edge(*edge_certificate)


def edge_gate(edge: Edge) -> None:
    check_edge(
        cast(CloudflareClient, edge),
        page_rules_client=cast(PageRulesClient, edge),
        zone_id="a" * 32,
        certificate_id="b" * 32,
        domain="lowerduckpond.net",
        origin="192.0.2.1",
        ca_path=edge.ca_path,
        now=edge.now,
    )


def test_enforced_edge_passes_unchanged(edge: Edge) -> None:
    edge_gate(edge)


@pytest.mark.parametrize(
    "routes",
    [
        [{"id": "c" * 32, "pattern": "*lowerduckpond.net/*", "script": "unexpected"}],
        [{"id": "c" * 32, "pattern": "*lowerduckpond.net/private/*"}],
        {},
        None,
    ],
)
def test_edge_gate_rejects_workers_routes_and_malformed_inventory(
    edge: Edge, routes: object
) -> None:
    edge.responses["/workers/routes"] = routes
    with pytest.raises(GateError, match="Workers routes"):
        edge_gate(edge)


@pytest.mark.parametrize(
    "rules",
    [
        [{"status": "active", "actions": [{"id": "forwarding_url"}]}],
        [{"status": "active", "actions": [{"id": "cache_level", "value": "cache_everything"}]}],
        [{"status": "disabled", "actions": [{"id": "forwarding_url"}]}],
        {},
        None,
    ],
)
def test_edge_gate_rejects_legacy_page_rules_and_malformed_inventory(
    edge: Edge, rules: object
) -> None:
    edge.responses["/pagerules"] = rules
    with pytest.raises(GateError, match="Page Rules"):
        edge_gate(edge)


@pytest.mark.parametrize("endpoint", ["/workers/routes", "/pagerules"])
@pytest.mark.parametrize("allowed", [True, False])
def test_edge_inventory_uses_the_single_page_api_and_refuses_denial(
    edge: Edge, monkeypatch: pytest.MonkeyPatch, endpoint: str, allowed: bool
) -> None:
    client = CloudflareClient("x" * 20)
    original = edge.get
    requested: list[str] = []

    def get(path: str) -> object:
        return client.get(path) if path.endswith(endpoint) else original(path)

    def response(request: urllib.request.Request, *, timeout: int) -> _CloudflareResponse:
        assert timeout > 0
        requested.append(request.full_url)
        return _CloudflareResponse({"success": True, "result": []}, status=200 if allowed else 403)

    monkeypatch.setattr(edge, "get", get)
    monkeypatch.setattr(urllib.request, "urlopen", response)
    with nullcontext() if allowed else pytest.raises(ProductionEdgePreflightError):
        edge_gate(edge)
    assert requested == ["https://api.cloudflare.com/client/v4/zones/" + "a" * 32 + endpoint]


@pytest.mark.parametrize("paused", [True, None, "false", 0])
def test_edge_gate_requires_the_proxy_to_be_unpaused(edge: Edge, paused: object) -> None:
    zone = cast(dict[str, object], edge.responses[""])
    zone["paused"] = paused
    with pytest.raises(GateError, match="pause state"):
        edge_gate(edge)


@pytest.mark.parametrize("drift", ["near-expiry", "api-expiration", "certificate"])
def test_edge_gate_revalidates_the_actual_origin_pull_certificate(edge: Edge, drift: str) -> None:
    leaf = cast(list[dict[str, object]], edge.responses["/origin_tls_client_auth"])[0]
    if drift == "near-expiry":
        edge.now += timedelta(days=306)
    elif drift == "api-expiration":
        leaf["expires_on"] = "2000-01-01T00:00:00Z"
    else:
        leaf["certificate"] = "invalid certificate"
    with pytest.raises(ProductionEdgePreflightError):
        edge_gate(edge)


@pytest.mark.parametrize("status", [None, "pending", "moved", "deactivated"])
def test_edge_gate_requires_an_active_zone(edge: Edge, status: str | None) -> None:
    cast(dict[str, object], edge.responses[""])["status"] = status
    with pytest.raises(GateError, match="active status"):
        edge_gate(edge)


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
def test_edge_gate_refuses_policy_drift(edge: Edge, path: str, response: object) -> None:
    edge.responses[path] = response
    with pytest.raises(GateError):
        edge_gate(edge)


@pytest.mark.parametrize("phase", list(expected_rules("lowerduckpond.net")))
def test_edge_gate_refuses_extra_rules_and_changed_actions(edge: Edge, phase: str) -> None:
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


@pytest.mark.parametrize("inventory", ["preceding", "archive", "query-error"])
def test_host_gate_queries_all_unit_files_and_distinguishes_absence_from_errors(
    host_tree: Path, inventory: str
) -> None:
    systemctl = host_tree / "bin/systemctl"
    output = {
        "preceding": "printf 'caddy.service enabled enabled\\n'",
        "archive": "printf 'lowerduckpond-archive-export.socket enabled enabled\\n'",
        "query-error": "exit 1",
    }[inventory]
    systemctl.write_text(
        "#!/bin/bash\n"
        "if [[ $1 == list-unit-files ]]; then\n"
        # A patterned no-match query really returns 1 on the installed systemd.
        '    for arg in "$@"; do [[ $arg != lowerduckpond-* ]] || exit 1; done\n'
        f"    {output}\n"
        "fi\n"
    )
    outcome = host_gate(host_tree)
    if inventory == "preceding":
        assert outcome.returncode == 0, outcome.stderr
    else:
        assert outcome.returncode != 0
        expected = "could not query" if inventory == "query-error" else "units already exist"
        assert expected in outcome.stderr


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
def test_edge_gate_rejects_unexpected_zone_ruleset_phases(edge: Edge, phase: str) -> None:
    inventory = cast(list[dict[str, object]], edge.responses["/rulesets"])
    inventory.append({"kind": "zone", "phase": phase})
    with pytest.raises(GateError, match="phases"):
        edge_gate(edge)


def test_edge_gate_distinguishes_available_managed_rulesets_from_zone_entrypoints(
    edge: Edge,
) -> None:
    inventory = cast(list[dict[str, object]], edge.responses["/rulesets"])
    inventory.append({"kind": "managed", "phase": "http_request_firewall_managed"})
    edge_gate(edge)


@pytest.mark.parametrize("malformed", ["missing", "duplicate", "unknown-kind"])
def test_edge_gate_requires_an_exact_zone_phase_inventory(edge: Edge, malformed: str) -> None:
    inventory = cast(list[dict[str, object]], edge.responses["/rulesets"])
    if malformed == "missing":
        inventory.pop()
    elif malformed == "duplicate":
        inventory[-1] = inventory[0]
    else:
        inventory.append({"kind": "unrecognized", "phase": "http_request_origin"})
    with pytest.raises(GateError):
        edge_gate(edge)


def test_completed_storage_policy_allows_tenant_objects_without_reading_or_mutating_them() -> None:
    storage = Storage()
    storage.responses.update(
        list_objects_v2={"Contents": [{"Key": "tenant/archive.zip"}]},
        list_object_versions={
            "Versions": [{"Key": ARCHIVE_KEY, "VersionId": "v1", "Size": 4096}],
            "IsTruncated": False,
        },
    )
    before = copy.deepcopy(storage.responses)
    check_storage(
        cast(PolicyClient, storage),
        bucket="archive-fixture",
        require_empty=False,
        expected_versions=frozenset({BOUND_VERSION}),
    )
    assert storage.responses == before
    assert storage.acl_requests == [
        {"Bucket": "archive-fixture", "Key": ARCHIVE_KEY, "VersionId": "v1"}
    ]
    assert storage.calls.count("list_object_versions") == INVENTORY_SNAPSHOTS
    assert storage.calls.count("list_multipart_uploads") == INVENTORY_SNAPSHOTS
    assert "list_objects_v2" not in storage.calls


@pytest.mark.parametrize(
    ("operation", "response"),
    [
        ("get_bucket_acl", {"Owner": {"ID": "owner"}, "Grants": []}),
        ("get_bucket_policy", "AccessDenied"),
        ("get_bucket_policy", {"Policy": "{}"}),
        ("get_bucket_lifecycle_configuration", {"Rules": [{"Status": "Enabled"}]}),
        ("get_bucket_versioning", {"Status": "Suspended"}),
    ],
)
def test_completed_storage_policy_still_refuses_unsafe_provider_controls(
    operation: str, response: object
) -> None:
    storage = Storage()
    storage.responses[operation] = response
    with pytest.raises((GateError, ArchiveQualificationError)):
        check_storage(
            cast(PolicyClient, storage),
            bucket="archive-fixture",
            require_empty=False,
            expected_versions=frozenset(),
        )


@pytest.mark.parametrize(
    "failed_zone", [None, "lowerduckpond.net", "lowerduckpond.com", "different-account", "token"]
)
def test_completed_provider_command_rechecks_both_edges_without_emptying_storage(
    monkeypatch: pytest.MonkeyPatch, failed_zone: str | None
) -> None:
    storage = Storage()
    storage.responses["list_object_versions"] = {
        "Versions": [{"Key": ARCHIVE_KEY, "VersionId": "v1", "Size": 4096}],
        "IsTruncated": False,
    }
    for key, value in {
        "SPACES_REGION": "fra1",
        "SPACES_ARCHIVE_BUCKET": "archive-fixture",
        "SPACES_ACCESS_KEY_ID": "fixture-key",
        "SPACES_SECRET_ACCESS_KEY": "fixture-secret",
        "CLOUDFLARE_API_TOKEN": "fixture-token",
        "PRODUCTION_ORIGIN_IPV4": "192.0.2.1",
        "CLOUDFLARE_ZONE_ID": "a" * 32,
        "CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID": "b" * 32,
        "CLOUDFLARE_TENANT_ZONE_ID": "c" * 32,
        "CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID": "d" * 32,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "provider-check",
            "--allow-existing-archives",
            "--archive-authority",
            "/private/current.json",
            "--artifact",
            "c" * 64,
            "--source",
            "0" * 40,
        ],
    )
    monkeypatch.setattr(
        provider, "read_archive_authority", lambda *_args, **_kwargs: frozenset({BOUND_VERSION})
    )
    monkeypatch.setattr(provider, "make_policy_client", lambda _config: storage)
    monkeypatch.setattr(provider, "CloudflareClient", lambda _token: object())
    monkeypatch.setattr(provider, "page_rules_client", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        provider, "verified_ca_bundle", lambda **_kwargs: nullcontext(Path("/fixture/ca.pem"))
    )
    checked: list[str] = []

    def check_zone(_client: object, **arguments: object) -> str:
        domain = str(arguments["domain"])
        checked.append(domain)
        if domain == failed_zone:
            raise GateError("edge policy drifted")
        return (
            "f" if failed_zone == "different-account" and domain == "lowerduckpond.com" else "e"
        ) * 32

    monkeypatch.setattr(provider, "check_edge", check_zone)
    token_checks = []

    def check_token(_environment: object, **arguments: object) -> None:
        token_checks.append(arguments["account_id"])
        if failed_zone == "token":
            raise GateError("runtime token drifted")

    monkeypatch.setattr(provider, "check_caddy_token", check_token)
    assert provider.main() == (0 if failed_zone is None else 1)
    assert token_checks == (["e" * 32] if failed_zone in {None, "token"} else [])
    assert checked == (
        ["lowerduckpond.net"]
        if failed_zone == "lowerduckpond.net"
        else ["lowerduckpond.net", "lowerduckpond.com"]
    )
    assert storage.acl_requests == [
        {"Bucket": "archive-fixture", "Key": ARCHIVE_KEY, "VersionId": "v1"}
    ]
    assert storage.calls.count("list_object_versions") == INVENTORY_SNAPSHOTS
    assert storage.calls.count("list_multipart_uploads") == INVENTORY_SNAPSHOTS


def test_completed_provider_policy_refuses_whole_bucket_multipart_without_cleanup() -> None:
    storage = Storage()
    storage.responses["list_multipart_uploads"] = {
        "Uploads": [{"Key": "outside-qualification/archive.zip", "UploadId": "u1"}],
        "IsTruncated": False,
    }
    before = copy.deepcopy(storage.responses)
    with pytest.raises(GateError, match="multipart"):
        check_storage(
            cast(PolicyClient, storage),
            bucket="archive-fixture",
            require_empty=False,
            expected_versions=frozenset(),
        )
    assert storage.responses == before
    assert storage.calls[-1] == "list_multipart_uploads"


@pytest.mark.parametrize("selected", ["old", "replacement"])
def test_overlapping_origin_pull_trust_accepts_the_leaf_from_either_valid_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selected: str
) -> None:
    anchors: dict[str, tuple[Path, dict[str, str]]] = {}
    for name in ("old", "replacement"):
        directory = tmp_path / name
        directory.mkdir()
        anchors[name] = _certificate_fixture(directory)
    monkeypatch.setenv(
        "CADDY_ORIGIN_PULL_CA_PATHS_JSON",
        json.dumps([str(path) for path, _leaf in anchors.values()]),
    )
    with provider.verified_ca_bundle(now=datetime.now(UTC)) as bundle:
        selected_edge = Edge(bundle, anchors[selected][1])
        edge_gate(selected_edge)
    assert not bundle.exists()
    # A replacement leaf must still fail when only the old CA is trusted.
    if selected == "replacement":
        with pytest.raises(ProductionEdgePreflightError):
            edge_gate(Edge(anchors["old"][0], anchors[selected][1]))


@pytest.mark.parametrize("bad_anchor", ["relative", "duplicate", "three", "symlink", "leaf-as-ca"])
def test_origin_pull_overlap_rejects_unsafe_or_unvalidated_anchors(
    edge: Edge, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_anchor: str
) -> None:
    paths = [str(edge.ca_path)]
    other = tmp_path / "other.pem"
    if bad_anchor == "relative":
        paths.append("relative.pem")
    elif bad_anchor == "duplicate":
        paths.append(paths[0])
    elif bad_anchor == "three":
        paths.extend([str(other), str(tmp_path / "third.pem")])
    elif bad_anchor == "symlink":
        other.symlink_to(edge.ca_path)
        paths.append(str(other))
    else:
        leaf = cast(list[dict[str, str]], edge.responses["/origin_tls_client_auth"])[0]
        other.write_text(leaf["certificate"])
        paths.append(str(other))
    monkeypatch.setenv("CADDY_ORIGIN_PULL_CA_PATHS_JSON", json.dumps(paths))
    with (
        pytest.raises((GateError, ProductionEdgePreflightError)),
        provider.verified_ca_bundle(now=datetime.now(UTC)),
    ):
        pytest.fail("unsafe overlapping trust was accepted")


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", None),
        ("id", "c" * 32),
        ("account", None),
        ("account", {}),
        ("account", {"id": "E" * 32}),
        ("account", {"id": 3}),
        ("account", {"id": "e" * 31}),
    ],
)
def test_edge_gate_rejects_mismatched_zone_and_malformed_account(
    edge: Edge, field: str, value: object
) -> None:
    cast(dict[str, object], edge.responses[""])[field] = value
    with pytest.raises(GateError, match="identity"):
        edge_gate(edge)
