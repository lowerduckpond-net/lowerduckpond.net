"""One production-policy journey spanning portable content, archive, and reboot."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import full_size_fixture as full_size
import test_archive_lifecycle as archives
import test_lifecycle as support
from independent_fixture import require_owned_fixture
from testinfra.host import Host

from scripts.qualification_context import ARTIFACT_ENV, RUN_ENV

_CONTENT = full_size.INDEX


def _context_path() -> Path:
    return Path(os.environ[ARTIFACT_ENV]).parent.parent / "cross-feature.json"


def test_cross_feature_before_reboot(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    assert support._initialize_namespace(host), "journey must begin on a fresh host"
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    history: list[tuple[dict[str, object], dict[str, object]]] = []

    def submit(
        operation: str,
        *,
        artifact: bytes | None = None,
        export: Path | None = None,
        **fields: object,
    ) -> dict[str, object]:
        request = support._request(operation, str(uuid.uuid7()), **fields)
        result = support._submit(
            tmp_path, *connection, request, artifact=artifact, export_path=export
        )
        assert result["status"] == "succeeded", result
        if artifact is None and export is None:
            history.append((request, result))
        return result

    slug = f"m3-journey-{uuid.uuid7().hex[-12:]}"
    source = submit(
        "create", slug=slug, quotas={"storageMiB": 100, "entries": full_size.ENTRY_COUNT}
    )
    source_id, source_origin = str(source["tenantId"]), str(source["canonicalOrigin"])
    payload = full_size.deployment()
    expected_digest = full_size.content_digest(payload)
    deployed = submit("deploy", tenantId=source_id, artifact=payload)
    full_size.assert_worker_budget(host, deployed)
    assert (
        full_size.installed_digest(host, source_id, support._desired_deployment(deployed))
        == expected_digest
    )
    bundle = tmp_path / "portable.zip"
    submit("export", tenantId=source_id, export=bundle)
    copied = submit(
        "create",
        slug=f"{slug}-copy",
        quotas={"storageMiB": 100, "entries": full_size.ENTRY_COUNT},
    )
    copy_id, copy_origin = str(copied["tenantId"]), str(copied["canonicalOrigin"])
    imported = submit("import", tenantId=copy_id, artifact=bundle.read_bytes())
    assert support._desired_deployment(imported) != support._desired_deployment(deployed)
    full_size.assert_worker_budget(host, imported)
    assert (
        full_size.installed_digest(host, copy_id, support._desired_deployment(imported))
        == expected_digest
    )
    support._assert_route(host, copy_origin, status=200, body=_CONTENT)
    archived = submit("archive", tenantId=source_id)
    assert support._lifecycle(archived) == "archived"
    full_size.assert_worker_budget(host, archived)
    assert len(archives._remote_versions(host)) == 1
    support._assert_route(host, source_origin, status=404)
    restored = submit("restore", tenantId=source_id)
    assert support._lifecycle(restored) == "active"
    full_size.assert_worker_budget(host, restored)
    assert (
        full_size.installed_digest(host, source_id, support._desired_deployment(restored))
        == expected_digest
    )
    assert support._desired_deployment(restored) != support._desired_deployment(deployed)
    assert not archives._remote_versions(host)
    support._assert_route(host, source_origin, status=200, body=_CONTENT)
    renamed_slug = f"{slug}-renamed"
    renamed = submit("rename", tenantId=copy_id, slug=renamed_slug)
    assert renamed["canonicalOrigin"] == copy_origin
    suspended = submit("suspend", tenantId=copy_id)
    assert support._lifecycle(suspended) == "suspended"
    support._assert_route(host, copy_origin, status=404)
    with _context_path().open("x", encoding="ascii") as stream:
        json.dump(
            {
                "run_id": os.environ[RUN_ENV],
                "content_digest": expected_digest,
                "source_deployment": support._desired_deployment(restored),
                "copy_deployment": support._desired_deployment(imported),
                "history": history,
                "source_id": source_id,
                "source_origin": source_origin,
                "copy_id": copy_id,
                "copy_origin": copy_origin,
                "copy_slug": renamed_slug,
                "source_manifest": support._manifest(restored),
                "copy_manifest": support._manifest(suspended),
            },
            stream,
        )


def test_cross_feature_after_reboot(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    context = json.loads(_context_path().read_text(encoding="ascii"))
    assert context["run_id"] == os.environ[RUN_ENV]
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    # Durable exact retries must retain their original result despite later state
    # transitions and restart. No record is deleted or rewritten to gain credit.
    for request, expected in context["history"]:
        assert support._submit(tmp_path, *connection, request) == expected
    for prefix in ("source", "copy"):
        assert (
            support._read_state(
                host, f"{support.STATE_ROOT}/tenants/{context[prefix + '_id']}/desired.json"
            )
            == context[prefix + "_manifest"]
        )
    for prefix in ("source", "copy"):
        assert (
            full_size.installed_digest(
                host, context[prefix + "_id"], context[prefix + "_deployment"]
            )
            == context["content_digest"]
        )
    support._assert_route(host, context["source_origin"], status=200, body=_CONTENT)
    support._assert_route(host, context["copy_origin"], status=404)
    resumed = support._submit(
        tmp_path,
        *connection,
        support._request("resume", str(uuid.uuid7()), tenantId=context["copy_id"]),
    )
    assert resumed["status"] == "succeeded"
    assert support._lifecycle(resumed) == "active"
    support._assert_route(host, context["copy_origin"], status=200, body=_CONTENT)
    support._assert_route(
        host,
        f"{context['copy_slug']}.lowerduckpond.com",
        status=302,
        redirect=f"https://{context['copy_origin']}/",
    )
    assert not archives._remote_versions(host)
