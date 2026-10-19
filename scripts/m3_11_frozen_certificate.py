"""Flat terminal-only disposal certificates; no recursive peer consumer trust.

Active-lease readiness still requires every original stopped actor present.
Only terminal local disposal accepts these certificates, after full retained
byte/effect/native terminal verification and a fresh empty daemon inventory.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast

from lowerduckpond_static_contracts import decode_json_object

from scripts import m3_11_frozen_actor_export as actors
from scripts import m3_11_frozen_export as export
from scripts import m3_11_frozen_remote_proof as remote
from scripts.m3_11_frozen_context import require
from scripts.m3_11_frozen_residual import Residual
from scripts.m3_11_frozen_retirement import plan as parse_plan
from scripts.m3_11_frozen_stage import Effects, authorization
from scripts.m3_11_frozen_terminal_bundle import verify as terminal
from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest, record
from scripts.m3_11_unattended.model import identity
from scripts.m3_11_unattended.state import LeaseState
from scripts.qualification_fence import require_committed

if TYPE_CHECKING:
    from scripts.m3_11_frozen_disposal import NativeLocal

FORMAT = "lowerduckpond-m3-11-terminal-disposal-certificate-v1"


def publish(owner: NativeLocal, completion: dict[str, object]) -> dict[str, object]:
    attempt = str(owner.retirement["producing_attempt"])
    use = read_private(owner.lease.directory / ("use-" + attempt + ".json"))
    release = read_private(owner.lease.directory / ("released-" + attempt + ".json"))
    value: dict[str, object] = {
        "format": FORMAT,
        "lease_id": owner.lease.manifest().lease_id,
        "manifest_sha256": owner.lease.manifest().sha256,
        "attempt_id": attempt,
        "use_sha256": digest(use),
        "release_sha256": digest(release),
        "request_sha256": digest(read_private(owner.producer / "request.json")),
        "exclusion": owner.exclusion,
        "stage_directory": str(owner.stage_root),
        "plan_sha256": digest(owner.plan),
        "completion_sha256": digest(completion),
    }
    record(owner.stage_root.parent / "disposed.json", value)
    return value


def saved_document(manifest: dict[str, object], output: Path, name: str) -> dict[str, object]:
    rows = [
        row for row in cast(list[dict[str, object]], manifest["entries"]) if row["path"] == name
    ]
    require(len(rows) == 1 and rows[0]["type"] == "file", "disposal export lost an original record")
    raw = read_private_bytes(output / "blobs" / digest(name), maximum=2 * 1024 * 1024)
    import hashlib  # noqa: PLC0415

    require(
        hashlib.sha256(raw).hexdigest() == rows[0]["sha256"],
        "disposal original record bytes differ",
    )
    return decode_json_object(raw, maximum_bytes=2 * 1024 * 1024)


def verify_absent(  # noqa: PLR0913 - exact original consumer and held local fence
    root: Path,
    lease: LeaseState,
    attempt: str,
    release: dict[str, object],
    owner: str,
    *,
    guard: Callable[[], None],
) -> dict[str, object]:
    """Caller holds the external immutable owner lock and observes no actors."""
    directory = root / "fixture-dispositions" / ("identity-" + owner + ".retired")
    certificate = fields(
        read_private(directory / "disposed.json"),
        {
            "format",
            "lease_id",
            "manifest_sha256",
            "attempt_id",
            "use_sha256",
            "release_sha256",
            "request_sha256",
            "exclusion",
            "stage_directory",
            "plan_sha256",
            "completion_sha256",
        },
    )
    manifest = lease.manifest()
    require(
        certificate["format"] == FORMAT
        and certificate["lease_id"] == manifest.lease_id
        and certificate["manifest_sha256"] == manifest.sha256
        and certificate["attempt_id"] == identity(attempt)
        and certificate["use_sha256"]
        == digest(read_private(lease.directory / ("use-" + attempt + ".json")))
        and certificate["release_sha256"] == digest(release)
        and certificate["request_sha256"]
        == digest(read_private(root / "runs" / attempt / "request.json")),
        "disposed consumer certificate differs from original release bindings",
    )
    stage = Path(str(certificate["stage_directory"]))
    selected = read_private(stage / "plan.json")
    require(
        stage == directory / ("local-" + digest(selected))
        and digest(selected) == certificate["plan_sha256"],
        "disposed consumer stage escaped its exact external ownership",
    )
    retired = parse_plan(selected["retirement_plan"])
    run = Path(str(retired["original_run"]))
    exclusion = cast(dict[str, object], certificate["exclusion"])
    require(
        retired["producing_attempt"] == attempt
        and selected["exclusion"] == exclusion
        and str(exclusion["fixture_id"]).replace("-", "") == owner
        and exclusion["plan_sha256"] == digest(retired),
        "disposed fixture exclusion differs",
    )
    require_committed(run, exclusion)
    require(not run.exists() and not run.is_symlink(), "disposed original path reappeared")
    approved = authorization(
        read_private(stage / "authorization.json"), selected, stage="local-disposal"
    )
    completion = read_private(stage / "completed.json")
    from scripts.m3_11_frozen_stage_receipt import local as validate_completion  # noqa: PLC0415

    validate_completion(completion, selected, observing=False)
    require(
        digest(completion) == certificate["completion_sha256"]
        and completion.get("plan_sha256") == digest(selected)
        and completion.get("authorization_sha256") == digest(approved)
        and completion.get("provider_calls") == 0
        and completion.get("original_directory") == "absent"
        and completion.get("qualification_changed") is False
        and completion.get("lease_changed") is False,
        "disposed consumer completion binding differs",
    )
    native = terminal(selected["terminal_selection"], lease)
    require(
        digest(native) == completion["terminal_proof_sha256"],
        "disposed native terminal proof changed",
    )
    limits = export.Limits(
        cast(int, selected["maximum_export_bytes"]), cast(int, selected["maximum_export_entries"])
    )
    destination = Path(str(selected["export_directory"]))
    preserved = export.verify_preserved(destination, limits=limits, guard=guard)
    require(
        digest(preserved) == completion["export_sha256"] and preserved["root"] == str(run),
        "disposed complete tree export changed",
    )
    fixture = cast(dict[str, object], selected["fixture"])
    require(
        digest(fixture) == retired["fixture_sha256"], "disposed original fixture binding differs"
    )
    effects = Effects(stage, plan=selected, approval=approved)
    total = cast(int, preserved["bytes"])
    for row in cast(list[dict[str, object]], fixture["actors"]):
        name = str(row["id"])
        captured = actors.verify(
            stage / "actors" / name,
            row,
            maximum_bytes=limits.bytes,
            maximum_entries=limits.entries,
            guard=guard,
        )
        require(
            digest(captured) == cast(dict[str, object], completion["actor_exports"])[name]
            and effects.submitted("remove-container-" + name, row),
            "disposed actor proof differs",
        )
        total += sum(
            cast(int, cast(dict[str, object], captured[key])["size"]) for key in ("rootfs", "logs")
        )
    require(total <= limits.bytes, "disposed full evidence exceeds approved bounds")
    original = cast(dict[str, object], preserved["metadata"])
    require(
        effects.submitted("remove-image", cast(dict[str, object], selected["image"]))
        and effects.submitted(
            "remove-directory",
            {
                "path": str(run),
                "device": original["device"],
                "inode": original["inode"],
                "export_sha256": digest(preserved),
            },
        ),
        "disposed resource removal lacks exact original intent",
    )
    remaining = Residual(run, preserved, effects, guard).observe()
    require(
        not remaining["pending"] and not remaining["unsubmitted"],
        "disposed directory entries lack exact original removal submissions",
    )
    remote_root = Path(str(selected["remote_directory"]))
    remote_receipt = read_private(remote_root / str(selected["remote_receipt_file"]))
    require(
        digest(remote_receipt) == selected["remote_receipt_sha256"],
        "disposed remote receipt changed",
    )
    remote_result = remote.verify(
        run,
        retired,
        fixture,
        manifest,
        remote_root,
        remote_receipt,
        guard=guard,
        original_storage=saved_document(preserved, destination, "live-storage.json"),
        fixture_id=str(exclusion["fixture_id"]),
    )
    require(
        digest(remote_result) == completion["remote_proof_sha256"],
        "disposed remote stage proof differs",
    )
    return certificate
