"""Local death detection in a separate container; only credential cleanup is authorized."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts import qualification_deadline
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.creation_outcome import AbortRecoveryError
from scripts.m3_11_unattended.docker import Docker, controller_name
from scripts.m3_11_unattended.inventory import Inventory, fact
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle, Lifecycle, intents
from scripts.m3_11_unattended.model import (
    Credential,
    LifecycleError,
    digest,
    identity,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState, RunState
from scripts.m3_11_unattended.worker import (
    persist_terminal_result,
    restore_created,
    retained_credentials,
)


def due_processes(root: Path, docker: Docker) -> list[Path]:
    """Detect local death/deadline changes without a 1Password request."""
    due = []
    for directory in root.glob("*"):
        run_id = identity(directory.name)
        if not (directory / "attempt.json").exists():
            continue
        state = RunState(directory)
        if (directory / "status.json").exists():
            progress = state.status()
            if progress["phase"] == "finished" and progress["credential_cleanup"] == "verified":
                continue
        attempt = read_private(directory / "attempt.json")
        try:
            container = docker.owned(controller_name(run_id))
            status = container.get("State")
            alive = isinstance(status, dict) and status.get("Running") is True
        except RuntimeError, OSError, ValueError:
            # A failed daemon read is uncertainty, never proof of process death.
            alive = True
        elapsed = datetime.now(UTC) - instant(attempt["started_at"])
        expired = elapsed > timedelta(seconds=qualification_deadline.LIVE_SECONDS)
        reporting_expired = elapsed > timedelta(
            seconds=qualification_deadline.LIVE_SECONDS
            + qualification_deadline.REPORT_SECONDS
            + 4 * qualification_deadline.GRACE_SECONDS
        )
        terminal = (directory / "journey-result.json").exists()
        if not alive or terminal or reporting_expired:
            due.append(directory)
        if not alive and not terminal:
            state.interrupted()
        if expired and alive and not terminal:
            state.cancel()
            # Stop only the owned controller. Never remove guest containers/data.
            docker.command("kill", "--signal=TERM", controller_name(run_id))
    return due


def reconcile_processes(
    lifecycle: Lifecycle,
    root: Path,
    docker: Docker,
    *,
    directories: set[Path] | None = None,
    outcome_failures: set[Path] | None = None,
) -> dict[str, Credential]:
    available: dict[str, Credential] = {}
    selected = due_processes(root, docker) if directories is None else directories
    for directory in selected:
        lifecycle.request_revocation(identity(directory.name))
        try:
            restore_created(lifecycle, directory, run_id=identity(directory.name))
        except AbortRecoveryError:
            if outcome_failures is None:
                raise
            outcome_failures.add(directory)
        available.update(retained_credentials(directory))
    return available


def finish_reconciled(
    lifecycle: Lifecycle, directories: set[Path], receipt: dict[str, object]
) -> None:
    """Stop terminal retries only after complete, freshly verified owned cleanup."""
    results = receipt.get("results")
    if not isinstance(results, list):
        return
    owned = intents(lifecycle.journal)
    for directory in directories:
        # A living controller still collecting diagnostics must finish its
        # immutable journey before a new start can consider this attempt closed.
        if not (directory / "journey-result.json").exists():
            continue
        state = RunState(directory)
        # This sweep may predate a concurrent successful controller revocation.
        state.update("finished", cleanup="unresolved", preserve_verified=True)
        run_id = identity(directory.name)
        expected = {intent.sha256 for intent in owned if intent.run_id == run_id}
        local = {path.stem for path in (directory / "credential-intents").glob("*.json")}
        available = retained_credentials(directory)
        if not local <= expected or not set(available) <= expected:
            continue
        verified = [
            value
            for value in results
            if isinstance(value, dict)
            and value.get("intent_sha256") in expected
            and value.get("status") == "verified"
            and (
                value["intent_sha256"] not in available
                or value.get("negative_authentication") == "denied"
            )
        ]
        if (
            len(verified) != len(expected)
            or {value["intent_sha256"] for value in verified} != expected
        ):
            continue
        try:
            persist_terminal_result(lifecycle, directory)
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            continue
        proof = {
            "format": "lowerduckpond-m3-11-watchdog-revocation-v1",
            "binding": read_private(directory / "attempt.json")["binding"],
            "helper_revision": receipt["helper_revision"],
            "observed_at": receipt["observed_at"],
            "results": verified,
        }
        # An interrupted write leaves its original evidence intact. A later
        # successful sweep adds another receipt rather than rewriting that file.
        write_private(directory / f"watchdog-revocation-{uuid.uuid7()}.json", proof)
        for path in (directory / "credential-cleanup").glob("*.json"):
            path.unlink()
        (directory / "runtime-inputs.json").unlink(missing_ok=True)
        state.update("finished", cleanup="verified")


def quiesce_runtime(directory: Path, docker: Docker) -> dict[str, object]:  # noqa: PLR0912, PLR0915 - exact identity, shutdown and release gates
    """Stop exact owned runtime consumers without removing any retained resource.

    This is an explicit operation, never an automatic restart or data-retirement
    path. A partial proof keeps ownership held and can be reconciled in place.
    """
    import json  # noqa: PLC0415

    from scripts import qualification_restore  # noqa: PLC0415
    from scripts.m3_11_qualification_evidence import fields  # noqa: PLC0415
    from scripts.m3_11_unattended.inputs import BINDING  # noqa: PLC0415
    from scripts.m3_11_unattended.model import LifecycleError, digest, fingerprint  # noqa: PLC0415
    from scripts.m3_11_unattended.state import LeaseState  # noqa: PLC0415
    from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, RUN_ENV  # noqa: PLC0415
    from scripts.qualification_probe import document  # noqa: PLC0415

    request = read_private(directory / "request.json")
    binding = fields(request["binding"], BINDING)
    state = LeaseState(directory.parent.parent / "leases" / identity(request["lease_id"]))
    with RunState(directory).lock(), state.use_lock():
        if not (directory / "journey-result.json").exists() or read_private(
            directory / "host-drained.json"
        ) != {"binding_sha256": digest(binding), "drained": True}:
            raise LifecycleError("host commands have not established quiescence")
        contexts = list((directory / "qualification").glob("*/fixture.json"))
        if len(contexts) != 1:
            raise LifecycleError("retained runtime fixture identity is unavailable or ambiguous")
        fixture = contexts[0].parent
        environment = qualification_restore.environment_for(fixture)
        if docker.endpoint != environment["DOCKER_HOST"] or docker.info() != request["daemon"]:
            raise LifecycleError("quiescence Docker host differs from the original attempt")
        owner = environment[RUN_ENV]
        label = "lowerduckpond.qualification.run"
        created = fields(document(fixture / "case-containers.json"), {HOST_ENV, ARCHIVE_ENV})
        # Require the original complete fixture graph. An early/interrupted
        # creation without these bindings remains blocked for an exact decision.
        expected_rows: dict[str, dict[str, object]] = {}
        for kind in ("source", "destination", "acme"):
            receipt = document(fixture / "restore" / (kind + ".json"))
            row = {key: receipt[key] for key in ("id", "name", "image", "owner")}
            selected = fingerprint(row["id"])
            role = "host" if kind == "source" else kind
            if (
                row["name"] != f"/ldp-m3-{owner}-{role}"
                or row["owner"] != owner
                or selected in expected_rows
                or (kind == "source" and selected != created[HOST_ENV])
            ):
                raise LifecycleError("retained fixture receipt ownership differs")
            expected_rows[selected] = row
        archive_id = fingerprint(created[ARCHIVE_ENV])
        if archive_id in expected_rows:
            raise LifecycleError("retained fixture repeats a container identity")
        ids = (
            docker.command(
                "ps",
                "--all",
                "--filter",
                f"label={label}={owner}",
                "--no-trunc",
                "--format",
                "{{.ID}}",
            )
            .decode()
            .splitlines()
        )
        rows: list[dict[str, object]] = []
        if len(ids) != len(set(ids)) or set(ids) != {*expected_rows, archive_id}:
            raise LifecycleError("retained fixture inventory differs from its original IDs")
        for selected in sorted(ids):
            fingerprint(selected)
            raw = json.loads(docker.command("inspect", selected))
            if not isinstance(raw, list) or len(raw) != 1 or raw[0].get("Id") != selected:
                raise LifecycleError("retained fixture identity changed")
            item = raw[0]
            if item["Config"]["Labels"].get(label) != owner:
                raise LifecycleError("retained fixture ownership changed")
            row = {"id": selected, "name": item["Name"], "image": item["Image"], "owner": owner}
            if (selected != archive_id and row != expected_rows[selected]) or (
                selected == archive_id and item["Name"] != "/" + environment[ARCHIVE_ENV]
            ):
                raise LifecycleError("retained fixture differs from its original identity")
            rows.append(row)
        pending = directory / "quiescence-intent.json"
        expected: dict[str, object] = {"binding_sha256": digest(binding), "containers": rows}
        if not pending.exists():
            write_private(pending, expected)
        if read_private(pending) != expected:
            raise LifecycleError("retained fixture set changed during quiescence")
        observations = []
        for row in rows:
            selected = str(row["id"])
            docker.command("update", "--restart=no", selected)
            docker.command("stop", "--time", "20", selected)
            raw = json.loads(docker.command("inspect", selected))
            item = raw[0]
            if (
                item["Id"] != selected
                or item["Name"] != row["name"]
                or item["Image"] != row["image"]
                or item["Config"]["Labels"].get(label) != owner
                or item["State"]["Running"] is not False
                or item["HostConfig"]["RestartPolicy"]["Name"] != "no"
            ):
                raise LifecycleError(
                    "retained fixture shutdown or restart prevention is unverified"
                )
            observations.append({**row, "running": False, "restart_policy": "no"})
        if sorted(
            docker.command(
                "ps",
                "--all",
                "--filter",
                f"label={label}={owner}",
                "--no-trunc",
                "--format",
                "{{.ID}}",
            )
            .decode()
            .splitlines()
        ) != sorted(ids):
            raise LifecycleError("retained fixture inventory changed after shutdown")
        proof = {"host_commands_drained": True, "containers": observations, "complete": True}
        state.release_use(attempt_id=identity(binding["managed_run_id"]), quiescence=proof)
        return proof


def prepare_lease_cleanup(root: Path, docker: Docker, inventory: Inventory) -> bool:  # noqa: PLR0912, PLR0915 - publication and issuer fencing precede cleanup
    """Publish cancellation before any cleanup lock; fence only the exact issuer.

    A retained failed attempt is left for explicit diagnosis or quiescence. An
    unavailable daemon/publication keeps closure unresolved while provider cleanup
    can still proceed using local manifest/identity records.
    """
    durable = True
    for directory in root.iterdir():
        request_path = directory / "request.json"
        if not request_path.exists():
            continue
        request = read_private(request_path)
        if request.get("format") != "lowerduckpond-m3-11-unattended-request-v2":
            continue
        state = RunState(directory)
        lease = LeaseState(root.parent / "leases" / identity(request["lease_id"]))
        if not (lease.directory / "manifest.json").exists():
            continue
        if directory.name != lease.directory.name:
            owner = lease.directory / ("use-" + directory.name + ".json")
            if not owner.exists() or read_private(owner).get("binding_sha256") != digest(
                request["binding"]
            ):
                # A rejected competing consumer cannot cancel the incumbent lease.
                continue
        manifest = lease.manifest()
        lifecycle = LeaseLifecycle(manifest, inventory, lease, providers={})
        deadline = manifest.policy.deadline(instant(manifest.created_at))
        terminal = directory / "journey-result.json"
        outcome = read_private(terminal)["outcome"] if terminal.exists() else None
        retained = (
            outcome in {"failed", "interrupted"}
            and manifest.policy.retain_after_failure
            and (directory / "attempt-started.json").exists()
            and read_private(directory / "attempt-started.json")
            == {
                "binding_sha256": digest(request["binding"]),
                "manifest_sha256": manifest.sha256,
            }
            and not state.cancelled
            and datetime.now(UTC) < deadline
            and (lease.directory / "issuer-stopped.json").exists()
            and not any(lease.directory.glob("close-*.json"))
        )
        if retained or state.status()["credential_cleanup"] == "verified":
            continue
        try:
            selected = docker.owned(controller_name(directory.name))
            alive = isinstance(selected.get("State"), dict) and cast(
                dict[str, object], selected["State"]
            ).get("Running")
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            alive = None
        elapsed = datetime.now(UTC) - instant(
            read_private(directory / "attempt.json")["started_at"]
        )
        due = (
            state.cancelled
            or outcome is not None
            or alive is False
            or datetime.now(UTC) >= deadline
            or elapsed.total_seconds() >= qualification_deadline.LIVE_SECONDS
        )
        if not due:
            continue
        state.cancel()
        try:
            lifecycle.request_close("cancel")
        except RuntimeError, OSError, ValueError:
            durable = False
        if not (lease.directory / "issuer-stopped.json").exists():
            try:
                proof = read_private(directory / "controller-identity.json")
                actual = docker.owned(str(proof["id"]))
                if {key: actual.get(key) for key in ("Id", "Name", "Image")} != {
                    "Id": proof["id"],
                    "Name": proof["name"],
                    "Image": proof["image"],
                } or digest(docker.info()) != proof["daemon_sha256"]:
                    raise LifecycleError("original issuer identity cannot be established")
                docker.command("update", "--restart=no", str(proof["id"]))
                docker.command("stop", "--time", "20", str(proof["id"]))
                actual = docker.owned(str(proof["id"]))
                if (
                    actual.get("Id") != proof["id"]
                    or cast(dict[str, object], actual["State"])["Running"] is not False
                    or cast(
                        dict[str, object],
                        cast(dict[str, object], actual["HostConfig"])["RestartPolicy"],
                    )["Name"]
                    != "no"
                ):
                    raise LifecycleError("original issuer can still execute or restart")
                # No absent role is invented as not-submitted after interruption.
                writer = read_private(lease.directory / "issuer.json")["writer_sha256"]
                stopped = lease.finish_issuer(
                    writer_sha256=str(writer), stopped_at=stamp(datetime.now(UTC))
                )
                inventory.publish(fact(manifest, "issuer-stopped", stopped))
                state.interrupted()
            except RuntimeError, OSError, ValueError, KeyError, TypeError:
                durable = False
    return durable


def finish_leases(root: Path, receipt: dict[str, object]) -> None:
    results = receipt.get("leases")
    if not isinstance(results, list):
        return
    closed = {
        row["lease_id"]
        for row in results
        if isinstance(row, dict) and row.get("status") == "closed"
    }
    for directory in root.iterdir():
        path = directory / "request.json"
        if not path.exists():
            continue
        request = read_private(path)
        if request.get("lease_id") in closed and (directory / "journey-result.json").exists():
            RunState(directory).update("finished", cleanup="verified")


def cancel_lease(directory: Path, config_path: Path) -> dict[str, object]:
    from scripts.m3_11_unattended import cleanup  # noqa: PLC0415
    from scripts.m3_11_unattended.config import LeaseConfiguration  # noqa: PLC0415
    from scripts.m3_11_unattended.inventory import ConnectInventory  # noqa: PLC0415
    from scripts.m3_11_unattended.state import cleanup_lock  # noqa: PLC0415

    RunState(directory).cancel()
    config = LeaseConfiguration.load(config_path)
    if config.mode != "cleanup-only":
        raise LifecycleError("lease cancellation requires isolated cleanup access")
    client = config.generations[config.active_generation]["cleanup"].reader()
    inventory = ConnectInventory(
        client, config.journal_vault, spool=directory.parent.parent / "inventory-pending" / "cancel"
    )
    try:
        published = prepare_lease_cleanup(directory.parent, Docker(), inventory)
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        published = False
    with cleanup_lock(directory.parent, blocking=False):
        result = cleanup.sweep_leases(
            config, inventory, root=directory.parent.parent / "leases", actor="watchdog"
        )
        if not published:
            result["status"] = "unresolved"
        else:
            finish_leases(directory.parent, result)
    return result


def require_released_consumers(lease: LeaseState, docker: Docker) -> None:
    """Freshly recheck every original consumer under the exclusive use lock."""
    import json  # noqa: PLC0415

    for path in lease.directory.glob("use-*.json"):
        use = read_private(path)
        attempt = identity(use["attempt_id"])
        if not lease.released_use(attempt_id=attempt, binding_sha256=str(use["binding_sha256"])):
            raise LifecycleError("previous lease consumer has not established quiescence")
        original = read_private(lease.directory.parent.parent / "runs" / attempt / "request.json")
        if (
            original["daemon"] != docker.info()
            or digest(original["binding"]) != use["binding_sha256"]
        ):
            raise LifecycleError("released consumer belongs to another daemon or attempt")
        release = read_private(lease.directory / ("released-" + attempt + ".json"))
        proof = cast(dict[str, object], release["quiescence"])
        rows = cast(list[dict[str, object]], proof["containers"])
        for row in rows:
            value = json.loads(docker.command("inspect", str(row["id"])))
            if not isinstance(value, list) or len(value) != 1:
                raise LifecycleError("released consumer identity is unavailable")
            item = value[0]
            if (
                item.get("Id") != row["id"]
                or item.get("Name") != row["name"]
                or item.get("Image") != row["image"]
                or item["Config"]["Labels"].get("lowerduckpond.qualification.run") != row["owner"]
                or item["State"]["Running"] is not False
                or item["HostConfig"]["RestartPolicy"]["Name"] != "no"
            ):
                raise LifecycleError("released consumer resumed or its identity changed")
        owners = {str(row["owner"]) for row in rows}
        for owner in owners:
            listed = (
                docker.command(
                    "ps",
                    "--all",
                    "--filter",
                    "label=lowerduckpond.qualification.run=" + owner,
                    "--no-trunc",
                    "--format",
                    "{{.ID}}",
                )
                .decode()
                .splitlines()
            )
            if set(listed) != {row["id"] for row in rows if row["owner"] == owner}:
                raise LifecycleError("released consumer inventory changed")
