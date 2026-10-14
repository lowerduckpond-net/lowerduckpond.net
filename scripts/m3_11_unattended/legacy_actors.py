"""Original bindings for legacy controllers and the retained manual diagnostic.

Observed container identity is approval input, not a claim that an old worker
record historically attested its image. These readers never stop an actor.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.creation_outcome import run_payload
from scripts.m3_11_unattended.docker import EVIDENCE_VOLUME, OWNER, Docker, helper_volume
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.journal import validate
from scripts.m3_11_unattended.legacy_terminal import original_run, terminal
from scripts.m3_11_unattended.lifecycle import _intents, _known_id
from scripts.m3_11_unattended.model import (
    Intent,
    LifecycleError,
    digest,
    fingerprint,
    identity,
    instant,
)
from scripts.production_qualification_inputs import revision

MANUAL_EVENTS = {
    "run-event.json",
    "intent-event.json",
    "created-event.json",
    "negative-required-event.json",
    "retained-record-unresolved-event.json",
}
DESCRIPTOR = {"container_id", "kind", "run_id", "directory"}


def descriptor(value: object) -> dict[str, object]:
    raw = fields(value, DESCRIPTOR)
    if raw["kind"] == "retained-diagnostic":
        fingerprint(raw["container_id"])
        if raw["run_id"] is not None or raw["directory"] is not None:
            raise LifecycleError("retained diagnostic cannot fabricate an original run")
        return raw
    selected, run_id = fingerprint(raw["container_id"]), identity(raw["run_id"])
    directory = raw["directory"]
    if raw["kind"] not in {"controller", "manual-page-rules"} or not isinstance(directory, str):
        raise LifecycleError("legacy actor kind or directory is invalid")
    path = Path(directory)
    parent = "runs" if raw["kind"] == "controller" else "manual-page-rules"
    if (
        not path.is_absolute()
        or path.name != run_id
        or path.parent.name != parent
        or path.resolve() != path
    ):
        raise LifecycleError("legacy actor original directory is invalid")
    return {
        "container_id": selected,
        "kind": str(raw["kind"]),
        "run_id": run_id,
        "directory": directory,
    }


def original_file(path: Path, retained: dict[str, str]) -> dict[str, object]:
    if retained.get(str(path)) != hashlib.sha256(read_private_bytes(path)).hexdigest():
        raise LifecycleError("legacy actor original is missing or changed")
    return read_private(path)


def manual_original(
    directory: Path, records: list[dict[str, object]], retained: dict[str, str]
) -> dict[str, object]:
    run = validate(original_file(directory / "run-event.json", retained))
    payload = run_payload(run["payload"])
    binding = fields(payload["binding"], BINDING)
    run_id = identity(binding["managed_run_id"])
    revision(binding["source_revision"])
    revision(binding["helper_revision"])
    for key in BINDING - {"managed_run_id", "source_revision", "helper_revision"}:
        fingerprint(binding[key])
    fingerprint(payload["approval_sha256"])
    started = fields(
        original_file(directory / "worker-started.json", retained), {"run_id", "started_at"}
    )
    instant(started["started_at"])
    intent = Intent.parse(original_file(directory / "intent.json", retained))
    intent_event = validate(original_file(directory / "intent-event.json", retained))
    created = validate(original_file(directory / "created-event.json", retained))
    for name in MANUAL_EVENTS:
        path = directory / name
        if path.exists() or path.is_symlink():
            original_file(path, retained)
    if any(
        row["run_id"] == run_id and row["kind"] == "run" and row["payload"] != run["payload"]
        for row in records
    ):
        raise LifecycleError("manual original run bindings conflict")
    if (
        directory.name != run_id
        or started["run_id"] != run_id
        or run["run_id"] != run_id
        or run["kind"] != "run"
        or payload["mode"] != "rehearsal"
        or intent.run_id != run_id
        or intent.role != "page-rules"
        or intent.provider != "cloudflare-user"
        or intent.source_revision != binding["source_revision"]
        or intent.helper_revision != binding["helper_revision"]
        or intent.targets.storage_digest != binding["storage_target_sha256"]
        or intent_event["kind"] != "intent"
        or intent_event["run_id"] != run_id
        or intent_event["payload"] != intent.document()
        or created["kind"] != "created"
        or created["run_id"] != run_id
        or created["payload"]
        != {"intent_sha256": intent.sha256, "credential_id": _known_id(records, intent)}
        or any(row not in records for row in (run, intent_event, created))
        or [i for i in _intents(records) if i.run_id == run_id] != [intent]
    ):
        raise LifecycleError("manual legacy actor differs from its original run and intent")
    credential = directory / "credential.json"
    if str(credential) not in retained:
        raise LifecycleError("manual legacy credential is outside the reviewed inventory")
    if credential.exists() or credential.is_symlink():
        raw = fields(original_file(credential, retained), {"identifier", "secret"})
        if (
            raw["identifier"] != _known_id(records, intent)
            or not isinstance(raw["secret"], str)
            or not raw["secret"]
        ):
            raise LifecycleError("manual legacy credential identity differs")
    else:
        proof = terminal(intent, records, credential_expected=True)
        if proof is None or proof.negative_authentication != "denied":
            raise LifecycleError("missing manual legacy credential lacks original denial")
    return {"run": run, "started": started, "intent": intent_event, "created": created}


def projection(actual: dict[str, object]) -> dict[str, object]:
    config = actual.get("Config")
    if not isinstance(config, dict):
        raise LifecycleError("legacy actor configuration is unavailable")
    labels = config.get("Labels")
    mounts = actual.get("Mounts")
    if not isinstance(labels, dict) or labels.get(OWNER) != "true" or not isinstance(mounts, list):
        raise LifecycleError("legacy actor ownership or mounts are unavailable")
    projected = []
    for raw in mounts:
        if not isinstance(raw, dict):
            raise LifecycleError("legacy actor mount is invalid")
        projected.append(
            {key: raw.get(key) for key in ("Type", "Name", "Source", "Destination", "RW")}
        )
    image = actual.get("Image")
    if not isinstance(image, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None:
        raise LifecycleError("legacy actor image is invalid")
    return {
        "container_id": fingerprint(actual.get("Id")),
        "name": actual.get("Name"),
        "image": image,
        "source_revision": revision(labels.get(OWNER + ".source")),
        "purpose": labels.get(OWNER + ".purpose"),
        "command_sha256": digest(
            {"command": config.get("Cmd"), "entrypoint": config.get("Entrypoint")}
        ),
        "mounts": sorted(projected, key=lambda row: str(row["Destination"])),
    }


def observe(
    docker: Docker, raw: object, records: list[dict[str, object]], retained: dict[str, str]
) -> dict[str, object]:
    actor = descriptor(raw)
    if actor["kind"] == "retained-diagnostic":
        from scripts.m3_11_unattended.legacy_diagnostics import (  # noqa: PLC0415
            original as diagnostic_original,
        )

        inspected = docker.owned(str(actor["container_id"]))
        return {
            **actor,
            "identity": projection(inspected),
            "original_sha256": diagnostic_original(docker, inspected),
        }
    directory = Path(str(actor["directory"]))
    if actor["kind"] == "controller":
        for kind in ("credential-created", "credential-aborted", "credential-cleanup"):
            for path in (directory / kind).glob("*.json"):
                original_file(path, retained)
    original = (
        original_run(directory, records, retained, allow_empty=True)
        if actor["kind"] == "controller"
        else manual_original(directory, records, retained)
    )
    binding = fields(
        original["binding"]
        if actor["kind"] == "controller"
        else cast(dict[str, dict[str, object]], original["run"])["payload"]["binding"],
        BINDING,
    )
    actual = projection(docker.owned(str(actor["container_id"])))
    expected_name = (
        "/ldp-m311-"
        + ("controller-" if actor["kind"] == "controller" else "page-rules-probe-")
        + uuid.UUID(str(actor["run_id"])).hex
    )
    if actual["name"] != expected_name or actual["source_revision"] != binding["helper_revision"]:
        raise LifecycleError("legacy actor name or source differs from its originals")
    if actor["kind"] == "controller":
        if actual["image"] != original["controller_image"] or docker.info() != original["daemon"]:
            raise LifecycleError("legacy controller image or daemon differs from its request")
    elif actual["purpose"] != "single-page-rules-diagnostic":
        raise LifecycleError("manual actor purpose differs")
    expected = {
        "/opt/lifecycle": (helper_volume(str(binding["helper_revision"])), False),
        "/evidence": (EVIDENCE_VOLUME, True),
    }
    if actor["kind"] == "manual-page-rules":
        expected["/probe"] = (
            "ldp-m311-manual-page-rules-" + uuid.UUID(str(actor["run_id"])).hex,
            False,
        )
    mounts = cast(list[dict[str, object]], actual["mounts"])
    for destination, (name, writable) in expected.items():
        selected = [row for row in mounts if row["Destination"] == destination]
        if len(selected) != 1 or (selected[0]["Type"], selected[0]["Name"], selected[0]["RW"]) != (
            "volume",
            name,
            writable,
        ):
            raise LifecycleError("legacy actor original volume binding differs")
    return {**actor, "identity": actual, "original_sha256": digest(original)}


def inventory(docker: Docker) -> set[str]:
    rows = (
        docker.command(
            "ps",
            "--all",
            "--filter",
            "label=" + OWNER + "=true",
            "--no-trunc",
            "--format",
            "{{.ID}} {{.Names}}",
        )
        .decode()
        .splitlines()
    )
    actors = set()
    for row in rows:
        selected, name = row.split(" ", 1)
        if name.startswith(("ldp-m311-controller-", "ldp-m311-page-rules-probe-")):
            if selected in actors:
                raise LifecycleError("legacy actor inventory repeats an identity")
            actors.add(fingerprint(selected))
        else:
            # Docker utilities have generated names. Their read-only utility
            # command is not an issuer; never classify an arbitrary owned actor
            # by a permissive name prefix.
            value = docker.owned(selected)
            config = value.get("Config", {})
            if not isinstance(config, dict):
                raise LifecycleError("owned legacy actor configuration is unavailable")
            command = config.get("Cmd", [])
            watchdog = [
                "uv",
                "run",
                "--no-sync",
                "--frozen",
                "python",
                "-m",
                "scripts.m3_11_unattended.cleanup",
                "--config",
                "/cleanup/cleanup.json",
                "--actor",
                "watchdog",
                "--watch",
                "--runs",
                "/evidence/runs",
            ]
            utility = [
                "uv",
                "run",
                "--no-sync",
                "--frozen",
                "python",
                "-m",
                "scripts.m3_11_unattended.connect_activate",
                "daemon-utility",
            ]
            permitted = (
                (
                    re.fullmatch(r"ldp-m311-watchdog-[a-f0-9]{12}", name) is not None
                    and command
                    in (
                        watchdog,
                        [*watchdog, "--journal-cache", "/evidence/cleanup-journal-cache.json"],
                    )
                )
                or command == utility
                or import_watchdog(docker, value)
            )
            if not permitted or config.get("Entrypoint") not in (
                None,
                [],
                ["/usr/local/bin/mise", "exec", "--"],
            ):
                # Unknown processes require explicit discovery and a fence;
                # a diagnostic-looking name cannot exempt them.
                actors.add(fingerprint(selected))
    return actors


def import_watchdog(docker: Docker, actual: dict[str, object]) -> bool:
    """Exempt only the exact reviewed cleanup bridge, never a name-only reader."""
    from scripts.m3_11_unattended import legacy_import_reader as bridge  # noqa: PLC0415
    from scripts.m3_11_unattended.legacy_diagnostics import script_digest  # noqa: PLC0415

    config = actual.get("Config")
    if not isinstance(config, dict) or not str(actual.get("Name", "")).startswith(
        "/ldp-m311-import-watchdog-"
    ):
        return False
    command, labels = config.get("Cmd"), config.get("Labels")
    expected = hashlib.sha256(Path(bridge.__file__).read_bytes()).hexdigest()
    if (
        actual.get("Name") != "/ldp-m311-import-watchdog-" + expected[:12]
        or not isinstance(command, list)
        or len(command) != len(bridge.watchdog_command("", ""))
        or not isinstance(labels, dict)
        or labels.get(OWNER + ".source") != bridge.LEGACY_REVISION
        or config.get("Entrypoint") not in (None, [], ["/usr/local/bin/mise", "exec", "--"])
        or not isinstance(command[9], str)
        or re.fullmatch(r"[a-z0-9]{26}", command[9]) is None
        or not isinstance(command[11], str)
        or re.fullmatch(r"[a-f0-9]{64}", command[11]) is None
        or command != bridge.watchdog_command(command[9], command[11])
    ):
        return False
    return (
        script_digest(docker, str(actual["Id"]), bridge.PROGRAM) == expected
        and script_digest(
            docker,
            str(actual["Id"]),
            "/opt/lifecycle/scripts/m3_11_unattended/connect_ledger.py",
        )
        == bridge.LEDGER_SHA256
    )


def require_import_readers(docker: Docker, *, vault: str, expected: str) -> None:
    """Before introducing the import, fence every unbridged host reader.

    GitHub jobs and its explicit bridge selection are a separate operator gate.
    This never stops a reader or treats a running bridge as a cleanup receipt.
    """
    from scripts.m3_11_unattended import legacy_import_reader as bridge  # noqa: PLC0415

    rows = (
        docker.command(
            "ps",
            "--all",
            "--filter",
            "label=" + OWNER + "=true",
            "--no-trunc",
            "--format",
            "{{.ID}} {{.Names}}",
        )
        .decode()
        .splitlines()
    )
    readers = compatible = 0
    seen = set()
    for row in rows:
        selected, name = row.split(" ", 1)
        if selected in seen:
            raise LifecycleError("legacy reader inventory repeats an identity")
        seen.add(fingerprint(selected))
        if not name.startswith(("ldp-m311-watchdog-", "ldp-m311-import-watchdog-")):
            continue  # Other actors are checked by the original issuer fence gate.
        readers += 1
        actual = docker.owned(selected)
        state = cast(dict[str, object], actual.get("State", {}))
        if import_watchdog(docker, actual):
            config = cast(dict[str, object], actual["Config"])
            if config["Cmd"] != bridge.watchdog_command(vault, expected):
                raise LifecycleError("legacy import reader approval differs")
            if state.get("Running") is True and all(
                state.get(key) is False for key in ("Restarting", "Paused", "Dead")
            ):
                compatible += 1
            continue
        host = cast(dict[str, object], actual.get("HostConfig", {}))
        if (
            state.get("Running") is not False
            or any(state.get(key) is True for key in ("Restarting", "Paused", "Dead"))
            or host.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0}
        ):
            raise LifecycleError("unbridged legacy reader may still execute or restart")
    if readers and not compatible:
        raise LifecycleError("legacy import has no running compatible host cleanup reader")


def fenced(docker: Docker, actor: dict[str, object]) -> dict[str, str]:
    actual = docker.owned(str(actor["container_id"]))
    if actor["kind"] == "retained-diagnostic":
        from scripts.m3_11_unattended.legacy_diagnostics import original  # noqa: PLC0415

        if original(docker, actual) != actor["original_sha256"]:
            raise LifecycleError("retained diagnostic source changed after discovery")
    state = actual.get("State", {})
    host = actual.get("HostConfig", {})
    if (
        projection(actual) != actor["identity"]
        or not isinstance(state, dict)
        or not isinstance(host, dict)
        or state.get("Running") is not False
        or any(state.get(key) is True for key in ("Restarting", "Paused", "Dead"))
        or host.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0}
    ):
        raise LifecycleError("legacy actor fence or original identity changed")
    result = {key: str(state.get(key)) for key in ("StartedAt", "FinishedAt")}
    for value in result.values():
        instant(value)
    return result


def manual_credentials(mapping: dict[str, object]) -> dict[str, str]:
    result = {}
    for row in cast(list[dict[str, object]], mapping["issuers"]):
        actor = row.get("actor")
        if isinstance(actor, dict) and actor.get("kind") == "manual-page-rules":
            result[str(Path(str(actor["directory"])) / "credential.json")] = str(actor["run_id"])
    return result


def credential_intents(
    mapping: dict[str, object], records: list[dict[str, object]]
) -> dict[str, Intent]:
    originals = {item.sha256: item for item in _intents(records)}
    result = {}
    for filename in cast(dict[str, str], mapping["retained_files"]):
        path = Path(filename)
        if path.parent.name == "credential-cleanup":
            if path.stem not in originals or originals[path.stem].run_id != path.parent.parent.name:
                raise LifecycleError("retained legacy credential lacks its original intent")
            result[filename] = originals[path.stem]
    for filename, run_id in manual_credentials(mapping).items():
        matches = [item for item in originals.values() if item.run_id == run_id]
        if len(matches) != 1 or filename not in cast(dict[str, str], mapping["retained_files"]):
            raise LifecycleError("manual credential lacks its unique original intent")
        result[filename] = matches[0]
    return result
