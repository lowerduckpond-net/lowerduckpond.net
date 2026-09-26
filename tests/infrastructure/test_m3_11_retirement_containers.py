"""Stopping authority is limited to the original incarnations and durable intent."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import m3_11_retirement_docker as containers
from scripts import m3_11_retirement_minio as minio
from scripts import qualification_restore as owned
from scripts.qualification_context import ARCHIVE_ENV, RUN_ENV


@pytest.fixture
def frozen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[containers.Containers, dict[str, object], Mock]:
    tmp_path.chmod(0o700)
    subject = object.__new__(containers.Containers)
    subject.environment = {}
    identities = {kind: {"id": kind + "-original"} for kind in ("source", "destination", "acme")}
    states = {
        kind: {"started_at": "original", "restarts": 0, "running": True, "status": "running"}
        for kind in identities
    }
    subject.state = Mock(side_effect=lambda _: copy.deepcopy(states))  # type: ignore[method-assign]
    intent: dict[str, object] = {"containers": identities, "states": copy.deepcopy(states)}
    image = {
        "size": containers.IMAGE_BYTES,
        "uid": 0,
        "mode": 0o666,
        "links": 1,
        "device": 1,
        "inode": 1,
    }
    intent["backing_images"] = dict.fromkeys(("source", "destination"), image)
    monkeypatch.setattr(
        containers.LiveReader, "_command", Mock(return_value=json.dumps(image).encode())
    )

    def stop(_environment: object, *args: str, **_kwargs: object) -> bytes:
        identity = args[-1]
        kind = identity.removesuffix("-original")
        assert args[:4] == ("docker", "stop", "--time", "60")
        assert kind in identities
        assert (tmp_path / ("stop-" + kind + ".json")).exists()
        states[kind].update(running=False, status="exited")
        return b""

    command = Mock(side_effect=stop)
    monkeypatch.setattr(owned, "command", command)
    subject.state.live = states
    return subject, intent, command


def test_freeze_stops_only_saved_ids_and_resumes_a_lost_stop_response(
    frozen: tuple[containers.Containers, dict[str, object], Mock], tmp_path: Path
) -> None:
    subject, intent, command = frozen
    stop = command.side_effect
    assert callable(stop)

    def lost(*args: object, **kwargs: object) -> bytes:
        stop(*args, **kwargs)
        raise TimeoutError("stop reply lost")

    command.side_effect = lost
    with pytest.raises(TimeoutError):
        subject.freeze(tmp_path, intent)
    command.side_effect = stop
    subject.freeze(tmp_path, intent)
    assert [call.args[-1] for call in command.call_args_list] == [
        "destination-original",
        "source-original",
        "acme-original",
    ]
    subject.stopped(intent)
    subject.freeze(tmp_path, intent)
    assert command.call_count == len(intent["containers"])  # type: ignore[arg-type]


@pytest.mark.parametrize("damage", ["restart", "changed-start", "unrecorded-stop"])
def test_changed_incarnation_or_unrecorded_stop_cannot_be_adopted(
    frozen: tuple[containers.Containers, dict[str, object], Mock], tmp_path: Path, damage: str
) -> None:
    subject, intent, command = frozen
    live = subject.state.live  # type: ignore[attr-defined]
    live["destination"].update(
        {
            "restart": {"restarts": 1},
            "changed-start": {"started_at": "new"},
            "unrecorded-stop": {"running": False, "status": "exited"},
        }[damage]
    )
    with pytest.raises((ValueError, FileNotFoundError)):
        subject.freeze(tmp_path, intent)
    command.assert_not_called()


@pytest.mark.parametrize("damage", [None, "replacement", "image", "owner", "auto-restart"])
def test_current_container_must_match_saved_identity_without_automatic_restart(
    monkeypatch: pytest.MonkeyPatch, damage: str | None
) -> None:
    subject = object.__new__(containers.Containers)
    subject.environment = {}
    expected: dict[str, object] = {
        "id": "saved-id",
        "name": "/saved-name",
        "owner": "saved-owner",
        "image": "saved-image",
    }
    current = dict(expected)
    if damage in {"replacement", "image", "owner"}:
        current["id" if damage == "replacement" else damage] = "foreign"
    monkeypatch.setattr(owned, "inspect", Mock(return_value=current))
    monkeypatch.setattr(containers, "snapshot", Mock(return_value={"running": True}))
    subject.api = Mock()
    subject.api.inspect_container.return_value = {
        "HostConfig": {"RestartPolicy": {"Name": "always" if damage == "auto-restart" else "no"}}
    }
    if damage:
        with pytest.raises(ValueError):
            subject.state({"source": expected})
    else:
        assert subject.state({"source": expected}) == {"source": {"running": True}}


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "environment",
        "duplicate-environment",
        "mount",
        "privileged",
        "host-namespace",
        "security-option",
        "entrypoint",
        "command",
        "recipe",
        "owner",
    ],
)
def test_unused_minio_has_only_observation_authority(
    monkeypatch: pytest.MonkeyPatch, damage: str | None
) -> None:
    recipe = b"the historical local server recipe"
    sha = hashlib.sha256(recipe).hexdigest()
    environment = {
        ARCHIVE_ENV: "unused-minio",
        RUN_ENV: "original-owner",
        "M3_10_ARCHIVE_BACKEND": "spaces",
        "M3_11_COMBINED_BACKEND": "spaces",
    }
    context = SimpleNamespace(environment=environment, context={"source_revision": "a" * 40})
    identity = {
        "id": "current-only",
        "name": "/unused-minio",
        "owner": "original-owner",
        "image": "local-image",
    }
    labels = {"net.lowerduckpond.fixture.minio-recipe": sha}
    image = {
        "Config": {
            "Env": ["PATH=/usr/bin"],
            "Labels": labels,
        }
    }
    environment_values = [
        "PATH=/usr/bin",
        "MINIO_ROOT_USER=molecule-m3-10-root",
        "MINIO_ROOT_PASSWORD=molecule-m3-10-disposable-root-secret",  # gitleaks:allow
        "MINIO_REGION_NAME=ams3",
    ]
    host: dict[str, object] = {"Privileged": False, "NetworkMode": "default"}
    config = {
        "Image": "ldp-minio-fixture:" + sha,
        "Entrypoint": ["/usr/bin/minio"],
        "Cmd": ["server", "/data", "--address", ":443", "--certs-dir", "/certs"],
        "Env": environment_values,
    }
    raw = {
        "Config": config,
        "HostConfig": host,
        "Path": "/usr/bin/minio",
        "Args": config["Cmd"],
        "Mounts": [],
    }
    if damage == "environment":
        environment_values.append("SPACES_ACCESS_KEY_ID=private-canary")
    elif damage == "duplicate-environment":
        environment_values.append("PATH=/other")
    elif damage == "mount":
        raw["Mounts"] = [{"Source": "/credentials"}]
    elif damage == "privileged":
        host["Privileged"] = True
    elif damage == "host-namespace":
        host["PidMode"] = "host"
    elif damage == "security-option":
        host["SecurityOpt"] = ["seccomp=unconfined"]
    elif damage == "entrypoint":
        raw["Path"] = "/bin/sh"
    elif damage == "command":
        config["Cmd"] = ["mc", "mirror"]
    elif damage == "recipe":
        labels["net.lowerduckpond.fixture.minio-recipe"] = "b" * 64
    elif damage == "owner":
        identity["owner"] = "foreign-owner"
    monkeypatch.setattr(owned, "inspect", Mock(return_value=identity))
    command = Mock(return_value=recipe)
    monkeypatch.setattr(owned, "command", command)
    api = Mock()
    api.inspect_container.return_value = raw
    api.inspect_image.return_value = image
    if damage:
        with pytest.raises(ValueError):
            minio.observe(context, api)  # type: ignore[arg-type]
    else:
        result = minio.observe(context, api)  # type: ignore[arg-type]
        assert result["authority"] == "observation-only; leave-untouched"
        assert result["current_id"] == "current-only"
    assert all(call.args[1] == "git" for call in command.call_args_list)
    api.stop.assert_not_called()
    api.remove_container.assert_not_called()
