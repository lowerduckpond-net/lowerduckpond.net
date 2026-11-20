from __future__ import annotations

import json
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import qualification_disposable_cleanup as cleanup
from scripts import qualification_disposition as disposition
from scripts import qualification_failure as failure
from scripts import qualification_local as local
from scripts import qualification_retirement
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV, RUN_ENV, resource_names, run_lease


@pytest.fixture
def fixture_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    environment = resource_names(uuid.uuid7().hex)
    environment.update(
        {
            "DOCKER_HOST": "unix:///disposable/docker.sock",
            "M3_10_ARCHIVE_BACKEND": "minio",
            ARTIFACT_ENV: str(tmp_path / "fixture/static-host-agent.tar"),
        }
    )
    (tmp_path / "fixture").mkdir()
    (tmp_path / "fixture.json").write_text(
        json.dumps({"format": "lowerduckpond-local-qualification-fixture-v1"})
    )
    (tmp_path / "run.lock").touch(mode=0o600)
    (tmp_path / "disposable-result.json").write_text(
        json.dumps(
            {
                "format": cleanup.RESULT_FORMAT,
                "run_id": environment[RUN_ENV],
                "outcome": "passed",
                "diagnostics": "completed-run",
            }
        )
    )
    monkeypatch.setattr(qualification_retirement, "environment_for", lambda _: environment)
    monkeypatch.setattr(cleanup, "daemon_id", lambda _: "original-daemon")
    monkeypatch.setattr(cleanup, "remove_owned_image", lambda _: None)
    cleanup.bind(tmp_path, environment)
    return environment


@pytest.fixture
def docker(
    monkeypatch: pytest.MonkeyPatch, fixture_context: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    owner = fixture_context[RUN_ENV]
    containers = {"host": "a" * 64, "archive": "b" * 64, "destination": "c" * 64, "acme": "d" * 64}
    removed: list[str] = []

    def command(args: list[str], **kwargs: object) -> bytes:
        assert kwargs["environment"] == fixture_context
        if args[1:3] == ["container", "ls"]:
            selected = (
                args[args.index("--filter") + 1].split("^")[1].removeprefix("/").removesuffix("$")
            )
            role = selected.removeprefix(f"ldp-m3-{owner}-")
            return containers.get(role, "").encode()
        if args[1] == "inspect":
            role = next(role for role, identity in containers.items() if identity == args[-1])
            return json.dumps(
                {"id": args[-1], "name": f"/ldp-m3-{owner}-{role}", "owner": owner}
            ).encode()
        if args[1] == "ps":
            return "\n".join(containers.values()).encode()
        raise AssertionError("unexpected Docker observation")

    def remove(_environment: dict[str, str], identity: str) -> None:
        role = next(role for role, current in containers.items() if current == identity)
        removed.append(role)
        del containers[role]

    monkeypatch.setattr(cleanup, "bounded_command", command)
    monkeypatch.setattr(cleanup, "remove_exact", remove)
    return containers, removed


def test_removes_only_bound_disposable_graph_and_preserves_evidence(
    tmp_path: Path, fixture_context: dict[str, str], docker: tuple[dict[str, str], list[str]]
) -> None:
    evidence = tmp_path / "failure-snapshot.json"
    evidence.write_text('{"observation":"retained"}')
    (tmp_path / "fixture/private-key").write_text("synthetic fixture input")
    retired = tmp_path / "failed-archive-retirement"
    retired.mkdir()
    (retired / "source.ext4").write_bytes(b"synthetic fixture image")
    (retired / "capture.json").write_text('{"digest":"preserved"}')
    cleanup.cleanup(tmp_path)
    assert docker[0] == {}
    assert docker[1] == ["destination", "acme", "host", "archive"]
    assert evidence.read_text() == '{"observation":"retained"}'
    assert not (tmp_path / "fixture").exists()
    assert not (retired / "source.ext4").exists()
    assert (retired / "capture.json").is_file()
    assert json.loads((tmp_path / "disposable-cleanup.json").read_text())["state"] == "complete"
    with pytest.raises(ValueError, match="cleanup permanently excludes"):
        disposition.require_available(tmp_path)


def test_changed_recorded_identity_refuses_all_removal(
    tmp_path: Path, fixture_context: dict[str, str], docker: tuple[dict[str, str], list[str]]
) -> None:
    (tmp_path / "case-containers.json").write_text(json.dumps({HOST_ENV: "f" * 64}))
    with pytest.raises(ValueError, match="identity changed"):
        cleanup.cleanup(tmp_path)
    assert not docker[1]


@pytest.mark.parametrize("bound", [False, True])
def test_auxiliary_retirement_fixture_is_bound_and_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_context: dict[str, str],
    docker: tuple[dict[str, str], list[str]],
    bound: bool,
) -> None:
    other = resource_names(uuid.uuid7().hex)
    image = "sha256:" + "e" * 64
    identity = "f" * 64
    (tmp_path / "native-unused-fixture.json").write_text(
        json.dumps(
            {
                "format": "lowerduckpond-native-unused-fixture-v1",
                "parent_run_id": fixture_context[RUN_ENV],
                "run_id": other[RUN_ENV],
                "name": other["LDP_QUALIFICATION_ARCHIVE"],
                "image": image,
                "id": identity if bound else None,
            }
        )
    )
    original_command = cleanup.bounded_command
    original_remove = cleanup.remove_exact
    present = True

    def command(args: list[str], **kwargs: object) -> bytes | None:
        if args[1] == "ps" and f"label={cleanup.LABEL}={other[RUN_ENV]}" in args:
            return identity.encode() if present else b""
        if args[1] == "inspect" and args[-1] == identity:
            return json.dumps(
                {
                    "id": identity,
                    "name": "/" + other["LDP_QUALIFICATION_ARCHIVE"],
                    "owner": other[RUN_ENV],
                    "image": image,
                }
            ).encode()
        return original_command(args, **kwargs)

    def remove(environment: dict[str, str], selected: str) -> None:
        nonlocal present
        if selected == identity:
            present = False
            docker[1].append("unused-archive")
        else:
            original_remove(environment, selected)

    monkeypatch.setattr(cleanup, "bounded_command", command)
    monkeypatch.setattr(cleanup, "remove_exact", remove)
    cleanup.cleanup(tmp_path)
    assert not present
    assert docker[1] == ["destination", "acme", "host", "archive", "unused-archive"]


def test_auxiliary_reservation_is_create_once_and_bound_to_parent(
    tmp_path: Path, fixture_context: dict[str, str]
) -> None:
    other = resource_names(uuid.uuid7().hex)
    image = "sha256:" + "e" * 64
    cleanup.reserve_auxiliary(tmp_path, fixture_context, other, image)
    path = tmp_path / "native-unused-fixture.json"
    original = path.read_bytes()
    record = json.loads(original)
    assert record["parent_run_id"] == fixture_context[RUN_ENV]
    assert record["run_id"] == other[RUN_ENV]
    assert record["id"] is None
    cleanup.complete_auxiliary(tmp_path, "f" * 64)
    assert json.loads(path.read_text())["id"] == "f" * 64
    original = path.read_bytes()
    with pytest.raises(ValueError, match="already allocated"):
        cleanup.reserve_auxiliary(tmp_path, fixture_context, other, image)
    assert path.read_bytes() == original


def test_local_data_cleanup_does_not_follow_disk_image_symlinks(tmp_path: Path) -> None:
    external = tmp_path / "unrelated"
    external.write_bytes(b"keep")
    retired = tmp_path / "failed-archive-retirement"
    retired.mkdir()
    (retired / "source.ext4").symlink_to(external)
    with pytest.raises(ValueError, match="disk image is unsafe"):
        cleanup.remove_local_data(tmp_path)
    assert external.read_bytes() == b"keep"


def test_changed_daemon_or_live_manifest_refuses_all_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_context: dict[str, str],
    docker: tuple[dict[str, str], list[str]],
) -> None:
    monkeypatch.setattr(cleanup, "daemon_id", lambda _: "another-daemon")
    with pytest.raises(ValueError, match="binding changed"):
        cleanup.cleanup(tmp_path)
    (tmp_path / "fixture.json").write_text('{"format":"live-spaces"}')
    with pytest.raises(ValueError, match="does not accept live"):
        cleanup.cleanup(tmp_path)
    assert not docker[1]


def test_interrupted_cleanup_resumes_only_original_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_context: dict[str, str],
    docker: tuple[dict[str, str], list[str]],
) -> None:
    original = cleanup.remove_exact
    calls = 0

    def interrupted(environment: dict[str, str], identity: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:  # noqa: PLR2004 - interrupt the second removal
            original(environment, identity)
            raise RuntimeError("lost response")
        original(environment, identity)

    monkeypatch.setattr(cleanup, "remove_exact", interrupted)
    with pytest.raises(RuntimeError, match="lost response"):
        cleanup.cleanup(tmp_path)
    assert docker[1] == ["destination", "acme"]
    monkeypatch.setattr(cleanup, "remove_exact", original)
    cleanup.cleanup(tmp_path)
    assert docker[1] == ["destination", "acme", "host", "archive"]


def test_failed_run_captures_diagnostics_before_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixture_context: dict[str, str]
) -> None:
    order: list[str] = []
    monkeypatch.setattr(failure, "capture_fixture", lambda: order.append("identity"))

    def snapshot() -> None:
        order.append("snapshot")
        (tmp_path / "failure-snapshot.json").write_text("{}")

    def report(directory: Path, status: int) -> Path:
        assert status == 17  # noqa: PLR2004 - original failure status
        order.append("report")
        return directory / "failure.json"

    def remove(directory: Path) -> None:
        assert json.loads((directory / "disposable-result.json").read_text())["outcome"] == "failed"
        order.append("cleanup")

    monkeypatch.setattr(failure, "capture_failure_observation", snapshot)
    monkeypatch.setattr(failure, "collect", report)
    monkeypatch.setattr(cleanup, "cleanup", remove)
    assert local.capture_and_cleanup(tmp_path, fixture_context, 17, retain_until=None)
    assert order == ["identity", "snapshot", "report", "cleanup"]


def test_missing_snapshot_never_reaches_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixture_context: dict[str, str]
) -> None:
    monkeypatch.setattr(failure, "capture_fixture", lambda: None)
    monkeypatch.setattr(failure, "capture_failure_observation", lambda: None)
    monkeypatch.setattr(
        cleanup, "cleanup", lambda _: pytest.fail("cleanup must wait for diagnostics")
    )
    assert not local.capture_and_cleanup(tmp_path, fixture_context, 17, retain_until=None)
    assert (tmp_path / "disposable-cleanup-error.json").is_file()


def test_retention_requires_an_explicit_future_timezone_and_expires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="timezone"):
        cleanup.expiry("2030-01-01T10:00:00")
    with pytest.raises(ValueError, match="explicit retention expiry"):
        local.run(tmp_path, create_only=True)
    deadline = datetime.now(UTC) + timedelta(hours=1)
    started: list[list[str]] = []
    environments: list[dict[str, str]] = []
    monkeypatch.setenv("SPACES_SECRET_ACCESS_KEY", "seeded-provider-secret")

    def spawn(command: list[str], **kwargs: object) -> None:
        started.append(command)
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        environments.append(environment)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    cleanup.retain_until(tmp_path, deadline)
    assert started and "--wait-for-expiry" in started[0]
    assert "seeded-provider-secret" not in json.dumps(environments)
    assert "SPACES_SECRET_ACCESS_KEY" not in environments[0]
    marker = tmp_path / "disposable-retention.json"
    value = json.loads(marker.read_text())
    value["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    marker.write_text(json.dumps(value))
    removed: list[Path] = []
    monkeypatch.setattr(cleanup, "cleanup", removed.append)
    cleanup.wait_for_expiry(tmp_path)
    assert removed == [tmp_path]


def test_interrupted_recovery_captures_before_disposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_context: dict[str, str],
    docker: tuple[dict[str, str], list[str]],
) -> None:
    monkeypatch.setattr(failure, "capture_fixture", lambda: None)
    monkeypatch.setattr(
        failure,
        "capture_failure_observation",
        lambda: (tmp_path / "failure-snapshot.json").write_text("{}"),
    )
    observed: list[int] = []
    monkeypatch.setattr(failure, "collect", lambda _, status: observed.append(status))
    cleanup.recover_interrupted(tmp_path)
    assert observed == [130]
    assert docker[0] == {}
    assert (tmp_path / "failure-snapshot.json").is_file()
    with pytest.raises(ValueError, match="cleanup permanently excludes"):
        disposition.require_available(tmp_path)


def test_active_run_lease_blocks_interrupted_recovery(
    tmp_path: Path,
    fixture_context: dict[str, str],
    docker: tuple[dict[str, str], list[str]],
) -> None:
    with run_lease(tmp_path), pytest.raises(BlockingIOError):
        cleanup.recover_interrupted(tmp_path)
    assert not docker[1]


def test_cleanup_error_details_do_not_copy_arbitrary_sensitive_output() -> None:
    assert cleanup.error_detail(ValueError("fixture identity or ownership changed"))["reason"] == (
        "fixture identity or ownership changed"
    )
    details = json.dumps(cleanup.error_detail(ValueError("seeded-secret-from-process-output")))
    assert "seeded-secret" not in details
    assert "unclassified" in details
