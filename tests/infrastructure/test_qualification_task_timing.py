from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, cast

import pytest
from molecule_plugins import docker

from scripts import qualification_task_timing as tasks
from scripts import qualification_timing as timing

CANARY = "private-task-name-argument-host-path-result"
FAILURE_STATUS = 7
SOURCE = timing.ROOT / "config/ansible/roles/caddy/tasks/main.yml"


@pytest.fixture
def directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(timing, "_tool_output", lambda _: "unknown")
    timing.start_run(tmp_path, "minio")
    monkeypatch.setenv(timing.EVENT_ENV, str(tmp_path / "timing-events.jsonl"))
    monkeypatch.setenv(timing.CONTEXT_ENV, "core")
    return tmp_path


def summary(directory: Path) -> dict[str, Any]:
    return cast(dict[str, Any], timing.finish_run(directory, 1)["ansible_tasks"])


def test_overlapping_playbooks_preserve_completed_and_unfinished_tasks(directory: Path) -> None:
    outer = tasks.start_task("verify", "ansible.builtin.command", f"{SOURCE}:194")
    inner = tasks.start_task("converge", "ansible.builtin.apt", f"{SOURCE}:117")
    tasks.finish_task(inner, "failed")
    report = summary(directory)
    assert report["completed_count"] == 1
    assert report["unfinished_count"] == 1
    assert report["longest_completed"][0]["outcome"] == "failed"
    assert report["unfinished"][0]["action"] == "command"
    assert outer is not None
    assert CANARY not in json.dumps(report)


def test_external_molecule_build_has_stable_source_without_absolute_paths(directory: Path) -> None:
    source = Path(docker.__file__).parent / "playbooks/create.yml"
    task = tasks.start_task("create", "community.docker.docker_image", f"{source}:104")
    assert task is not None
    assert task["source"] == "molecule-plugins/docker/create.yml"
    tasks.finish_task(task, "completed")
    assert summary(directory)["completed_count"] == 1


@pytest.mark.parametrize(
    ("output", "seconds"),
    [
        ("Fetched 94.8 MB in 20min 5s (78.7 kB/s)", 1205),
        ("Fetched 94.8 MB in 1s (94.8 MB/s)", 1),
        ("Fetched 1 MB in " + "1" * 5000 + "s (1 B/s)", None),
        (CANARY, None),
    ],
)
def test_apt_download_attribution_contains_only_numeric_duration(
    directory: Path, output: str, seconds: int | None
) -> None:
    task = tasks.start_task("converge", "ansible.builtin.apt", f"{SOURCE}:1")
    tasks.observe_result(task, {"stdout": f"{CANARY}\n{output}\n{CANARY}"})
    tasks.finish_task(task, "completed")
    report = summary(directory)
    assert report["longest_completed"][0]["apt_download_seconds"] == seconds
    assert CANARY not in json.dumps(report)
    assert CANARY not in (directory / tasks.JOURNAL).read_text()


def test_no_log_results_are_not_inspected(directory: Path) -> None:
    task = tasks.start_task("converge", "ansible.builtin.apt", f"{SOURCE}:1")
    tasks.observe_result(task, {"stdout": "Fetched 1 MB in 5s (1 B/s)", "_ansible_no_log": True})
    tasks.finish_task(task, "completed")
    assert summary(directory)["longest_completed"][0]["apt_download_seconds"] is None


def test_unknown_values_and_private_playbook_paths_are_not_serialized(directory: Path) -> None:
    task = tasks.start_task(CANARY, CANARY, f"/private/{CANARY}.yml:123")
    tasks.finish_task(task, "completed")
    assert CANARY not in (directory / tasks.JOURNAL).read_text()
    assert CANARY not in json.dumps(summary(directory))


def test_untracked_playbook_inside_checkout_cannot_expose_its_name(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(timing, "ROOT", directory)
    monkeypatch.setattr(tasks, "_checkout_sources", lambda _: frozenset())
    private = directory / f"config/ansible/{CANARY}.yml"
    private.parent.mkdir(parents=True)
    private.touch()
    task = tasks.start_task("converge", "ansible.builtin.command", f"{private}:1")
    assert task is not None and task["source"] == "unknown"
    tasks.finish_task(task, "completed")
    assert CANARY not in (directory / tasks.JOURNAL).read_text()
    assert CANARY not in json.dumps(summary(directory))


def test_partial_final_append_retains_started_task_without_inventing_completion(
    directory: Path,
) -> None:
    tasks.start_task("create", "community.docker.docker_image", f"{SOURCE}:1")
    with (directory / tasks.JOURNAL).open("ab") as stream:
        stream.write(b'{"secret":"' + CANARY.encode())
    original = (directory / tasks.JOURNAL).read_bytes()
    report = summary(directory)
    assert report["partial_final_append"] is True
    assert report["unfinished_count"] == 1
    assert report["completed_count"] == 0
    assert (directory / tasks.JOURNAL).read_bytes() == original
    assert CANARY not in json.dumps(report)


def test_completion_racing_collection_does_not_erase_inflight_evidence(directory: Path) -> None:
    task = tasks.start_task("converge", "ansible.builtin.apt", f"{SOURCE}:1")
    observed = time.monotonic_ns()
    tasks.finish_task(task, "completed")
    tasks.start_task("converge", "ansible.builtin.file", f"{SOURCE}:2")
    started = json.loads((directory / "timing-start.json").read_text())["started_ns"]
    report = tasks.summarize(directory, started, observed)
    assert report["status"] == "observed"
    assert report["unfinished_count"] == 1
    assert report["completed_count"] == 0


@pytest.mark.parametrize("shape", ["symlink", "fifo", "oversize", "malformed"])
def test_bad_journal_preserves_phase_report_and_command_status(
    directory: Path, shape: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = directory / tasks.JOURNAL
    if shape == "symlink":
        target = directory / "private"
        target.write_text(CANARY)
        path.symlink_to(target)
    elif shape == "fifo":
        os.mkfifo(path)
    elif shape == "oversize":
        path.write_bytes(b"x" * 1025)
        monkeypatch.setattr(tasks, "MAX_BYTES", 1024)
    else:
        path.write_text(json.dumps({"secret": CANARY}) + "\n")
    with timing.measure("prepare"):
        task = tasks.start_task("prepare", "ansible.builtin.command", f"{SOURCE}:1")
        tasks.finish_task(task, "completed")
    report = timing.finish_run(directory, FAILURE_STATUS)
    assert report["exit_status"] == FAILURE_STATUS
    assert report["event_count"] == 1
    assert report["ansible_tasks"] == {"status": "invalid-or-incomplete"}
    assert CANARY not in (directory / "timing.json").read_text()
    if shape == "symlink":
        assert (directory / "private").read_text() == CANARY
    if shape == "oversize":
        assert path.stat().st_size == tasks.MAX_BYTES + 1


@pytest.mark.parametrize("field", ["source", "group", "action", "phase", "outcome"])
def test_report_revalidates_journal_fields(directory: Path, field: str) -> None:
    task = tasks.start_task("converge", "ansible.builtin.command", f"{SOURCE}:1")
    assert task is not None
    (directory / tasks.JOURNAL).write_text(json.dumps({**task, field: CANARY}) + "\n")
    assert summary(directory) == {"status": "invalid-or-incomplete"}


def test_real_ansible_sigkill_keeps_inflight_no_log_task(directory: Path) -> None:
    playbook = directory / f"{CANARY}.yml"
    playbook.write_text(
        f"- hosts: localhost\n  gather_facts: false\n  tasks:\n"
        f"    - name: {CANARY}\n      ansible.builtin.command: /bin/sleep 60\n"
        "      no_log: true\n"
    )
    with subprocess.Popen(  # noqa: S603 - disposable local playbook, own process group only
        [
            str(timing.ROOT / ".venv/bin/ansible-playbook"),
            "-i",
            "localhost,",
            "-c",
            "local",
            str(playbook),
        ],
        env=timing.child_environment(directory),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    ) as process:
        try:
            deadline = time.monotonic() + 15
            path = directory / tasks.JOURNAL
            while not path.exists() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.05)
            assert path.exists(), "callback did not journal the task before running it"
        finally:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    timing.interrupted_run(directory)
    report = json.loads((directory / "timing-interrupted.json").read_text())
    assert report["exit_status"] is None
    assert report["event_count"] == 0
    assert report["ansible_tasks"]["unfinished_count"] == 1
    assert report["ansible_tasks"]["unfinished"][0]["action"] == "command"
    assert report["ansible_tasks"]["completed_count"] == 0
    assert CANARY not in json.dumps(report)
    assert not (directory / "case.json").exists()
