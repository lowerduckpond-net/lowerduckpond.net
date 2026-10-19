"""Actual bootstrap/entry frames and nonrenewing transport, with no backend calls."""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import os
import select
import signal
import subprocess
import sys
import threading
import time
import zlib
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import m3_11_frozen_context as context
from scripts import m3_11_frozen_driver as driver
from scripts import m3_11_frozen_entry as entry
from scripts import m3_11_frozen_transport as transport
from scripts import production_qualification_inputs as source
from scripts.m3_11_frozen_frames import send
from scripts.m3_11_frozen_retirement import FrozenRetirement, reserve
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended import storage_admission as admission
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import LifecycleError, stamp
from scripts.m3_11_unattended.state import RunState

from .test_m3_11_frozen_owner import owner as owner  # noqa: PLC0414 - pytest fixture
from .test_m3_11_frozen_retirement import Fixture, journal_snapshot
from .test_m3_11_frozen_retirement import case as case  # noqa: PLC0414 - pytest fixture

Case = tuple[FrozenRetirement, Fixture, dict[str, object]]


@pytest.fixture
def synthetic_closeout_support(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise transaction primitives with fake providers, never native readiness."""
    for module in (driver, entry, context):
        monkeypatch.setattr(module, "require_supported_closeout", lambda: None)


@pytest.fixture
def locked_owner(
    owner: context.NativeFixture, monkeypatch: pytest.MonkeyPatch
) -> tuple[context.NativeFixture, dict[str, object], list[Path]]:
    owner.root.chmod(0o700)
    run = owner.producer / "qualification" / "spaces-test"
    run.mkdir(mode=0o700, parents=True)
    (run / "run.lock").touch(mode=0o600)
    with RunState(owner.consumer).lock():
        pass
    owner.fixture.update(original_files={}, actors=[], source_incarnation={})
    plan = {
        **owner.plan,
        "original_run": str(run),
        "producing_attempt": owner.producer.name,
        "fixture_sha256": digest(owner.fixture),
    }
    lease_directory = Path(str(vars(admission)["LEASE_DIRECTORY"]))
    monkeypatch.setattr(context, "LEASE_DIRECTORY", str(lease_directory))
    monkeypatch.setattr(context, "environment_for", lambda path: {"DOCKER_HOST": "unix:///test"})
    monkeypatch.setattr(
        LiveStorage,
        "_retained",
        classmethod(lambda cls, env: SimpleNamespace(target=owner.manifest.targets)),
    )
    monkeypatch.setattr(owner, "client", lambda role: SimpleNamespace(role=role))
    monkeypatch.setattr(owner, "guard", lambda plan: owner.owner())
    owner.held = False
    paths = [
        owner.consumer / "controller.lock",
        owner.lease.directory / "runtime-use.lock",
        lease_directory
        / (
            digest(
                {
                    "region": owner.manifest.targets.region,
                    "archive_bucket": owner.manifest.targets.archive_bucket,
                }
            )
            + ".lock"
        ),
        run / "run.lock",
        run / "fixture-operation.lock",
    ]
    return owner, plan, paths


def test_real_lock_enclosure_preserves_cleanup_outside_submission(
    locked_owner: tuple[context.NativeFixture, dict[str, object], list[Path]],
) -> None:
    owner, plan, paths = locked_owner
    cleanup = owner.root / ".credential-cleanup.lock"
    with owner.locked(plan):
        for path in paths:
            with pytest.raises(BlockingIOError), admission.existing_lock(path):
                pass
        with admission.existing_lock(cleanup):
            pass
        with owner.submission(), pytest.raises(BlockingIOError), admission.existing_lock(cleanup):
            pass
        with admission.existing_lock(cleanup):
            pass
    for path in [*paths, cleanup]:
        with admission.existing_lock(path):
            pass
    assert owner.held is False


def test_unreleased_prior_consumer_blocks_native_locked_entry(
    locked_owner: tuple[context.NativeFixture, dict[str, object], list[Path]],
) -> None:
    owner, plan, paths = locked_owner
    (owner.lease.directory / ("released-" + owner.producer.name + ".json")).unlink()
    with pytest.raises(ValueError, match="another retained consumer"), owner.locked(plan):
        pytest.fail("unreleased producer accepted")
    assert owner.held is False
    for path in paths:
        with admission.existing_lock(path):
            pass


@pytest.mark.parametrize("missing", ["fixture-operation.lock", "run.lock", "external-path"])
def test_native_read_only_owner_does_not_recreate_missing_lock_files(
    locked_owner: tuple[context.NativeFixture, dict[str, object], list[Path]], missing: str
) -> None:
    owner, plan, _paths = locked_owner
    with owner.locked(plan):
        pass
    run = Path(str(plan["original_run"]))
    path = (
        owner.root / "fixture-dispositions" / ("path-" + digest(str(run)) + ".lock")
        if missing == "external-path"
        else run / missing
    )
    path.unlink()
    owner.observation_only = True
    before = {item: item.read_bytes() for item in owner.root.rglob("*") if item.is_file()}
    with pytest.raises(FileNotFoundError), owner.locked(plan):
        pytest.fail("read-only owner repaired a missing required lock")
    assert not path.exists()
    assert before == {item: item.read_bytes() for item in owner.root.rglob("*") if item.is_file()}


def program_for(payload: dict[str, object]) -> tuple[str, str]:
    raw = json.dumps({"modules": {}, "payload": payload}, sort_keys=True).encode()
    bundle = base64.b85encode(zlib.compress(raw)).decode()
    return program_for_bundle(bundle), bundle


def program_for_bundle(bundle: str) -> str:
    return (
        "EXPECTED_DATA_SHA256 = "
        + repr(hashlib.sha256(bundle.encode()).hexdigest())
        + "\n"
        + transport.BOOTSTRAP
    )


def driver_program(case: Case, operation: str = "execute") -> tuple[str, str]:
    return program_for(
        {"plan": case[0].plan, "fixture": {}, "runtime_revision": "b" * 40, "operation": operation}
    )


@pytest.mark.parametrize("operation", ["execute", "reconcile"])
@pytest.mark.usefixtures("synthetic_closeout_support")
def test_real_bootstrap_entry_driver_protocol_and_no_replay(  # noqa: PLR0915 - one real protocol exchange
    case: Case, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    """Run the bootstrap on the main thread so its actual SIGALRM guard is exercised."""
    transaction, fixture, approval = case
    if operation == "reconcile":
        fixture.store.failure = "after"
        with pytest.raises(ConnectionError):
            transaction.execute(approval)
    earlier_submissions = len(fixture.store.deletes)
    before = journal_snapshot(transaction.root) if operation == "reconcile" else None
    verified: list[str] = []
    processes: list[Any] = []
    failures: list[BaseException] = []
    outcomes: list[dict[str, object]] = []
    created = threading.Event()
    completed = threading.Event()
    monkeypatch.setattr(entry, "bounded_helper", nullcontext)
    monkeypatch.setattr(entry, "require_remaining", lambda seconds: None)
    monkeypatch.setattr(source, "current_candidate", lambda *args: {})
    monkeypatch.setattr(LeaseConfiguration, "load", classmethod(lambda cls, path: object()))
    monkeypatch.setattr(entry, "ReadOnlyDocker", object)

    def make_fixture(**kwargs: Any) -> Fixture:  # noqa: ANN401 - synthetic native boundary
        old_guard = fixture.guard

        def guard(plan: dict[str, object]) -> None:
            old_guard(plan)
            kwargs["revalidate_copies_and_cleanup"]()
            fixture.reads = 1  # type: ignore[attr-defined]
            fixture.deletes = len(fixture.store.deletes) - earlier_submissions  # type: ignore[attr-defined]

        monkeypatch.setattr(fixture, "guard", guard)
        return fixture

    monkeypatch.setattr(entry, "NativeFixture", make_fixture)
    proof_expiry = datetime.now(UTC) + timedelta(minutes=60)

    def verify() -> dict[str, object]:
        verified.append("verify")
        return {
            "evidence_sha256": transaction.plan["evidence_sha256"],
            "status": "native-files-and-cleanup-verified",
            "proof_valid_until": stamp(proof_expiry),
            "observed_at": stamp(datetime.now(UTC)),
        }

    program, bundle = program_for(
        {
            "plan": transaction.plan,
            "fixture": {},
            "runtime_revision": "b" * 40,
            "operation": operation,
        }
    )

    class Process:
        def __init__(self, args: list[str], **kwargs: object) -> None:
            assert args[:6] == ["docker", "exec", "-i", "-w", "/work/source", "a" * 64]
            assert args[-1] == program
            reads, writes = os.pipe()
            outreads, outwrites = os.pipe()
            self.stdin = os.fdopen(writes, "wb", buffering=0)
            self.stdout = os.fdopen(outreads, "rb", buffering=0)
            self.remote_in = os.fdopen(reads, "rb", buffering=0)
            self.remote_out = os.fdopen(outwrites, "wb", buffering=0)
            self.returncode: int | None = None
            processes.append(self)
            created.set()

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int | None:
            if not completed.wait(timeout):
                raise TimeoutError("synthetic child not complete")
            return self.returncode

        def kill(self) -> None:
            if not self.stdin.closed:
                self.stdin.close()

    monkeypatch.setattr(subprocess, "Popen", Process)
    output = tmp_path / "driver"

    def invoke() -> dict[str, object]:
        return driver.execute(
            program=program,
            bundle=bundle,
            authorization=approval,
            controller="a" * 64,
            environment={"DOCKER_HOST": "unix:///synthetic"},
            output=output,
            verify=verify,
            observation_only=operation == "reconcile",
        )

    def drive() -> None:
        try:
            outcomes.append(invoke())
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=drive, daemon=True)
    worker.start()
    assert created.wait(30), "driver did not reach the mocked transport"
    process = processes[0]
    monkeypatch.setattr(
        sys, "stdin", SimpleNamespace(buffer=process.remote_in, fileno=process.remote_in.fileno)
    )
    monkeypatch.setattr(
        entry, "emit", lambda value: process.remote_out.write((json.dumps(value) + "\n").encode())
    )
    before_path, before_meta = list(sys.path), list(sys.meta_path)
    previous_alarm = signal.getsignal(signal.SIGALRM)
    try:
        with pytest.raises(SystemExit) as caught:
            exec(compile(program, "<synthetic-reviewed-bootstrap>", "exec"), {})  # noqa: S102
        process.returncode = caught.value.code
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_alarm)
        sys.path[:], sys.meta_path[:] = before_path, before_meta
        process.remote_in.close()
        process.remote_out.close()
        completed.set()
        worker.join(30)
    assert not worker.is_alive() and not failures
    assert outcomes[0]["status"] == ("observed" if operation == "reconcile" else "verified")
    assert len(processes) == 1
    assert len(fixture.store.deletes) == earlier_submissions + (operation == "execute")
    if operation == "reconcile":
        assert outcomes[0]["provider_delete_submissions"] == 0
        assert journal_snapshot(transaction.root) == before
        observation = cast(dict[str, object], outcomes[0]["retirement"])
        assert observation["version_state"] == "absent"
        assert observation["recorded_retirement"] is False
        with pytest.raises(ValueError):
            driver.terminal(outcomes[0], approval)
    assert len(verified) > 2  # noqa: PLR2004 - initial plus repeated native proofs
    with pytest.raises(FileExistsError):
        invoke()
    assert len(processes) == 1


def test_proof_exchange_leaves_room_for_full_local_child_and_response() -> None:
    assert entry.ACK_SECONDS >= 600 + 120


@pytest.mark.parametrize("remaining", [2459, 2460])
@pytest.mark.usefixtures("synthetic_closeout_support")
def test_native_permanent_marker_admission_requires_post_effect_and_report_reserve(
    owner: context.NativeFixture, monkeypatch: pytest.MonkeyPatch, remaining: int
) -> None:
    # This regression isolates the enclosing allowance. Envelope eligibility has
    # separate native inventory, credential-clock and capacity boundary tests.
    monkeypatch.setattr("scripts.m3_11_frozen_envelope.verify", lambda _fixture: {})
    monkeypatch.setattr(admission, "_deadline", float(remaining))
    monkeypatch.setattr(admission, "time", SimpleNamespace(monotonic=lambda: 0.0))
    if remaining < context.POST_EFFECT_RESERVE + admission.REPORT_SECONDS:
        with pytest.raises(LifecycleError, match="lacks time"):
            owner.before_disposition()
    else:
        owner.before_disposition()


def test_observation_cannot_hide_a_provider_mutation_or_claim_completion(case: Case) -> None:
    transaction, fixture, approval = case
    fixture.store.failure = "after"
    with pytest.raises(ConnectionError):
        transaction.execute(approval)
    observed = transaction.execute(approval, reconcile_only=True)
    outer = {
        "status": "observed",
        "retirement": observed,
        "elapsed_seconds": 1.0,
        "provider_delete_submissions": 0,
        "provider_inventory_owner_reads": 2,
    }
    driver.terminal(outer, approval, observation_only=True)
    for changed in (
        {**outer, "provider_delete_submissions": 1},
        {**outer, "status": "verified"},
        {**outer, "retirement": {**observed, "recorded_retirement": 1}},
        {**outer, "retirement": {**observed, "lease_released": True}},
    ):
        with pytest.raises(ValueError):
            driver.terminal(changed, approval, observation_only=True)


@pytest.mark.parametrize("where", ["before-reservation", "after-reservation"])
@pytest.mark.usefixtures("synthetic_closeout_support")
def test_driver_never_submits_after_enclosing_allowance_consumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str, case: Case
) -> None:
    tmp_path.chmod(0o700)
    clock, sent = [0.0], []
    monkeypatch.setattr(driver, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    original = reserve

    def delayed_reserve(path: Path, value: dict[str, object]) -> None:
        original(path, value)
        if where == "after-reservation":
            clock[0] = driver.CALLER_SECONDS - admission.HELPER_SECONDS

    def verify() -> dict[str, object]:
        if where == "before-reservation":
            clock[0] = driver.CALLER_SECONDS - admission.HELPER_SECONDS
        return {}

    monkeypatch.setattr(driver, "reserve", delayed_reserve)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: sent.append(a))
    output = tmp_path / "driver"
    with pytest.raises(TimeoutError):
        driver.execute(
            program=driver_program(case)[0],
            bundle=driver_program(case)[1],
            authorization=case[2],
            controller="a" * 64,
            environment={"DOCKER_HOST": "unix:///synthetic"},
            output=output,
            verify=verify,
        )
    assert not sent
    assert (output / "exec-submitted.json").exists() == (where == "after-reservation")


@pytest.mark.parametrize("prelude_seconds", [2500.0, 6001.0])
@pytest.mark.usefixtures("synthetic_closeout_support")
def test_original_caller_origin_includes_preimport_and_review_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prelude_seconds: float, case: Case
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setattr(driver, "time", SimpleNamespace(monotonic=lambda: prelude_seconds))
    sent: list[object] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: sent.append(a))
    output = tmp_path / "original-clock"
    with pytest.raises(TimeoutError):
        driver.execute(
            program=driver_program(case)[0],
            bundle=driver_program(case)[1],
            authorization=case[2],
            controller="a" * 64,
            environment={"DOCKER_HOST": "unix:///synthetic"},
            output=output,
            verify=dict,
            caller_started=0.0,
        )
    assert not sent and not (output / "exec-submitted.json").exists()


@pytest.mark.usefixtures("synthetic_closeout_support")
def test_driver_cannot_promote_malformed_verified_frame(
    case: Case, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _transaction, _fixture, approval = case

    class Pipe:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.stdin, self.stdout = io.BytesIO(), io.BytesIO()

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(subprocess, "Popen", Pipe)
    monkeypatch.setattr(driver, "frame", lambda *args, **kwargs: {"status": "verified"})
    monkeypatch.setattr(driver, "send", lambda *args, **kwargs: None)
    output = tmp_path / "malformed"
    with pytest.raises((ValueError, RuntimeError)):
        driver.execute(
            program=driver_program(case)[0],
            bundle=driver_program(case)[1],
            authorization=approval,
            controller="a" * 64,
            environment={"DOCKER_HOST": "unix:///synthetic"},
            output=output,
            verify=dict,
        )
    assert not (output / "verified.json").exists()
    assert (output / "unresolved.json").is_file()


def test_stalled_authorization_write_has_one_deadline_and_restores_fd() -> None:
    read, write = os.pipe()
    try:
        with os.fdopen(write, "wb", buffering=0) as outgoing:
            with pytest.raises(TimeoutError):
                send(outgoing, {"bounded": "a" * 100_000}, deadline=time.monotonic() + 0.05)
            assert os.get_blocking(outgoing.fileno())
    finally:
        os.close(read)


def test_bootstrap_arms_startup_deadline_before_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered: list[object] = []
    monkeypatch.setattr(entry, "run", entered.append)

    def stalled(*args: object) -> tuple[list[object], list[object], list[object]]:
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert 0 < remaining <= transport.STARTUP_SECONDS and interval == 0
        assert 0 < cast(float, args[-1]) <= transport.STARTUP_SECONDS
        return [], [], []

    monkeypatch.setattr(select, "select", stalled)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=object()))
    previous_alarm = signal.getsignal(signal.SIGALRM)
    before_path, before_meta = list(sys.path), list(sys.meta_path)
    try:
        with pytest.raises(TimeoutError):
            exec(compile(program_for({})[0], "<synthetic-startup>", "exec"), {})  # noqa: S102
        assert not entered
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_alarm)
        sys.path[:], sys.meta_path[:] = before_path, before_meta


def bootstrap_frame(monkeypatch: pytest.MonkeyPatch, program: str, raw: bytes) -> dict[str, object]:
    """Use actual pipes and the actual frame reader, without an external process."""
    read, write = os.pipe()
    stream = os.fdopen(read, "rb", buffering=0)

    def feed() -> None:
        try:
            with os.fdopen(write, "wb", buffering=0) as outgoing:
                view = memoryview(raw)
                while view:
                    count = outgoing.write(view)
                    assert count is not None and count > 0
                    view = view[count:]
        except BrokenPipeError:
            pass  # Rejected bounded input closes the other end intentionally.

    writer = threading.Thread(target=feed, daemon=True)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=stream, fileno=stream.fileno))
    previous_alarm = signal.getsignal(signal.SIGALRM)
    before_path, before_meta = list(sys.path), list(sys.meta_path)
    namespace: dict[str, object] = {}
    writer.start()
    try:
        exec(compile(program, "<synthetic-reviewed-bootstrap>", "exec"), namespace)  # noqa: S102
        return namespace
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_alarm)
        sys.path[:], sys.meta_path[:] = before_path, before_meta
        stream.close()
        writer.join(30)
        assert not writer.is_alive()


def script_closure(repository: Path) -> list[str]:
    """Exercise the complete actual script dependency closure, not a tiny stub."""
    waiting = {
        "scripts.m3_11_frozen_entry",
        "scripts.m3_11_frozen_local",
        "scripts.m3_11_frozen_driver",
        "scripts.m3_11_frozen_transport",
    }
    found: set[str] = set()
    while waiting:
        name = waiting.pop()
        path = repository / (name.replace(".", "/") + ".py")
        if name in found or not path.is_file():
            continue
        found.add(name)
        for node in ast.walk(ast.parse(path.read_bytes())):
            if isinstance(node, ast.Import):
                waiting.update(item.name for item in node.names if item.name.startswith("scripts."))
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("scripts."):
                    waiting.add(node.module)
                    waiting.update(node.module + "." + item.name for item in node.names)
                elif node.module == "scripts":
                    waiting.update("scripts." + item.name for item in node.names)
    return sorted(name.replace(".", "/") + ".py" for name in found)


def test_full_actual_source_closure_uses_small_argv_and_bound_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = Path(transport.__file__).resolve().parents[1]
    names = script_closure(repository)

    def git(path: Path, *arguments: str) -> bytes:
        assert path == repository
        if arguments == ("status", "--porcelain", "--untracked-files=all"):
            return b""
        if arguments == ("rev-parse", "HEAD"):
            return b"b" * 40
        assert arguments[:2] == ("diff", "--name-only")
        if arguments[-1] == "scripts":
            return "\n".join(names).encode()
        assert arguments[-4:] == ("packages", "tools", "services", "uv.lock")
        return b""

    monkeypatch.setattr(transport, "git", git)
    payload: dict[str, object] = {
        "plan": {"implementation_revision": "b" * 40},
        "fixture": {},
        "runtime_revision": "a" * 40,
        "operation": "reconcile",
    }
    built = transport.build(repository, payload)
    program, bundle = str(built["program"]), str(built["bundle"])
    assert len(bundle.encode()) > transport.MAX_PROGRAM
    assert len(program.encode()) < transport.MAX_PROGRAM
    assert hashlib.sha256(bundle.encode()).hexdigest() == built["bundle_sha256"]
    decoded = json.loads(zlib.decompress(base64.b85decode(bundle)))
    assert decoded["payload"] == payload
    assert set(cast(dict[str, str], built["modules"])) == set(names)
    for name in names:
        raw = (repository / name).read_bytes()
        assert decoded["modules"][name.removesuffix(".py").replace("/", ".")] == raw.decode()
        assert cast(dict[str, str], built["modules"])[name] == hashlib.sha256(raw).hexdigest()
    entered: list[dict[str, object]] = []

    def run(value: dict[str, object]) -> int:
        entered.append(value)
        return 0

    monkeypatch.setattr(entry, "run", run)
    with pytest.raises(SystemExit) as caught:
        bootstrap_frame(
            monkeypatch,
            program,
            (json.dumps({"bundle": bundle, "authorization": {"synthetic": True}}) + "\n").encode(),
        )
    assert caught.value.code == 0
    assert entered == [{**payload, "authorization": {"synthetic": True}}]


@pytest.mark.parametrize("kind", ["tampered", "bundle-too-large", "frame-too-large", "extra-key"])
def test_bootstrap_rejects_bad_initial_frame_before_entry(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    program, bundle = program_for({})
    initial: dict[str, object] = {"bundle": bundle, "authorization": {}}
    entered: list[object] = []
    monkeypatch.setattr(entry, "run", entered.append)
    if kind == "tampered":
        initial["bundle"] = "x" + bundle[1:]
    elif kind == "bundle-too-large":
        initial["bundle"] = "x" * (transport.MAX_BUNDLE + 1)
        program = program_for_bundle(str(initial["bundle"]))
    elif kind == "extra-key":
        initial["unapproved"] = True
    raw = (json.dumps(initial) + "\n").encode()
    if kind == "frame-too-large":
        raw = b"x" * (1024 * 1024 + 2)
    with pytest.raises(ValueError):
        bootstrap_frame(monkeypatch, program, raw)
    assert not entered


def test_partial_initial_frame_cannot_renew_startup_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_select, calls = select.select, []
    entered: list[object] = []
    prefix = b'{"bundle":'

    def ready(*args: Any) -> tuple[list[object], list[object], list[object]]:  # noqa: ANN401
        calls.append(float(args[-1]))
        if len(calls) > len(prefix):
            return [], [], []
        return cast(tuple[list[object], list[object], list[object]], original_select(*args))

    monkeypatch.setattr(select, "select", ready)
    monkeypatch.setattr(entry, "run", entered.append)
    with pytest.raises(TimeoutError):
        bootstrap_frame(monkeypatch, program_for({})[0], prefix)
    assert not entered
    assert len(calls) == len(prefix) + 1
    assert all(0 < remaining <= transport.STARTUP_SECONDS for remaining in calls)
    assert calls == sorted(calls, reverse=True)


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
@pytest.mark.usefixtures("synthetic_closeout_support")
def test_driver_interrupt_preserves_uncertain_identity_and_never_reexecutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException], case: Case
) -> None:
    tmp_path.chmod(0o700)
    processes: list[object] = []

    class Process:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.stdin, self.stdout = io.BytesIO(), io.BytesIO()
            processes.append(self)

        def poll(self) -> int:
            return 0

    def interrupted(*args: object, **kwargs: object) -> dict[str, object]:
        raise error("synthetic interruption with no retry authority")

    monkeypatch.setattr(subprocess, "Popen", Process)
    monkeypatch.setattr(driver, "send", lambda *a, **kw: None)
    monkeypatch.setattr(driver, "frame", interrupted)
    output = tmp_path / "driver"

    def invoke() -> None:
        driver.execute(
            program=driver_program(case)[0],
            bundle=driver_program(case)[1],
            authorization=case[2],
            controller="a" * 64,
            environment={"DOCKER_HOST": "unix:///synthetic"},
            output=output,
            verify=dict,
        )

    with pytest.raises(error):
        invoke()
    assert (output / "exec-submitted.json").is_file()
    assert json.loads((output / "unresolved.json").read_bytes())["no_replay"] is True
    assert not (output / "verified.json").exists()
    with pytest.raises(FileExistsError):
        invoke()
    assert len(processes) == 1


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
@pytest.mark.usefixtures("synthetic_closeout_support")
def test_entry_interrupt_reports_unresolved_without_claiming_retirement(
    monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    emitted: list[dict[str, object]] = []

    def interrupted(*args: object) -> None:
        raise error("must-not-appear-in-diagnostic")

    monkeypatch.setattr(entry, "bounded_helper", nullcontext)
    monkeypatch.setattr(source, "current_candidate", interrupted)
    monkeypatch.setattr(entry, "emit", emitted.append)
    assert (
        entry.run(
            {
                "plan": {},
                "authorization": {},
                "fixture": {},
                "runtime_revision": "a" * 40,
                "operation": "execute",
            }
        )
        == 1
    )
    assert emitted[0]["status"] == "unresolved" and emitted[0]["no_replay"] is True
    assert "must-not-appear-in-diagnostic" not in json.dumps(emitted)


@pytest.mark.parametrize("acknowledgement", [None, False, 1])
def test_separate_closeout_requires_explicit_boolean_acknowledgement(
    case: Case, acknowledgement: object
) -> None:
    transaction, fixture, approval = case
    changed = {**approval, "acknowledge_separate_closeout_required": acknowledgement}
    with pytest.raises(ValueError):
        transaction.execute(changed)
    assert not fixture.store.deletes and not transaction.root.exists()


@pytest.mark.parametrize("operation", ["execute", "reconcile"])
def test_driver_rejects_opposite_sealed_operation_before_any_exec_or_reservation(
    case: Case, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    program, bundle = driver_program(case, operation)
    effects: list[object] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: effects.append(a))
    output = tmp_path / "mismatched-mode"

    def verify() -> dict[str, object]:
        effects.append("verify")
        return {}

    with pytest.raises(ValueError, match="operation/plan"):
        driver.execute(
            program=program,
            bundle=bundle,
            authorization=case[2],
            controller="a" * 64,
            environment={"DOCKER_HOST": "unix:///synthetic"},
            output=output,
            verify=verify,
            observation_only=operation == "execute",
        )
    assert not output.exists() and effects == []
    assert not case[1].store.deletes


@pytest.mark.parametrize("fault", ["program", "plan", "trailing", "expansion", "unknown"])
def test_driver_mode_check_binds_program_plan_and_bounded_exact_bundle(
    case: Case, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    program, bundle = driver_program(case)
    authorization = case[2]
    if fault == "program":
        program += "\nraise RuntimeError('unbound executable')\n"
    elif fault == "plan":
        authorization = {**authorization, "plan_sha256": "0" * 64}
    elif fault == "trailing":
        bundle = base64.b85encode(base64.b85decode(bundle) + b"trailing").decode()
        program = program_for_bundle(bundle)
    elif fault == "expansion":
        monkeypatch.setattr(transport, "MAX_EXPANDED_BUNDLE", 64)
    else:
        program, bundle = driver_program(case, "unexpected")
    effects: list[object] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: effects.append(a))
    output = tmp_path / "unbound-input"
    with pytest.raises(ValueError):
        driver.execute(
            program=program,
            bundle=bundle,
            authorization=authorization,
            controller="a" * 64,
            environment={"DOCKER_HOST": "unix:///synthetic"},
            output=output,
            verify=dict,
        )
    assert not output.exists() and not effects and not case[1].store.deletes


@pytest.mark.parametrize("count", [0, True, 2, -1])
def test_execution_terminal_requires_exactly_one_integer_delete(case: Case, count: object) -> None:
    result = case[0].execute(case[2])
    outer = {
        "status": "verified",
        "retirement": result,
        "elapsed_seconds": 1.0,
        "provider_delete_submissions": 1,
        "provider_inventory_owner_reads": 2,
    }
    driver.terminal(outer, case[2])
    with pytest.raises(ValueError):
        driver.terminal({**outer, "provider_delete_submissions": count}, case[2])


@pytest.mark.parametrize("boundary", ["driver", "entry", "native-owner"])
def test_missing_supported_closeout_blocks_native_execution_before_effects(
    case: Case,
    owner: context.NativeFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    transaction, fixture, approval = case
    output = tmp_path / "must-not-reserve"
    effects: list[str] = []

    def unexpected(*args: object, **kwargs: object) -> Any:  # noqa: ANN401 - forbidden boundary
        effects.append("unexpected-effect")
        pytest.fail("unimplemented closeout must stop before native work")

    monkeypatch.setattr(source, "current_candidate", unexpected)
    monkeypatch.setattr(entry, "LocalProof", unexpected)
    monkeypatch.setattr(subprocess, "Popen", unexpected)
    monkeypatch.setattr(owner, "owner", unexpected)
    if boundary == "driver":
        program, bundle = driver_program(case)
        with pytest.raises(ValueError, match="staged closeout review is incomplete"):
            driver.execute(
                program=program,
                bundle=bundle,
                authorization=approval,
                controller="a" * 64,
                environment={"DOCKER_HOST": "unix:///synthetic"},
                output=output,
                verify=unexpected,
            )
    elif boundary == "entry":
        emitted: list[dict[str, object]] = []
        monkeypatch.setattr(entry, "emit", emitted.append)
        assert (
            entry.run(
                {
                    "plan": transaction.plan,
                    "fixture": {},
                    "authorization": approval,
                    "runtime_revision": "b" * 40,
                    "operation": "execute",
                }
            )
            == 1
        )
        assert len(emitted) == 1 and emitted[0]["status"] == "unresolved"
        assert emitted[0]["no_replay"] is True
    else:
        with pytest.raises(ValueError, match="staged closeout review is incomplete"):
            owner.before_disposition()
    assert not effects and not output.exists() and not transaction.root.exists()
    assert not fixture.store.deletes


def test_old_permanent_disposal_approval_is_not_reinterpreted(case: Case) -> None:
    transaction, fixture, approval = case
    previous = {**approval, "format": "lowerduckpond-m3-11-frozen-archive-authorization-v1"}
    del previous["acknowledge_separate_closeout_required"]
    previous["acknowledge_permanent_disposal_block"] = True
    with pytest.raises(ValueError):
        transaction.execute(previous)
    assert fixture.guards == 0 and not fixture.store.deletes and not transaction.root.exists()
