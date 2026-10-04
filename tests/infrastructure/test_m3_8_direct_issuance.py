"""Execute the actual embedded fixture program across admission failure boundaries."""

from __future__ import annotations

import hashlib
import json
import sys
import time
from collections.abc import Callable
from contextlib import nullcontext
from types import ModuleType, SimpleNamespace

import lowerduckpond_static_host_agent as agent
import pytest
from lowerduckpond_static_host_agent.locks import StateBusyError

IDENTITY = "0198d17f-6f4a-7000-8000-000000000001"


@pytest.mark.parametrize("artifact", [None, b"unchanged artifact bytes"])
@pytest.mark.parametrize("failure", ["transient-busy", "persistent-busy", "rate", "other"])
def test_direct_fixture_issuance_retains_inputs_and_bounds_lock_contention(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    artifact: bytes | None,
    failure: str,
) -> None:
    support = installed_module("test_lifecycle")
    transport = installed_module("test_transport_recovery")
    calls: list[tuple[bytes, dict[str, object]]] = []
    sleeps: list[float] = []
    commits: list[bool] = []
    intakes: list[str] = []
    refusals = 2

    class Issuer:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def issue(self, raw: bytes, **arguments: object) -> SimpleNamespace:
            calls.append((raw, arguments))
            if failure == "persistent-busy" or (
                failure == "transient-busy" and len(calls) <= refusals
            ):
                raise StateBusyError("tenant-state.lock is busy")
            if failure == "rate":
                raise agent.CorrelationRateLimitError("correlation burst limit is exhausted")
            if failure == "other":
                raise RuntimeError("unrelated issuance failure")
            return SimpleNamespace(job_id="accepted-job")

    class Intake:
        def admit(
            self,
            *,
            operation: str,
            correlation_id: str,
            declared: agent.VerifiedArtifact,
            read: Callable[[], bytes],
            blocking: bool,
        ) -> nullcontext[SimpleNamespace]:
            assert operation == "deploy" and correlation_id == IDENTITY and blocking
            assert artifact is not None and read() == artifact
            assert declared == agent.VerifiedArtifact(
                size=len(artifact), sha256=hashlib.sha256(artifact).hexdigest()
            )
            intakes.append(correlation_id)
            return nullcontext(
                SimpleNamespace(
                    artifact=SimpleNamespace(verified=declared),
                    commit=lambda: commits.append(True),
                )
            )

    monkeypatch.setattr(agent, "StateRepository", lambda *_args, **_kwargs: nullcontext(object()))
    monkeypatch.setattr(agent, "ArtifactIntake", lambda *_args, **_kwargs: nullcontext(Intake()))
    monkeypatch.setattr(agent, "CommandPublicationGate", lambda *_args: object())
    monkeypatch.setattr(agent, "AuthorizationIssuer", Issuer)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(time, "sleep", sleeps.append)
    monkeypatch.setattr(support, "_paced_issue", lambda _request, issue: issue())

    def execute(_host: object, command: str) -> str:
        # Run the real generated program with only its installed I/O boundaries
        # doubled. Merely compiling the command cannot catch the CI failure.
        exec(compile(command, "<fixture-issuance>", "exec"), {})  # noqa: S102
        return capsys.readouterr().out.strip()

    monkeypatch.setattr(support, "_issue_command", execute)
    host = SimpleNamespace(run=lambda *_args: SimpleNamespace(rc=0, stdout="/fixture", stderr=""))
    request = support._request("create" if artifact is None else "deploy", IDENTITY)

    def issue() -> str:
        if artifact is None:
            return support._issue_without_handoff(host, request)
        return transport._issue_artifact_without_handoff(host, request, artifact)

    if failure == "transient-busy":
        assert issue() == "accepted-job"
        assert len(calls) == refusals + 1
    elif failure == "persistent-busy":
        with pytest.raises(StateBusyError, match=r"tenant-state\.lock is busy"):
            issue()
        assert len(calls) == support._BUSY_RETRY_ATTEMPTS
    elif failure == "rate":
        with pytest.raises(SystemExit) as stopped:
            issue()
        assert stopped.value.code == support.RATE_LIMIT_EXIT_STATUS
        assert len(calls) == 1
    else:
        with pytest.raises(RuntimeError, match="unrelated issuance failure"):
            issue()
        assert len(calls) == 1
    assert sleeps == [support._BUSY_RETRY_SECONDS] * (len(calls) - 1)
    assert all(raw == calls[0][0] and json.loads(raw) == request for raw, _args in calls)
    assert all(args["artifact"] == calls[0][1]["artifact"] for _raw, args in calls)
    assert intakes == ([] if artifact is None else [IDENTITY])
    assert commits == ([True] if artifact is not None and failure == "transient-busy" else [])
