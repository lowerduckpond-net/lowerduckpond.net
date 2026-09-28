"""Private trace messages cannot leak values or masquerade as another invocation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import m3_11_debug_trace as trace


def sample(**changes: object) -> dict[str, object]:
    return {
        "event": "sample",
        "step": "installed-audit",
        "invocation": "a" * 32,
        "elapsed_seconds": 60.0,
        "cpu_seconds": 10.0,
        "stack": [{"file": "locks.py", "line": 123, "function": "acquire"}],
        **changes,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"secret": "private-canary"},
        {"invocation": "b" * 32},
        {"step": "private-canary"},
        {"cpu_seconds": float("nan")},
        {"elapsed_seconds": -1},
        {"event": ["sample"]},
        {"stack": [{"file": "/private/canary.py", "line": 1, "function": "acquire"}]},
        {"stack": [{"file": "locks.py", "line": True, "function": "acquire"}]},
        {"stack": [{"file": "locks.py", "line": 1, "function": "secret=value"}]},
    ],
)
def test_unclassified_private_fields_and_stale_invocations_are_omitted(
    changes: dict[str, object],
) -> None:
    assert trace.event(json.dumps(sample(**changes)), "a" * 32) is None


def test_compact_summary_is_bound_to_coordinator_invocation(tmp_path: Path) -> None:
    path = tmp_path / "restore.journals.log"
    path.write_text(
        "\n".join(
            [
                "lowerduckpond-host-restore.service",
                "InvocationID=" + "a" * 32,
                "private journal canary",
                "timestamp " + trace.PREFIX + json.dumps(sample(invocation="b" * 32)),
                "timestamp " + trace.PREFIX + json.dumps(sample()),
                "timestamp " + trace.PREFIX + json.dumps(sample(elapsed_seconds=90.0)),
                "caddy.service",
                "timestamp " + trace.PREFIX + json.dumps(sample()),
            ]
        )
    )
    result = trace.summarize(path)
    assert result["events"] == 2  # noqa: PLR2004 - two current coordinator samples
    assert result["sample_locations"] == [
        {"file": "locks.py", "line": 123, "function": "acquire", "samples": 2}
    ]
    assert "private" not in json.dumps(result)
    assert "invocation" not in json.dumps(result)


def test_missing_invocation_does_not_reuse_old_traces(tmp_path: Path) -> None:
    path = tmp_path / "restore.journals.log"
    path.write_text("lowerduckpond-host-restore.service\n" + trace.PREFIX + json.dumps(sample()))
    assert trace.summarize(path) == {"collection": "unavailable"}
