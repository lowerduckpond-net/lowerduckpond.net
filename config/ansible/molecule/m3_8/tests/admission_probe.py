"""Read immutable host history and ask the installed admission policy for eligibility."""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

MAX_RECORD_BYTES = 1024 * 1024
MAX_CORRELATIONS = 10000
MICROSECOND = timedelta(microseconds=1)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def eligible_at(history: tuple[datetime, ...], now: datetime) -> datetime:
    from lowerduckpond_static_host_agent.correlations import (  # noqa: PLC0415
        CorrelationRateLimitError,
        _admit_rate,
    )

    try:
        _admit_rate(history, now)
    except CorrelationRateLimitError:
        pass
    else:
        return now
    low, high = now, max((now, *history)) + timedelta(hours=1)
    # Invalid historical admissions must fail here, rather than invent capacity.
    _admit_rate(history, high)
    while high - low > MICROSECOND:
        middle = low + (high - low) // 2
        try:
            _admit_rate(history, middle)
        except CorrelationRateLimitError:
            low = middle
        else:
            high = middle
    return high


def history_from(directory: Path) -> dict[str, datetime]:
    from lowerduckpond_static_contracts import (  # noqa: PLC0415
        ContractKind,
        validate_contract,
        validate_uuid7,
    )
    from lowerduckpond_static_host_agent.correlations import _accepted_at  # noqa: PLC0415

    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        history: dict[str, datetime] = {}
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(history) >= MAX_CORRELATIONS:
                    raise ValueError("fixture correlation history exceeds the bound")
                identity = validate_uuid7(entry.name.removesuffix(".json"))
                if entry.name != f"{identity}.json":
                    raise ValueError("unexpected fixture correlation record")
                record_fd = os.open(
                    entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
                )
                try:
                    if not stat.S_ISREG(os.fstat(record_fd).st_mode):
                        raise ValueError("fixture correlation is not a regular file")
                    with os.fdopen(record_fd, "rb", closefd=False) as stream:
                        raw = stream.read(MAX_RECORD_BYTES + 1)
                    if len(raw) > MAX_RECORD_BYTES:
                        raise ValueError("fixture correlation exceeds the record bound")
                    record = json.loads(raw)
                    validate_contract(record, expected_kind=ContractKind.AUTHORIZATION_JOB)
                    if record["request"]["correlationId"] != identity:
                        raise ValueError("fixture correlation filename and binding differ")
                    history[identity] = _accepted_at(record)
                finally:
                    os.close(record_fd)
        return history
    finally:
        os.close(descriptor)


def observation(history: dict[str, datetime], identity: str, now: datetime) -> dict[str, object]:
    recorded = identity in history
    eligible = now if recorded else eligible_at(tuple(history.values()), now)
    return {
        "recorded": recorded,
        "host_now_us": (now - EPOCH) // MICROSECOND,
        "eligible_at_us": (eligible - EPOCH) // MICROSECOND,
    }


def assert_installed_policy() -> None:
    """Exercise denials with synthetic timestamps; never alter the host's clock/state."""
    from lowerduckpond_static_host_agent.correlations import (  # noqa: PLC0415
        CorrelationRateLimitError,
        _admit_rate,
    )

    now = datetime(2026, 9, 18, tzinfo=UTC)
    cases = (
        ((now,) * 5, now, now + timedelta(minutes=1)),
        (
            tuple(now + timedelta(minutes=i) for i in range(60)),
            now + timedelta(minutes=59, seconds=1),
            now + timedelta(hours=1),
        ),
        ((now,), now - MICROSECOND, now),
    )
    for history, denied, allowed in cases:
        try:
            _admit_rate(history, denied)
        except CorrelationRateLimitError:
            pass
        else:
            raise ValueError("installed admission policy did not enforce its denial")
        _admit_rate(history, allowed)


def main() -> int:
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(30)
    try:
        current = Path("/opt/lowerduckpond/static-host-agent/current")
        selected = current.resolve(strict=True)
        if (
            selected.parent != current.parent
            or re.fullmatch(r"[0-9a-f]{64}", selected.name) is None
        ):
            raise ValueError("invalid installed admission artifact selection")
        sys.path.insert(0, str(selected / "site-packages"))
        from lowerduckpond_static_contracts import validate_uuid7  # noqa: PLC0415

        if sys.argv[1:] == ["--policy-check"]:
            assert_installed_policy()
            print('{"installed_policy":"passed"}')
            return 0
        if len(sys.argv) != 2:  # noqa: PLR2004 - one UUID argument
            raise ValueError("expected one fixture correlation")
        identity = validate_uuid7(sys.argv[1])
        history = history_from(Path("/var/lib/lowerduckpond/static/authorization/correlations"))
        print(json.dumps(observation(history, identity, datetime.now(UTC))))
        return 0
    except Exception:
        print("Installed admission observation is unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
