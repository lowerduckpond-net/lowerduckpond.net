"""Run and inspect an owned installed M3.12 diagnostic attempt."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.m3_12_diagnostic_store import (
    ATTEMPT_ENV,
    ROLES,
    ROOT,
    Attempt,
    clock,
    encode,
    failure,
    process_status,
    projection,
    publish,
    read,
)

ENVIRONMENT = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "UV_CACHE_DIR",
        "UV_PYTHON_INSTALL_DIR",
        "UV_TOOL_DIR",
        "LDP_QUALIFICATION_UNIX_PEER_ADDRESS",
    }
)


@dataclass(frozen=True)
class Step:
    stage: str
    operation: str
    category: str
    arguments: tuple[str, ...]


def emit(value: object) -> None:
    sys.stdout.buffer.write(encode(value))
    sys.stdout.buffer.flush()


def child_environment(attempt: Attempt) -> dict[str, str]:
    return {
        **{name: value for name, value in os.environ.items() if name in ENVIRONMENT},
        ATTEMPT_ENV: str(attempt.directory),
        "M3_10_ARCHIVE_BACKEND": "minio",
        "UV_FROZEN": "1",
        "ANSIBLE_CONFIG": str(ROOT / "config/ansible/ansible.cfg"),
        "ANSIBLE_CALLBACK_PLUGINS": str(ROOT / "config/ansible/plugins/callback"),
        "ANSIBLE_CALLBACKS_ENABLED": "ldp_timing",
        "LDP_QUALIFICATION_TIMING_EVENTS": str(attempt.directory / "timing-events.jsonl"),
    }


def installed_steps(attempt: Attempt, group: str) -> tuple[Step, ...]:
    from scripts.qualification_groups import GROUPS  # noqa: PLC0415 - after private run allocation

    if group not in GROUPS:
        raise ValueError("unsupported installed group")
    # Keep the pinned setup and installed entry point used by the legacy recipe.
    return (
        Step(
            "dependencies",
            "controller",
            "dependencies",
            ("uv", "sync", "--all-packages", "--all-groups", "--frozen"),
        ),
        Step(
            "dependencies",
            "ansible",
            "dependencies",
            (
                "uv",
                "run",
                "--frozen",
                "ansible-galaxy",
                "collection",
                "install",
                "--no-deps",
                "--requirements-file",
                "config/ansible/requirements.yml",
            ),
        ),
        Step(
            "bootstrap",
            "controller",
            "controller",
            (
                "uv",
                "run",
                "--frozen",
                "python",
                "-m",
                "scripts.qualification_timing",
                "run",
                "--directory",
                str(attempt.directory),
                "--",
                "uv",
                "run",
                "--frozen",
                "python",
                str(ROOT / "scripts/qualification_local.py"),
                "--case",
                group,
            ),
        ),
    )


def status(attempt: Attempt) -> dict[str, Any]:
    record = attempt.result()
    result = projection(record)
    if record.get("terminalEvidence") == "recorded":
        process = record.get("process")
        if isinstance(process, dict) and "exit" in process and type(process["exit"]) is int:
            result["process"] = process_status(process["exit"])
        elif isinstance(process, dict) and "signal" in process and type(process["signal"]) is int:
            result["process"] = process_status(-process["signal"])
    result["attemptPath"] = str(attempt.directory)
    result["summaryPath"] = str(attempt.directory / "summary.json")
    result["uncertainWork"] = record.get("outcome") in {"uncertain", "interrupted"} or (
        (attempt.directory / "guest-start.json").is_file()
        and not (attempt.directory / "guest-result.json").is_file()
    )
    result["next"] = ["just", "m3-12", "inspect", str(attempt.directory)]
    return result


def inspect(attempt: Attempt) -> None:
    emit(status(attempt))
    names = attempt.names()
    names.extend(
        name
        for name in ("guest-start.json", "guest-result.json")
        if (attempt.directory / name).is_file()
    )
    for name in names:
        record = attempt.record(name)
        event = projection(record)
        roles = record.get("failures", [])
        event["failureRoles"] = [
            item["role"] for item in roles if isinstance(item, dict) and item.get("role") in ROLES
        ]
        event["layer"] = "guest" if name.startswith("guest-") else "controller"
        emit(event)


def secondary(attempt: Attempt, role: str, operation: str, error: BaseException) -> None:
    try:
        attempt.append(
            "inspection", operation, clock(), incident=failure(role, "controller", operation, error)
        )
    except Exception:
        print("M3.12 diagnostic incident could not be persisted.", file=sys.stderr)


def collect(attempt: Attempt) -> dict[str, Any]:
    """Export one original outcome projection; preserve it on subsequent reads."""
    try:
        original = attempt.result()
        summary = projection(original)
        if original.get("terminalEvidence") != "recorded":
            return summary
        try:
            publish(attempt.directory, "summary.json", summary)
        except FileExistsError:
            if read(attempt.directory, "summary.json") != summary:
                raise ValueError("diagnostic summary conflict") from None
        return summary
    except Exception as error:
        secondary(attempt, "collection", "collector", error)
        raise


def finish(
    attempt: Attempt,
    step: Step,
    started: tuple[str, int],
    result: int,
    error: BaseException | None = None,
) -> int:
    try:
        if isinstance(error, KeyboardInterrupt):
            attempt.append(
                step.stage, step.operation, started, outcome="interrupted", original=True
            )
        else:
            attempt.append(
                step.stage,
                step.operation,
                started,
                status=result,
                original=True,
                incident=failure("primary", step.category, step.operation, error)
                if error
                else None,
            )
    except Exception as persistence_error:
        secondary(attempt, "finalization", "filesystem", persistence_error)
        print(
            "M3.12 original checkpoint write failed. Inspect the last durable start.",
            file=sys.stderr,
        )
        if not result:
            return 2
    return result if result >= 0 else 128 - result


def execute(attempt: Attempt, steps: Iterable[Step]) -> int:
    """Keep the controller result separate from all observations and collection."""
    with attempt.lock("controller.lock", blocking=False):
        environment = child_environment(attempt)
        for step in steps:
            start = clock()
            try:
                with attempt.lock("dispatch.lock"):
                    if os.path.lexists(attempt.directory / "cancel.json"):
                        attempt.append(
                            step.stage, step.operation, start, outcome="interrupted", original=True
                        )
                        return 130
                    attempt.append(step.stage, step.operation, start)
                    child = subprocess.Popen(  # noqa: S603 - fixed installed command sequence
                        step.arguments,
                        env=environment,
                        cwd=ROOT,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                result = child.wait()
            except KeyboardInterrupt as interrupt:
                return finish(attempt, step, start, 130, interrupt)
            except OSError as launch_error:
                return finish(attempt, step, start, 2, launch_error)
            if result:
                return finish(
                    attempt,
                    step,
                    start,
                    result,
                    subprocess.CalledProcessError(result, step.arguments),
                )
            attempt.append(step.stage, step.operation, start, status=0)
        return finish(attempt, Step("acceptance", "controller", "controller", ()), clock(), 0)


def run(arguments: Sequence[str]) -> int:
    data = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))).absolute()
    configured = os.environ.get("LDP_M3_12_DIAGNOSTIC_ROOT")
    root = Path(configured).absolute() if configured else data / "lowerduckpond.net/m3-12"
    attempt = Attempt.allocate(root)
    print(f"Private M3.12 diagnostic attempt: {attempt.directory}", flush=True)
    try:
        if len(arguments) != 1:
            raise ValueError("an installed group is required")
        steps = installed_steps(attempt, arguments[0])
    except Exception as error:
        attempt.append(
            "allocation",
            "controller",
            clock(),
            status=2,
            original=True,
            incident=failure("primary", "prerequisite", "controller", error),
        )
        result = 2
    else:
        result = execute(attempt, steps)
    try:
        collect(attempt)
    except Exception:
        print("M3.12 collection unavailable; original result retained.", file=sys.stderr)
        result = result or 2
    try:
        emit(status(attempt))
    except Exception:
        print("M3.12 status unavailable; inspect the private attempt.", file=sys.stderr)
        result = result or 2
    return result


def cli(arguments: Sequence[str]) -> int:
    if arguments[:1] == ["run"]:
        return run(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "status",
            "prepare",
            "inspect",
            "collect",
            "debug",
            "resume",
            "finalize",
            "cancel",
            "cleanup",
        ),
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--guest", choices=("start", "result"))
    parser.add_argument(
        "--shell", action="store_true", help="open an attended shell on the retained owned guest"
    )
    args = parser.parse_args(arguments)
    if args.guest and args.action != "collect":
        raise ValueError("guest readback requires collection")
    if args.shell and args.action != "debug":
        raise ValueError("shell is available only for debugging")
    if args.action == "prepare":
        from scripts.m3_12_successor import preview  # noqa: PLC0415

        emit(preview(args.directory.absolute()))
        return 0
    attempt = Attempt(args.directory.absolute())
    if args.action == "status":
        emit(status(attempt))
    elif args.action == "inspect":
        inspect(attempt)
    elif args.action == "collect" and args.guest:
        from scripts.m3_12_diagnostic_transport import collect_guest  # noqa: PLC0415

        emit(projection(collect_guest(attempt, args.guest)))
    elif args.action in {"collect", "finalize"}:
        emit(collect(attempt))
    else:
        from scripts.m3_12_diagnostic_transport import retained  # noqa: PLC0415

        emit(retained(attempt, args.action, shell=args.shell))
    return 0


def main() -> int:
    os.umask(0o077)
    try:
        return cli(sys.argv[1:])
    except Exception:
        print(
            "M3.12 diagnostic action refused or unavailable. Inspect the original attempt.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
