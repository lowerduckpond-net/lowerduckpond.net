"""Continue a failed live fixture for diagnosis; never package qualification."""

from __future__ import annotations

import argparse
import json
import os
import traceback
import uuid
from pathlib import Path

from scripts.m3_11_debug_capture import checkpoint, controller, exception
from scripts.m3_11_debug_files import FORMAT, original, workspace
from scripts.m3_11_debug_fixture import inputs
from scripts.m3_11_debug_runner import STAGES, run
from scripts.qualification_context import run_lease
from scripts.qualification_storage_lease import FD_ENV, storage_lease


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--from", dest="start", choices=STAGES)
    parser.add_argument("--exclusive-archive-writers", action="store_true")
    parser.add_argument(
        "--repair", type=Path, help="tracked Python script to execute in the retained destination"
    )
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if not args.exclusive_archive_writers:
            raise ValueError("diagnostic continuation requires exclusive archive writers")
        saved, _ = original(args.directory)
        environment = {**os.environ, "DOCKER_HOST": saved["DOCKER_HOST"]}
        environment.pop("DOCKER_CONTEXT", None)
        with storage_lease(environment) as fd, run_lease(args.directory):
            root = workspace(args.directory)
            os.environ.update(environment)
            environment, _ = inputs(root)
            environment[FD_ENV] = str(fd)
            result = run(
                root,
                environment,
                start=args.start,
                guard=lambda: inputs(root),
                prepare=lambda attempt: controller(attempt, args.repair),
                capture=lambda attempt, label: checkpoint(root, attempt, label, environment),
                repair=args.repair is not None,
            )
        print(json.dumps(result, sort_keys=True))
        return 0 if result["outcome"] == "diagnostic-complete" else 1
    except Exception as error:
        # Setup errors must also leave a traceback, without printing credentials.
        log = args.directory / ("debug-setup-" + uuid.uuid7().hex + ".log")
        try:
            with log.open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                traceback.print_exc(file=stream)
            print(f"Private setup log: {log}")
        except OSError:
            pass
        print(
            json.dumps(
                {
                    "format": FORMAT,
                    "qualification_authority": "none",
                    "outcome": "diagnostic-unavailable",
                    **exception(error),
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
