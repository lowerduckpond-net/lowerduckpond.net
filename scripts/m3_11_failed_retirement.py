"""Explicit failed-fixture archive retirement on the secure workstation."""

from __future__ import annotations

import argparse
import json
import os
import traceback
from pathlib import Path

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_retirement_context import Context
from scripts.m3_11_retirement_files import RetirementError, directory
from scripts.m3_11_retirement_live import SpacesFixture
from scripts.m3_11_retirement_receipt import FORMAT, receipt
from scripts.m3_11_retirement_transaction import Retirement, summary
from scripts.qualification_context import run_lease
from scripts.qualification_storage_lease import storage_lease


def inspect(run: Path) -> dict[str, object]:
    directory(run)
    root = run / "failed-archive-retirement"
    if not root.exists():
        return {"format": FORMAT, "stage": "not-prepared", "qualification_authority": "none"}
    directory(root)
    if (root / "retired.json").exists():
        return receipt(read_private(root / "retired.json"))
    if (root / "plan.json").exists():
        result = summary(read_private(root / "plan.json"))
        result["deletion_authorized"] = (root / "authorization.json").exists()
        result["versions_retired"] = sum(
            (root / f"deleted-{index:02d}.json").exists() for index in range(25)
        )
        result["progress_authority"] = "local-diagnostic-only"
        return result
    return {"format": FORMAT, "stage": "preparation-incomplete", "qualification_authority": "none"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "retire", "inspect"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--plan-sha256")
    parser.add_argument("--acknowledge-failed-run-data-loss", action="store_true")
    parser.add_argument("--exclusive-archive-writers", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.action == "inspect":
            result = inspect(arguments.directory)
        else:
            if not arguments.exclusive_archive_writers:
                raise RetirementError(
                    "other workstation and production archive writers must be excluded"
                )
            context = Context(arguments.directory, os.environ)
            with storage_lease(context.environment), run_lease(arguments.directory):
                transaction = Retirement(arguments.directory, SpacesFixture(context))
                result = (
                    transaction.prepare()
                    if arguments.action == "prepare"
                    else transaction.retire(
                        arguments.plan_sha256 or "",
                        acknowledge=arguments.acknowledge_failed_run_data_loss,
                    )
                )
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        # All raw coordinates, credential values and provider responses stay private.
        print(
            json.dumps(
                {
                    "format": FORMAT,
                    "stage": arguments.action,
                    "outcome": "incomplete",
                    "reason": str(error)
                    if isinstance(error, RetirementError)
                    else (
                        "A required input, filesystem or provider observation failed; "
                        "original evidence is retained."
                    ),
                    "qualification_authority": "none",
                    "locations": [
                        {"file": Path(frame.filename).name, "line": frame.lineno}
                        for frame in traceback.extract_tb(error.__traceback__)
                        if Path(frame.filename).name.startswith("m3_11_retirement_")
                    ][-8:],
                },
                sort_keys=True,
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
