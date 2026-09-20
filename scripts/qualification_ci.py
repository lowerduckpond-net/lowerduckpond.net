"""Publish the fixed CI matrix and reject incomplete selected-group results."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.qualification_case import validate_installed_receipt
from scripts.qualification_context import RUN_PATTERN
from scripts.qualification_groups import GROUP_REPORT_FORMAT
from scripts.qualification_probe import document
from scripts.qualification_selection import ALL, FORMAT, select_revisions, selection


def selected_cases(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"format", "mode", "reason", "cases"}:
        raise ValueError("invalid installed selection")
    cases = value["cases"]
    if (
        value["format"] != FORMAT
        or not isinstance(value["reason"], str)
        or not isinstance(cases, list)
        or any(not isinstance(case, str) for case in cases)
        or cases != [case for case in ALL if case in cases]
        or value["mode"] != ("all" if cases == list(ALL) else "affected" if cases else "none")
    ):
        raise ValueError("invalid installed selection")
    return cases


def complete_required(event: str) -> bool:
    return event not in {"pull_request", "push"}


def matrix(cases: list[str]) -> dict[str, object]:
    return {"include": [{"case": case} for case in cases] or [{"case": "none"}]}


def plan(event: str, base: str, head: str) -> dict[str, object]:
    return (
        selection(ALL, "scheduled-manual-or-release")
        if complete_required(event)
        else select_revisions(base, head)
    )


def verify(  # noqa: PLR0913 - explicit required CI lane results
    value: object,
    directory: Path,
    *,
    event: str,
    matrix_result: str,
    complete_result: str,
    static_result: str,
) -> None:
    cases = selected_cases(value)
    complete = complete_required(event)
    if (
        static_result != "success"
        or matrix_result != ("success" if cases else "skipped")
        or complete_result != ("success" if complete else "skipped")
        or (complete and cases != list(ALL))
    ):
        raise ValueError("a required installed job did not pass")
    expected = {f"installed-result-{case}" for case in cases}
    entries = {path.name for path in directory.iterdir()} if directory.exists() else set()
    # Pinned download-artifact v8 flattens a single pattern match, even with
    # merge-multiple=false. It creates named directories for multiple matches.
    single_flat = len(cases) == 1 and entries == {"case.json"}
    if not single_flat and entries != expected:
        raise ValueError("selected installed result is missing or unexpected")
    owners = set()
    for case in cases:
        report = document(
            directory / "case.json"
            if single_flat
            else directory / f"installed-result-{case}" / "case.json"
        )
        run_id = report.get("run_id")
        installed = report.get("installed")
        if case == "full-size-archive":
            if not isinstance(installed, dict) or not isinstance(run_id, str):
                raise ValueError("full-size installed evidence is missing")
            validate_installed_receipt(installed, run_id)
        if (
            not isinstance(run_id, str)
            or RUN_PATTERN.fullmatch(run_id) is None
            or run_id in owners
            or report
            != {
                "format": GROUP_REPORT_FORMAT,
                "authority": "diagnostic-only",
                "case": case,
                "run_id": run_id,
                "backend": "minio",
                "status": "passed",
                "local_accounting": "passed",
                "independent_storage_absence": "passed",
                "destroy": "passed",
                **({"installed": installed} if case == "full-size-archive" else {}),
            }
        ):
            raise ValueError("selected installed result is incomplete")
        owners.add(run_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "verify"))
    parser.add_argument("--event", required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    if args.command == "plan":
        value = plan(args.event, args.base, args.head)
        cases = selected_cases(value)
        values = {
            "selection": json.dumps(value, separators=(",", ":")),
            "matrix": json.dumps(matrix(cases), separators=(",", ":")),
            "required": str(bool(cases)).lower(),
            "complete": str(complete_required(args.event)).lower(),
        }
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="ascii") as stream:
            for key, item in values.items():
                stream.write(f"{key}={item}\n")
        print(values["selection"])
        return 0
    if args.directory is None:
        parser.error("verify requires a result directory")
    try:
        verify(
            json.loads(os.environ["INSTALLED_SELECTION"]),
            args.directory,
            event=args.event,
            matrix_result=os.environ["MATRIX_RESULT"],
            complete_result=os.environ["COMPLETE_RESULT"],
            static_result=os.environ["STATIC_RESULT"],
        )
    except OSError, ValueError, KeyError:
        print("Required installed checks or their completion receipts did not pass.")
        return 1
    print("Every required installed group and accounting receipt passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
