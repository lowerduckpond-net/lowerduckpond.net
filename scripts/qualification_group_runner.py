"""Execute one declared group stage and receipt only an exact, entirely passing run."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from scripts.qualification_context import ARTIFACT_ENV, RUN_ENV, host_name
from scripts.qualification_groups import GROUPS

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "config/ansible/molecule/m3_8"
FORMAT = "lowerduckpond-installed-group-stage-v1"


class Completion:
    """A zero exit code alone cannot prove that the required assertions ran."""

    def __init__(self, expected: tuple[str, ...]) -> None:
        self.expected = expected
        self.collected: list[str] = []
        self.reports: dict[str, list[tuple[str, str, bool]]] = {}

    @staticmethod
    def relative(nodeid: str) -> str:
        return nodeid.removeprefix("config/ansible/molecule/m3_8/")

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.collected = [self.relative(item.nodeid) for item in session.items]

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        self.reports.setdefault(self.relative(report.nodeid), []).append(
            (report.when, report.outcome, hasattr(report, "wasxfail"))
        )

    def passed(self, status: int) -> bool:
        return (
            bool(self.expected)
            and status == 0
            and self.collected == list(self.expected)
            and set(self.reports) == set(self.expected)
            and all(
                stages == [(phase, "passed", False) for phase in ("setup", "call", "teardown")]
                for stages in self.reports.values()
            )
        )


def run(case: str, stage: str) -> int:
    host = host_name()
    if (
        not os.environ.get(RUN_ENV)
        or os.environ.get("M3_10_ARCHIVE_BACKEND") != "minio"
        or os.environ.get("M3_10_INSTALLED_REPORT")
    ):
        raise ValueError("installed groups require a fresh owned local fixture")
    nodes = GROUPS[case].nodes(stage, host)
    destination = Path(os.environ[ARTIFACT_ENV]).parent.parent / f"group-{stage}.json"
    if destination.exists():
        raise ValueError("a group stage cannot be repeated in the same fixture")
    completion = Completion(nodes)
    status = int(
        pytest.main(
            [
                "--verbose",
                f"--hosts=docker://{host}",
                *(f"{SCENARIO}/{value}" for value in nodes),
            ],
            plugins=[completion],
        )
    )
    if not completion.passed(status):
        return status or 2
    with destination.open("x", encoding="ascii") as stream:
        json.dump(
            {
                "format": FORMAT,
                "run_id": os.environ[RUN_ENV],
                "case": case,
                "stage": stage,
                "nodes": nodes,
            },
            stream,
            sort_keys=True,
        )
        stream.write("\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=tuple(GROUPS))
    parser.add_argument("stage", choices=("run", "before", "after"))
    args = parser.parse_args()
    return run(args.case, args.stage)


if __name__ == "__main__":
    raise SystemExit(main())
