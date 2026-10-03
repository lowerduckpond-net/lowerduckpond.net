"""Export only validated, constructed public receipts; raw logs remain private."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.m3_10_qualification_report import verify_report
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import digest as sha256
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.model import LifecycleError, identity, instant, stamp
from scripts.m3_11_unattended.state import RunState
from scripts.production_qualification_inputs import revision


def export(directory: Path, *, repository: Path, include_report: bool) -> dict[str, object]:
    state = RunState(directory)
    request = read_private(directory / "request.json")
    binding = fields(request["binding"], BINDING)
    identity(binding["managed_run_id"])
    for name in ("source_revision", "helper_revision"):
        revision(binding[name])
    for name in BINDING - {"managed_run_id", "source_revision", "helper_revision"}:
        sha256(binding[name])
    result: dict[str, object] = {"binding": binding, "status": state.status()}
    receipt = directory / "revocation.json"
    if receipt.exists():
        value = fields(
            read_private(receipt),
            {
                "actor",
                "helper_revision",
                "observed_at",
                "status",
                "overdue",
                "results",
            },
        )
        if value["actor"] != "controller" or value["helper_revision"] != binding["helper_revision"]:
            raise LifecycleError("revocation receipt is not bound to this controller")
        entries = value["results"]
        if not isinstance(entries, list):
            raise LifecycleError("revocation receipt is malformed")
        public = []
        for entry in entries:
            record = fields(entry, {"intent_sha256", "status", "negative_authentication"})
            sha256(record["intent_sha256"])
            if record["status"] not in {
                "verified",
                "not-due",
                "unresolved",
                "creation-uncertain",
            } or record["negative_authentication"] not in {
                "denied",
                "unavailable",
                "unverified",
                "not-tested",
            }:
                raise LifecycleError("revocation result is invalid")
            public.append(record)
        result["revocation"] = {
            "observed_at": stamp(instant(value["observed_at"])),
            "results": public,
        }
    if include_report and state.status()["qualification"] == "passed":
        paths = list((directory / "qualification").glob("*/qualification.json"))
        if len(paths) != 1:
            raise LifecycleError("qualification report is missing or ambiguous")
        # The existing full report verifier enforces its closed sanitized schemas.
        raw = verify_report(
            paths[0],
            source=str(binding["source_revision"]),
            artifact=str(binding["artifact_sha256"]),
            repository=repository,
            storage_target=str(binding["storage_target_sha256"]),
            milestone="3.11",
        )
        result["qualification_report"] = json.loads(raw)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "evidence", "cancel"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "cancel":
            RunState(args.directory).cancel()
            print('{"cancellation":"requested"}')
        else:
            print(
                json.dumps(
                    export(
                        args.directory,
                        repository=args.source,
                        include_report=args.action == "evidence",
                    ),
                    sort_keys=True,
                )
            )
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Sanitized evidence is unavailable; retain the private controller volume.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
