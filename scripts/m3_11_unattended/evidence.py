"""Export only validated, constructed public receipts; raw logs remain private."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts import qualification_deadline, qualification_failure
from scripts.m3_10_qualification_report import verify_report
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import digest as sha256
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import historical_absence
from scripts.m3_11_unattended.connect_diagnostics import verified_failure
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.model import Intent, LifecycleError, identity, instant, stamp
from scripts.m3_11_unattended.state import PHASES, RunState
from scripts.production_qualification_inputs import revision


def watchdog_receipts(directory: Path, binding: dict[str, object]) -> list[dict[str, object]]:
    """Project retained watchdog closure with the same complete local intent coverage."""
    paths = sorted(directory.glob("watchdog-revocation-*.json"))
    if not paths:
        return []
    owned = set()
    for path in (directory / "credential-intents").glob("*.json"):
        intent = Intent.parse(read_private(path))
        if (
            path.stem != intent.sha256
            or intent.run_id != binding["managed_run_id"]
            or intent.source_revision != binding["source_revision"]
            or intent.helper_revision != binding["helper_revision"]
            or intent.targets.storage_digest != binding["storage_target_sha256"]
        ):
            raise LifecycleError("watchdog evidence has a misbound local intent")
        owned.add(intent.sha256)
    receipts: list[dict[str, object]] = []
    for path in paths:
        value = fields(
            read_private(path), {"format", "binding", "helper_revision", "observed_at", "results"}
        )
        if (
            value["format"] != "lowerduckpond-m3-11-watchdog-revocation-v1"
            or value["binding"] != binding
            or not isinstance(value["results"], list)
        ):
            raise LifecycleError("watchdog revocation receipt differs from this attempt")
        # A newer trusted watchdog may finish cleanup of an older pinned run.
        helper = revision(value["helper_revision"])
        observed_at = stamp(instant(value["observed_at"]))
        results = []
        for entry in value["results"]:
            row = fields(entry, {"intent_sha256", "status", "negative_authentication"})
            sha256(row["intent_sha256"])
            if row["status"] != "verified" or row["negative_authentication"] not in {
                "denied",
                "unavailable",
                "not-tested",
            }:
                raise LifecycleError("watchdog revocation result is invalid")
            results.append(row)
        if len(results) != len(owned) or {row["intent_sha256"] for row in results} != owned:
            raise LifecycleError("watchdog revocation evidence lacks complete local coverage")
        receipts.append({"helper_revision": helper, "observed_at": observed_at, "results": results})
    return receipts


def export(  # noqa: PLR0912 - each evidence family has its own closed validation
    directory: Path, *, repository: Path, include_report: bool
) -> dict[str, object]:
    state = RunState(directory)
    request = read_private(directory / "request.json")
    binding = fields(request["binding"], BINDING)
    identity(binding["managed_run_id"])
    for name in ("source_revision", "helper_revision"):
        revision(binding[name])
    for name in BINDING - {"managed_run_id", "source_revision", "helper_revision"}:
        sha256(binding[name])
    result: dict[str, object] = {"binding": binding, "status": state.status()}
    for name in ("worker", "cleanup", "production"):
        path = directory / (name + "-failure.json")
        if path.exists():
            result[name + "_diagnostic"] = verified_failure(
                read_private(path),
                binding=binding,
                stages=frozenset({"bootstrap", "validate"}) if name == "production" else PHASES,
            )
    # Reuse the supervisor's private, bounded context and existing fixed-label
    # failure projection. Phase is an observation, never a completion receipt.
    context = directory / "supervisor/context.json"
    if context.exists():
        selected, phase, _endpoint = qualification_deadline.context(context)
        if not selected.is_relative_to(directory / "qualification"):
            raise LifecycleError("supervisor context escaped its original attempt")
        result["last_qualification_phase"] = phase
        result["controller_failure"] = qualification_failure.controller_failure(selected)
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
                historical_absence.STATUS,
            } or record["negative_authentication"] not in {
                "denied",
                "unavailable",
                "unverified",
                "not-tested",
            }:
                raise LifecycleError("revocation result is invalid")
            if record["status"] == historical_absence.STATUS and (
                record["intent_sha256"] != historical_absence.INTENT
                or record["negative_authentication"] != "unavailable"
            ):
                raise LifecycleError("historical exception differs from the approved obligation")
            public.append(record)
        result["revocation"] = {
            "observed_at": stamp(instant(value["observed_at"])),
            "results": public,
        }
    watchdog = watchdog_receipts(directory, binding)
    if watchdog:
        result["watchdog_revocations"] = watchdog
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
            managed_binding=binding,
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
