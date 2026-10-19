"""Record execution readiness under preserved standing consent; never grant consent."""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import publish_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import approval, standing_authority
from scripts.m3_11_unattended import operator_records as records
from scripts.m3_11_unattended.journal import MAX_OUTPUT
from scripts.m3_11_unattended.model import (
    LifecycleError,
    digest,
    fingerprint,
    instant,
    stamp,
    strings,
)
from scripts.m3_11_unattended.state import private_directory


def execution_record(  # noqa: PLR0913 - exact sources and preserved execution clock
    body: dict[str, object],
    *,
    authorized: dict[str, object],
    checked: dict[str, object],
    assessment: Path,
    learning_reference: str,
    review_reference: str,
    checked_at: str,
) -> dict[str, object]:
    return {
        **{key: value for key, value in body.items() if key not in {"format", "expires_at"}},
        "format": standing_authority.EXECUTION_FORMAT,
        "authority": authorized,
        "assessment": checked,
        "assessment_path": str(assessment.resolve(strict=True)),
        "readiness": {
            "checked_at": checked_at,
            "expires_at": body["expires_at"],
            "learning_reference": learning_reference,
            "review_reference": review_reference,
        },
    }


def record(  # noqa: PLR0913 - exact external evidence, reviewed proposal and one output
    *,
    proposal: Path,
    expected: str,
    authority: Path,
    assessment: Path,
    learning_reference: str,
    review_reference: str,
    output: Path,
    now: datetime,
) -> dict[str, object]:
    proposed = fields(
        records.read(proposal), {"format", "kind", "sources", "parameters", "proposed"}
    )
    if (
        proposed["format"] != records.FORMAT
        or proposed["kind"] != "attempt"
        or digest(proposed) != fingerprint(expected)
        or not isinstance(proposed["sources"], dict)
        or set(proposed["sources"]) != {"inputs", "prepared", "reuse_status"}
        or not isinstance(proposed["parameters"], dict)
        or not isinstance(proposed["proposed"], dict)
    ):
        raise LifecycleError("readiness requires the exact retained-lease attempt proposal")
    authorized, checked = records.read(authority), records.read(assessment)
    standing_authority.reference(learning_reference)
    standing_authority.reference(review_reference)
    inputs = {
        "proposal": proposed,
        "authority": authorized,
        "assessment": checked,
        "assessment_path": str(assessment.resolve(strict=True)),
        "learning_reference": learning_reference,
        "review_reference": review_reference,
    }
    records.local(output)
    # Readback never renews even an expired record's original checked_at.
    if output.exists():
        private_directory(output)
        if {p.name for p in output.iterdir()} != {
            "inputs.json",
            "receipt.json",
            "live-approval.json",
        }:
            raise LifecycleError("readiness output is incomplete; preserve it")
        result = records.read(output / "live-approval.json")
        receipt = records.read(output / "receipt.json")
        if records.read(output / "inputs.json") != inputs or receipt != {
            "inputs_sha256": digest(inputs),
            "record_sha256": digest(result),
        }:
            raise LifecycleError("readiness output conflicts with the original")
        readiness = fields(
            result["readiness"],
            {
                "checked_at",
                "expires_at",
                "learning_reference",
                "review_reference",
            },
        )
        if result != execution_record(
            proposed["proposed"],
            authorized=authorized,
            checked=checked,
            assessment=assessment,
            learning_reference=learning_reference,
            review_reference=review_reference,
            checked_at=str(readiness["checked_at"]),
        ):
            raise LifecycleError(
                "retained readiness differs from its original proposal and consent"
            )
        approval.validate(
            result, mode=str(proposed["parameters"]["mode"]), now=instant(readiness["checked_at"])
        )
        return result
    standing_authority.authority(authorized, now=now)
    standing_authority.assessment(checked, authorized=authorized, now=now)
    sources: dict[str, dict[str, object]] = {}
    for key, raw in proposed["sources"].items():
        entry = strings(fields(raw, {"path", "sha256"}))
        source = records.read(Path(entry["path"]))
        if digest(source) != fingerprint(entry["sha256"]):
            raise LifecycleError("readiness proposal source facts changed")
        sources[str(key)] = source
    body = records.build("attempt", sources, proposed["parameters"], now=now)
    if body != proposed["proposed"]:
        raise LifecycleError("readiness proposal facts changed")
    result = execution_record(
        body,
        authorized=authorized,
        checked=checked,
        assessment=assessment,
        learning_reference=learning_reference,
        review_reference=review_reference,
        checked_at=stamp(now),
    )
    approval.validate(result, mode=str(proposed["parameters"]["mode"]), now=now)
    # Files are an offline record, not a provider/cleanup validation receipt.
    # A changed assessment while rebuilding inputs must not publish readiness.
    if records.read(assessment) != checked or records.read(authority) != authorized:
        raise LifecycleError("standing authority changed while recording readiness")
    output.mkdir(mode=0o700)
    write_private(output / "inputs.json", cast(dict[str, object], inputs), maximum=MAX_OUTPUT)
    write_private(
        output / "receipt.json",
        {
            "inputs_sha256": digest(inputs),
            "record_sha256": digest(result),
        },
        maximum=MAX_OUTPUT,
    )
    publish_private(output / "live-approval.json", result, maximum=MAX_OUTPUT)
    return result


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("proposal", "authority", "assessment", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-proposal-sha256", "learning-reference", "review-reference"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = record(
            proposal=args.proposal,
            expected=args.expected_proposal_sha256,
            authority=args.authority,
            assessment=args.assessment,
            learning_reference=args.learning_reference,
            review_reference=args.review_reference,
            output=args.output,
            now=datetime.now(UTC),
        )
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(
            1, "Readiness incomplete; preserve original consent, assessment and candidate.\n"
        )
    print(str(args.output) + " " + digest(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
