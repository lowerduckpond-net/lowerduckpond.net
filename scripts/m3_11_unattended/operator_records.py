"""Local proposal serialization and explicit consent records; never an approval authority."""

from __future__ import annotations

import argparse
import dataclasses
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import publish_private, read_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import approval, operator_assemble
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.journal import (
    MAX_OUTPUT,
    MIGRATION_FORMAT,
    MIGRATION_FORMAT_V2,
    migration,
)
from scripts.m3_11_unattended.journal import validate as event_validate
from scripts.m3_11_unattended.legacy_terminal import validate_claims
from scripts.m3_11_unattended.lifecycle import _intents, _known_id
from scripts.m3_11_unattended.model import (
    LEASE_POLICY_FORMAT,
    LeaseManifest,
    LeasePolicy,
    LifecycleError,
    Targets,
    digest,
    fingerprint,
    identity,
    instant,
    strings,
)
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import (
    current_candidate,
    revision,
)
from scripts.production_qualification_inputs import (
    fingerprint as source_fingerprint,
)
from scripts.qualification_budget import MINIMUM_TOKEN_REMAINING

FORMAT = "lowerduckpond-m3-11-operator-proposal-v1"
EVIDENCE_FORMAT = "lowerduckpond-m3-11-migration-evidence-v1"
RETRY_FORMAT = "lowerduckpond-m3-11-retry-basis-v1"
POLICY_KEYS = {
    "start_before",
    "issuance_before",
    "credential_lifetime_seconds",
    "cleanup_reserve_seconds",
    "retain_after_failure",
}
CONSENT = {"approved_at", "approval_reference"}
MAX_APPROVAL_REFERENCE = 256
FIRST_PRINTABLE = 32
FILENAMES = {
    "policy": "policy.json",
    "migration": "legacy-import.json",
    "attempt": "live-approval.json",
}


def local(path: Path) -> Path:
    private_directory(path.parent)
    if path.resolve().is_relative_to(operator_assemble.ROOT):
        raise LifecycleError("operator records must remain outside the source checkout")
    return path


def read(path: Path) -> dict[str, object]:
    return read_private(local(path), maximum=MAX_OUTPUT)


def policy_body(value: object) -> dict[str, object]:
    if isinstance(value, dict) and value.get("format") in {
        operator_assemble.FORMAT,
        operator_assemble.RECEIPT_FORMAT,
    }:
        raw = value.get("policy")
        if not isinstance(raw, dict) or set(raw) - (POLICY_KEYS | CONSENT | {"format"}):
            raise LifecycleError("operator draft policy contains unsupported fields")
        value = {key: raw[key] for key in POLICY_KEYS}
    body = fields(value, POLICY_KEYS)
    if (
        instant(body["start_before"]) > instant(body["issuance_before"])
        or any(
            type(body[k]) is not int or not 0 < cast(int, body[k]) <= 2**31 - 1
            for k in ("credential_lifetime_seconds", "cleanup_reserve_seconds")
        )
        or type(body["retain_after_failure"]) is not bool
    ):
        raise LifecycleError("policy proposal requires explicit valid bounds")
    return {"format": LEASE_POLICY_FORMAT, **body}


def migration_body(value: object) -> dict[str, object]:
    evidence = fields(
        value, {"format", "records", "obligations", "retained_files", "expiry_updates", "issuers"}
    )
    modern = evidence["format"] == "lowerduckpond-m3-11-migration-evidence-v2"
    if evidence["format"] not in {
        EVIDENCE_FORMAT,
        "lowerduckpond-m3-11-migration-evidence-v2",
    } or not isinstance(evidence["records"], list):
        raise LifecycleError("migration requires original collected evidence")
    records = [event_validate(row) for row in evidence["records"]]
    by_id = {str(row["event_id"]): row for row in records}
    if len(by_id) != len(records):
        raise LifecycleError("migration source repeats an original event")
    declared = evidence["obligations"]
    intents = _intents(records)
    if not isinstance(declared, dict) or set(declared) != {intent.sha256 for intent in intents}:
        raise LifecycleError("migration declarations do not cover original obligations")
    obligations = {}
    for intent in intents:
        row = fields(
            declared[intent.sha256],
            {"generation_id", "original_status"}
            | ({"cleanup_authority_sha256"} if modern else set()),
        )
        if modern and row["cleanup_authority_sha256"] != intent.cleanup_authority_sha256:
            raise LifecycleError("legacy generation declaration differs from original authority")
        obligations[intent.sha256] = {**row, "provider_id": _known_id(records, intent)}
    result = {
        "format": MIGRATION_FORMAT_V2 if modern else MIGRATION_FORMAT,
        "records": {key: digest(row) for key, row in by_id.items()},
        "obligations": obligations,
        "retained_files": evidence["retained_files"],
        "expiry_updates": evidence["expiry_updates"],
        "issuers": evidence["issuers"],
    }
    validate_claims(result, records)
    return result


def retry_basis(
    status: object, *, policy: LeasePolicy, targets: Targets, now: datetime
) -> LeaseManifest:
    if not isinstance(status, dict):
        raise LifecycleError("retry requires exported prior-attempt status")
    basis = fields(
        status.get("retry_basis"),
        {"format", "manifest", "manifest_sha256", "attempt_binding_sha256", "deadline"},
    )
    manifest = LeaseManifest.parse(basis["manifest"])
    lease = fields(
        status.get("lease"), {"lease_id", "manifest_sha256", "policy_sha256", "use_released"}
    )
    binding = fields(status.get("binding"), BINDING)
    identity(binding["managed_run_id"])
    for key in ("source_revision", "helper_revision"):
        revision(binding[key])
    for key in BINDING - {"managed_run_id", "source_revision", "helper_revision"}:
        fingerprint(binding[key])
    progress = fields(
        status.get("status"),
        {
            "format",
            "phase",
            "credential_cleanup",
            "observed_at",
            "qualification",
            "closure",
            "exit_status",
        },
    )
    instant(progress["observed_at"])
    if (
        progress["format"] != "lowerduckpond-m3-11-unattended-status-v1"
        or progress["phase"] != "finished"
        or progress["qualification"] not in {"failed", "interrupted"}
        or progress["credential_cleanup"] != "pending"
        or progress["closure"] != "unresolved"
        or type(progress["exit_status"]) is not int
        or not 0 < progress["exit_status"] <= 255  # noqa: PLR2004 - process exit byte
        or binding["storage_target_sha256"] != targets.storage_digest
    ):
        raise LifecycleError("retry requires a completed failed attempt with retained credentials")
    deadline = manifest.policy.deadline(instant(manifest.created_at))
    if (
        basis["format"] != RETRY_FORMAT
        or basis["manifest_sha256"] != manifest.sha256
        or basis["attempt_binding_sha256"] != digest(status.get("binding"))
        or instant(basis["deadline"]) != deadline
        or lease["lease_id"] != manifest.lease_id
        or lease["manifest_sha256"] != manifest.sha256
        or lease["policy_sha256"] != policy.sha256
        or manifest.policy != policy
        or manifest.targets != targets
        or lease["use_released"] is not True
        or deadline - now < MINIMUM_TOKEN_REMAINING
    ):
        raise LifecycleError("retry does not preserve the released original lease and deadline")
    return manifest


def attempt_body(
    sources: dict[str, dict[str, object]], parameters: dict[str, object], *, now: datetime
) -> dict[str, object]:
    parameters = fields(parameters, {"source", "mode", "expires_at"})
    source = revision(parameters["source"])
    mode = parameters["mode"]
    if mode not in {"rehearsal", "qualification"} or instant(parameters["expires_at"]) <= now:
        raise LifecycleError("attempt proposal mode or expiry is invalid")
    inputs = sources["inputs"]
    if (
        inputs.get("format") != operator_assemble.RECEIPT_FORMAT
        or inputs.get("runtime_revision") != source
    ):
        raise LifecycleError("attempt proposal differs from the bound runtime revision")
    policy = LeasePolicy.parse(inputs["policy"])
    if inputs.get("approved_policy_sha256") != policy.sha256:
        raise LifecycleError("attempt policy binding changed")
    targets = Targets.parse(inputs["targets"])
    prepared = approval.preparation(sources["prepared"])
    if prepared["source_revision"] != source or prepared["helper_revision"] != source:
        raise LifecycleError("attempt preparation differs from the bound source/helper")
    current_candidate(operator_assemble.ROOT, source)
    fingerprint(prepared["artifact_sha256"])
    lease_id = None
    if "reuse_status" in sources:
        retained = retry_basis(sources["reuse_status"], policy=policy, targets=targets, now=now)
        lease_id = retained.lease_id
        # Revalidate the complete original assembly inputs at their original
        # lease issuance. This is structural/history validation, not renewed
        # issuance authority: retry eligibility and approval use the real now.
        operator_assemble.validate(inputs, now=instant(retained.created_at))
    else:
        operator_assemble.validate(inputs, now=now)
    return {
        "format": approval.FORMAT,
        "prepared": prepared,
        "targets": dataclasses.asdict(targets),
        "qualification_inputs_sha256": source_fingerprint(operator_assemble.ROOT, source),
        "modes": [mode],
        "expires_at": parameters["expires_at"],
        "policy_sha256": policy.sha256,
        "lease_id": lease_id,
    }


def build(
    kind: str,
    sources: dict[str, dict[str, object]],
    parameters: dict[str, object],
    *,
    now: datetime,
) -> dict[str, object]:
    if kind == "policy":
        if set(sources) != {"inputs"} or parameters:
            raise LifecycleError("policy source index differs")
        return policy_body(sources["inputs"])
    if kind == "migration":
        if set(sources) != {"evidence_index"} or parameters:
            raise LifecycleError("migration source index differs")
        return migration_body(sources["evidence_index"])
    if kind != "attempt" or set(sources) not in (
        {"inputs", "prepared"},
        {"inputs", "prepared", "reuse_status"},
    ):
        raise LifecycleError("proposal kind or source index is unsupported")
    return attempt_body(sources, parameters, now=now)


def propose(
    kind: str, paths: dict[str, Path], *, parameters: dict[str, object], output: Path, now: datetime
) -> dict[str, object]:
    sources = {key: read(path) for key, path in paths.items()}
    value: dict[str, object] = {
        "format": FORMAT,
        "kind": kind,
        "sources": {
            key: {"path": str(path.resolve()), "sha256": digest(sources[key])}
            for key, path in paths.items()
        },
        "parameters": parameters,
        "proposed": build(kind, sources, parameters, now=now),
    }
    local(output)
    if output.exists():
        if read(output) != value:
            raise LifecycleError("proposal output conflicts with retained original")
    else:
        publish_private(output, value, maximum=MAX_OUTPUT)
    return value


def record(  # noqa: PLR0912, PLR0913 - explicit source, consent, output and time boundaries
    kind: str,
    *,
    proposal: Path,
    expected: str,
    approved_at: str,
    approval_reference: str,
    output: Path,
    now: datetime,
) -> dict[str, object]:
    proposed = fields(read(proposal), {"format", "kind", "sources", "parameters", "proposed"})
    if (
        proposed["format"] != FORMAT
        or proposed["kind"] != kind
        or digest(proposed) != fingerprint(expected)
    ):
        raise LifecycleError("approved proposal identity changed")
    if not isinstance(proposed["sources"], dict) or not isinstance(proposed["parameters"], dict):
        raise LifecycleError("proposal source index is invalid")
    sources = {}
    for key, raw in proposed["sources"].items():
        entry = strings(fields(raw, {"path", "sha256"}))
        source = read(Path(entry["path"]))
        if digest(source) != fingerprint(entry["sha256"]):
            raise LifecycleError("proposal source facts changed")
        sources[str(key)] = source
    if instant(approved_at) > now:
        raise LifecycleError("consent is future dated")
    if not 1 <= len(approval_reference) <= MAX_APPROVAL_REFERENCE or any(
        ord(c) < FIRST_PRINTABLE for c in approval_reference
    ):
        raise LifecycleError("explicit consent reference is required")
    if not isinstance(proposed["proposed"], dict):
        raise LifecycleError("proposal facts are malformed")
    result = {
        **proposed["proposed"],
        "approved_at": approved_at,
        "approval_reference": approval_reference,
    }
    local(output)
    companions: dict[str, dict[str, object]] = {
        "proposal.json": proposed,
        "sources.json": cast(dict[str, object], proposed["sources"]),
        "digest.json": {"sha256": digest(result)},
        "receipt.json": {
            "kind": kind,
            "proposal_sha256": expected,
            "record_sha256": digest(result),
            "sources_sha256": digest(proposed["sources"]),
        },
    }
    filename = FILENAMES[kind]
    if output.exists():
        private_directory(output)
        if {p.name for p in output.iterdir()} != {*companions, filename} or any(
            read(output / name) != value for name, value in {**companions, filename: result}.items()
        ):
            raise LifecycleError("record output is incomplete or conflicts with the original")
        return result
    body = build(kind, sources, proposed["parameters"], now=now)
    if body != proposed["proposed"]:
        raise LifecycleError("proposal facts changed")
    if kind == "policy":
        policy = LeasePolicy.parse(result)
        policy.require_start(now=now, approved_sha256=policy.sha256)
    elif kind == "migration":
        migration(result)
        validate_claims(result, cast(list[dict[str, object]], sources["evidence_index"]["records"]))
    else:
        approval.validate(result, mode=str(proposed["parameters"]["mode"]), now=now)
    output.mkdir(mode=0o700)
    for name, value in companions.items():
        write_private(output / name, value, maximum=MAX_OUTPUT)
    publish_private(output / filename, result, maximum=MAX_OUTPUT)
    return result


def bind_inputs(  # noqa: PLR0913 - explicit draft, approvals, revision, output and clock
    *, draft: Path, policy: Path, imported: Path, runtime: str, output: Path, now: datetime
) -> dict[str, object]:
    value = read(draft)
    approved = LeasePolicy.parse(read(policy))
    mapping = migration(read(imported))
    bindings = {
        "format": operator_assemble.RECEIPT_FORMAT,
        "policy": approved.document(),
        "approved_policy_sha256": approved.sha256,
        "migration_sha256": digest(mapping),
        "runtime_revision": revision(runtime),
    }
    for key, wanted in bindings.items():
        if value.get(key) is not None and value[key] != wanted:
            raise LifecycleError("draft contains a contradictory approved binding")
    value.update(bindings)
    operator_assemble.validate(value, now=now)
    local(output)
    if output.exists():
        if read(output) != value:
            raise LifecycleError("bound inputs cannot replace the original")
    else:
        publish_private(output, value)
    return value


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for kind in FILENAMES:
        p = sub.add_parser(kind + "-proposal")
        p.add_argument("--output", type=Path, required=True)
        p.add_argument(
            "--evidence-index" if kind == "migration" else "--inputs", type=Path, required=True
        )
        if kind == "attempt":
            p.add_argument("--prepared", type=Path, required=True)
            p.add_argument("--source", required=True)
            p.add_argument("--mode", required=True)
            p.add_argument("--expires-at", required=True)
            p.add_argument("--reuse-status", type=Path)
        r = sub.add_parser("record-" + kind)
        for name in ("proposal", "output"):
            r.add_argument("--" + name, type=Path, required=True)
        for name in ("expected-proposal-sha256", "approved-at", "approval-reference"):
            r.add_argument("--" + name, required=True)
    b = sub.add_parser("bind-inputs")
    for name in ("draft", "policy", "migration", "output"):
        b.add_argument("--" + name, type=Path, required=True)
    b.add_argument("--runtime-revision", required=True)
    args = parser.parse_args()
    try:
        now = datetime.now(UTC)
        if args.operation == "bind-inputs":
            result = bind_inputs(
                draft=args.draft,
                policy=args.policy,
                imported=args.migration,
                runtime=args.runtime_revision,
                output=args.output,
                now=now,
            )
        elif args.operation.startswith("record-"):
            result = record(
                args.operation.removeprefix("record-"),
                proposal=args.proposal,
                expected=args.expected_proposal_sha256,
                approved_at=args.approved_at,
                approval_reference=args.approval_reference,
                output=args.output,
                now=now,
            )
        else:
            kind = args.operation.removesuffix("-proposal")
            paths = (
                {"evidence_index": args.evidence_index}
                if kind == "migration"
                else {"inputs": args.inputs}
            )
            parameters = {}
            if kind == "attempt":
                paths["prepared"] = args.prepared
                if args.reuse_status is not None:
                    paths["reuse_status"] = args.reuse_status
                parameters = {
                    "source": args.source,
                    "mode": args.mode,
                    "expires_at": args.expires_at,
                }
            result = propose(kind, paths, parameters=parameters, output=args.output, now=now)
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Operator record incomplete; preserve original proposals and evidence.\n")
    print(str(args.output) + " " + digest(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
