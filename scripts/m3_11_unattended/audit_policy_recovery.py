"""Restore one explicitly approved diagnostic addition to a known bootstrap.

This is recovery for the October 6 uncertain Page Rules intent, not a generic
policy editor. The immutable candidate was read without changing the provider.
No caller may substitute another credential, policy, expiry, or account.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from copy import deepcopy
from datetime import UTC, datetime, timedelta

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.cloudflare import Cloudflare, result
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.journal import Journal, event, validate
from scripts.m3_11_unattended.model import Intent, LifecycleError, digest, instant, stamp
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-audit-policy-restoration-v1"
PROOF_FORMAT = "lowerduckpond-m3-11-audit-policy-observation-v1"
CANDIDATE_SHA256 = "ae2a4f830b44d5d7e350943b2b4a668773fed52de151a92c9366279674629f0d"
INTENT_SHA256 = "ccdc7926243530cf6dd6615745f8520440d29531f28869a226f432b31a64b574"
RUN_ID = "01a11021-76d1-775a-adb1-fe00b6fd6152"
GRANT_WINDOW = timedelta(minutes=10)
RESTORE_WINDOW = timedelta(minutes=15)
WRITABLE = {"name", "policies", "condition", "expires_on", "not_before", "status"}
NATIVE = WRITABLE | {"id", "issued_on", "modified_on", "last_used_on"}


def candidate(value: object) -> dict[str, object]:
    selected = fields(
        value,
        {
            "account_id",
            "authorized",
            "before",
            "candidate_after",
            "credential_id",
            "credential_sha256",
            "observed_at",
            "provider",
            "scope",
        },
    )
    if digest(selected) != CANDIDATE_SHA256 or selected["authorized"] is not False:
        raise LifecycleError("audit policy candidate differs from the inspected identity")
    return selected


def plan(record: dict[str, object]) -> dict[str, object]:
    validate(record)
    value = fields(
        record["payload"],
        {
            "format",
            "candidate",
            "helper_revision",
            "intent_sha256",
            "grant_before",
            "restore_after",
        },
    )
    candidate(value["candidate"])
    start = instant(record["recorded_at"])
    if (
        record["kind"] != "heartbeat"
        or value["format"] != FORMAT
        or value["intent_sha256"] != INTENT_SHA256
        or instant(value["grant_before"]) - start != GRANT_WINDOW
        or instant(value["restore_after"]) - start != RESTORE_WINDOW
    ):
        raise LifecycleError("audit restoration obligation has an invalid binding or window")
    revision(value["helper_revision"])
    return value


def plans(records: list[dict[str, object]]) -> list[dict[str, object]]:
    selected = [
        record
        for record in records
        if isinstance(record["payload"], dict) and record["payload"].get("format") == FORMAT
    ]
    for record in selected:
        plan(record)
    # Multiple publications never renew access or prevent restoration. Grant
    # admission rejects them; cleanup immediately reduces the pinned policy.
    return selected


def admission_clear(
    records: list[dict[str, object]],
    *,
    now: datetime,
    independent: Callable[[dict[str, object]], bool],
) -> bool:
    selected = plans(records)
    if not selected:
        return True
    if len(selected) != 1:
        return False
    record = selected[0]
    due = instant(plan(record)["restore_after"])
    if now < due:
        return False
    proofs = [
        row
        for row in records
        if row["kind"] == "heartbeat"
        and isinstance(row["payload"], dict)
        and row["payload"].get("format") == PROOF_FORMAT
        and row["payload"].get("plan_sha256") == digest(record)
        and row["payload"].get("cleanup_actor") == "github"
        and independent(row)
    ]
    if not proofs:
        return False
    latest = max(proofs, key=lambda row: instant(row["recorded_at"]))
    value = latest["payload"]
    return (
        isinstance(value, dict)
        and value.get("status") == "original-policy-verified"
        and due <= instant(value.get("observed_at")) <= now
    )


def body(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not {"name", "policies", "status"} <= value.keys():
        raise LifecycleError("audit policy metadata is incomplete")
    if value.keys() - NATIVE:
        raise LifecycleError("audit policy metadata has unrecognized top-level fields")
    selected = {key: deepcopy(item) for key, item in value.items() if key in WRITABLE}
    # Native responses add policy IDs/group names and can change array order.
    # Normalize only those informational fields; preserve every policy boundary.
    policies = selected["policies"]
    if not isinstance(policies, list) or not policies:
        raise LifecycleError("audit policy metadata is incomplete")
    normalized = []
    for item in policies:
        if not isinstance(item, dict) or set(item) - {
            "id",
            "effect",
            "resources",
            "permission_groups",
        }:
            raise LifecycleError("audit policy metadata has unrecognized restrictions")
        groups = item.get("permission_groups")
        if (
            not isinstance(groups, list)
            or not groups
            or any(
                not isinstance(group, dict)
                or set(group) - {"id", "name"}
                or not isinstance(group.get("id"), str)
                for group in groups
            )
        ):
            raise LifecycleError("audit permission metadata is incomplete")
        normalized.append(
            {
                "effect": item.get("effect"),
                "resources": item.get("resources"),
                "permission_groups": sorted(
                    ({"id": group["id"]} for group in groups), key=lambda group: group["id"]
                ),
            }
        )
    selected["policies"] = sorted(normalized, key=digest)
    # APIs may return omitted optional fields as null/empty. They mean no bound.
    for key in ("condition", "not_before"):
        if selected.get(key) in (None, {}):
            selected.pop(key, None)
    return selected


def inspect(api: Api, approved: dict[str, object]) -> dict[str, object]:
    path = f"/accounts/{approved['account_id']}/tokens/{approved['credential_id']}"
    response = api.request("GET", path)
    item = result(response.status, response.body)
    if not isinstance(item, dict) or item.get("id") != approved["credential_id"]:
        raise LifecycleError("audit policy readback identity is unproven")
    return body(item)


def update(api: Api, approved: dict[str, object], *, restore: bool) -> None:
    # Dedicated transport entry point permits only the pinned account/token and
    # the two reviewed bodies. Generic provider request() still refuses PUT.
    api.audit_policy_update(
        candidate=approved, body=body(approved["before" if restore else "candidate_after"])
    )


def restore(api: Api, approved: dict[str, object]) -> str:
    candidate(approved)
    original, expanded = body(approved["before"]), body(approved["candidate_after"])
    observed = inspect(api, approved)
    if observed == original:
        return "original-policy-verified"
    if observed != expanded:
        raise LifecycleError("audit policy changed independently; automatic overwrite refused")
    # A lost response is reconciled by fresh GET, never a successful PUT alone.
    with suppress(LifecycleError):
        update(api, approved, restore=True)
    if inspect(api, approved) != original:
        raise LifecycleError("audit policy restoration remains unresolved")
    return "original-policy-verified"


def reconcile(
    journal: Journal,
    provider: object,
    *,
    now: datetime,
    arm_restore: Callable[[datetime], None] | None = None,
    force_restore: bool = False,
) -> str:
    """Recheck forever after the deadline, even after a previous successful restore.

    An interrupted or delayed grant must not outlive a one-time 'resolved' bit.
    No matching obligation means zero additional provider calls. A pending or
    failed restoration blocks independent readiness while child cleanup proceeds.
    """
    selected = plans(journal.records())
    if not selected:
        return "no-obligation"
    value = plan(selected[0])
    approved = candidate(value["candidate"])
    client = restoration_authority(journal, provider, approved)
    if not force_restore and len(selected) == 1 and now < instant(value["restore_after"]):
        if arm_restore is not None:
            arm_restore(instant(value["restore_after"]))
        if inspect(client.api, approved) not in (
            body(approved["before"]),
            body(approved["candidate_after"]),
        ):
            raise LifecycleError("audit policy changed independently; restoration is unresolved")
        return "policy-metadata-verified"
    return restore(client.api, approved)


def restoration_authority(
    journal: Journal, provider: object, approved: dict[str, object]
) -> Cloudflare:
    if not isinstance(provider, Cloudflare) or provider.kind != "cloudflare-account":
        raise LifecycleError("audit restoration authority is unavailable")
    if provider.path != f"/accounts/{approved['account_id']}/tokens":
        raise LifecycleError("audit restoration account differs")
    bound = [
        Intent.parse(record["payload"])
        for record in journal.records()
        if record["kind"] == "intent"
        and record["run_id"] == RUN_ID
        and isinstance(record["payload"], dict)
        and record["payload"].get("role") == "audit"
    ]
    if (
        len(bound) != 1
        or bound[0].provider != "cloudflare-account"
        or provider.authority_sha256 != bound[0].cleanup_authority_sha256
        or provider.authority_sha256 == approved["credential_sha256"]
    ):
        raise LifecycleError(
            "audit restoration is not using the original separate cleanup authority"
        )
    return provider


def observation(journal: Journal, *, status: str, actor: str, helper: str, now: datetime) -> None:
    selected = plans(journal.records())
    if not selected:
        return
    if status not in {
        "original-policy-verified",
        "policy-metadata-verified",
        "restoration-unresolved",
    }:
        raise LifecycleError("unknown audit restoration status")
    payload: dict[str, object] = {
        "format": PROOF_FORMAT,
        "plan_sha256": digest(selected[0]),
        "status": status,
        "cleanup_actor": actor,
        "observed_at": stamp(now),
        "helper_revision": revision(helper),
    }
    if len(selected) != 1:
        payload["status"] = "restoration-unresolved"
    previous = [
        row["payload"]
        for row in journal.records()
        if isinstance(row["payload"], dict)
        and row["payload"].get("format") == PROOF_FORMAT
        and row["payload"].get("cleanup_actor") == actor
        and row["payload"].get("plan_sha256") == digest(selected[0])
    ]
    latest = max(previous, key=lambda row: str(row.get("observed_at"))) if previous else None
    if latest is None or latest.get("status") != status or actor == "github":
        journal.append(event("heartbeat", str(selected[0]["run_id"]), payload))


def grant(
    api: Api,
    record: dict[str, object],
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    value = plan(record)
    approved = candidate(value["candidate"])
    if not instant(record["recorded_at"]) <= clock() < instant(value["grant_before"]):
        raise LifecycleError("audit access grant window elapsed")
    if api.credential_sha256 != approved["credential_sha256"]:
        raise LifecycleError("audit access bootstrap fingerprint differs")
    response = api.request("GET", f"/accounts/{approved['account_id']}/tokens/verify")
    verified = result(response.status, response.body)
    if (
        not isinstance(verified, dict)
        or verified.get("id") != approved["credential_id"]
        or verified.get("status") != "active"
    ):
        raise LifecycleError("audit access bootstrap identity is unproven")
    if inspect(api, approved) != body(approved["before"]):
        raise LifecycleError("audit access prestate changed; grant refused")
    if not instant(record["recorded_at"]) <= clock() < instant(value["grant_before"]):
        raise LifecycleError("audit access grant window elapsed before provider invocation")
    update(api, approved, restore=False)
    if inspect(api, approved) != body(approved["candidate_after"]):
        raise LifecycleError("audit access grant was not verified")
