"""Read a fenced source's replay inputs without executing or repairing any job."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository


def collect() -> dict[str, object]:
    # This module is sent to the original source and loaded through its artifact.
    root = Path("/var/lib/lowerduckpond/static")
    with (
        StateRepository(root, expected_owner=0) as repository,
        repository.publication_transaction() as transaction,
    ):
        inventory = transaction.measure_authorization_records()
        tenants = list(transaction.measure_inventory().tenant_ids)
        pending, exports, creates = [], [], []
        for identity in inventory.job_ids:
            job = transaction.read(StateRecordPath.authorization_job(identity)).document
            request = cast("dict[str, object]", job["request"])
            if (
                request["operation"] == "deploy"
                and job["phase"] == "pending"
                and (root / "intake" / (str(request["correlationId"]) + ".artifact")).is_file()
            ):
                pending.append((identity, request["correlationId"]))
            if identity not in inventory.result_ids:
                continue
            result = transaction.read(StateRecordPath.authorization_result(identity)).document
            if result["status"] != "succeeded":
                continue
            if (
                request["operation"] == "export"
                and (root / "exports" / (identity + ".zip")).exists()
            ):
                exports.append(identity)
            if request["operation"] == "create" and result.get("tenantId") in tenants:
                creates.append({"request": request, "result": result})
        if len(pending) != 1 or len(exports) != 1 or not creates:
            raise ValueError("retained source replay history is ambiguous")
        return {
            "tenants": tenants,
            "replay": {
                **creates[-1],
                "missingJob": pending[0][0],
                "missingCorrelation": pending[0][1],
                "exportJob": exports[0],
            },
        }


if __name__ == "__main__":
    print(json.dumps(collect()))
