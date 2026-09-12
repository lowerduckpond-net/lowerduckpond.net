from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from conftest import FIXTURE_ROOT
from lowerduckpond_static_contracts import ContractError, validate_contract


@pytest.mark.parametrize(
    "field,value",
    [
        ("reason", " "),
        ("reason", "different"),
        ("operatorPrincipal", "ldp-provisioner"),
        ("correlationId", "0198d17f-6f4a-7000-8000-000000000099"),
        ("sourceRuntimeGenerationId", "0198d17f-6f4a-7000-8000-000000000005"),
        ("jobId", "0198d17f-6f4a-7000-8000-000000000099"),
    ],
)
def test_emergency_authority_rejects_inconsistent_binding(field: str, value: object) -> None:
    document = json.loads(
        Path(FIXTURE_ROOT, "accepted/emergency-deletion-intent.json").read_bytes()
    )
    document[field] = value
    with pytest.raises(ContractError):
        validate_contract(document)


@pytest.mark.parametrize("field", ["auditEntry", "result"])
def test_emergency_authority_rejects_embedded_ordinary_provenance(field: str) -> None:
    document = json.loads(
        Path(FIXTURE_ROOT, "accepted/emergency-deletion-intent.json").read_bytes()
    )
    nested = cast(dict[str, object], document[field])
    nested["provenance"] = {
        "kind": "authorization-job",
        "jobId": "0198d17f-6f4a-7000-8000-000000000099",
    }
    with pytest.raises(ContractError):
        validate_contract(document)
