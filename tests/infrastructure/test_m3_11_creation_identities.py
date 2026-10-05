"""Incomplete native creation responses remain owned across cleanup restarts."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_unattended.cloudflare import Cloudflare
from scripts.m3_11_unattended.http import Api, Response
from scripts.m3_11_unattended.lifecycle import Lifecycle, intents, known_id
from scripts.m3_11_unattended.model import Credential, Intent, LifecycleError, ProviderKind, stamp
from scripts.m3_11_unattended.spaces import Spaces

from .test_m3_11_unattended_lifecycle import CANARY, NOW, SCOPE, TARGETS, Case


class CreationApi:
    """Provider inventory and mutations, with faults in the one create response."""

    credential_sha256 = "d" * 64
    selected = "credential00000001"

    def __init__(self, kind: ProviderKind, *, response_fault: str, wrong_scope: bool) -> None:
        self.kind, self.response_fault, self.wrong_scope = kind, response_fault, wrong_scope
        self.creates = 0
        self.deletes: list[str] = []
        self.item: dict[str, object] | None = None
        self.response_id: object = self.selected

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        spaces = self.kind == "spaces"
        if method == "POST":
            assert body is not None
            self.creates += 1
            self.item = {
                **copy.deepcopy(body),
                "access_key" if spaces else "id": self.selected,
                "created_at" if spaces else "issued_on": stamp(NOW),
                "status": "active",
            }
            if self.wrong_scope:
                self.item["grants" if spaces else "policies"] = (
                    [{"bucket": "", "permission": "fullaccess"}] if spaces else []
                )
            elif not spaces:
                self.item["policies"] = [
                    {
                        "effect": "allow",
                        "resources": TARGETS.zone_resources,
                        "permission_groups": [{"id": "e" * 32, "name": "Page Rules Read"}],
                    }
                ]
            returned = {**self.item, "access_key" if spaces else "id": self.response_id}
            if self.response_fault != "missing":
                returned["secret_key" if spaces else "value"] = {
                    "empty": "",
                    "non-string": [CANARY],
                    "valid": CANARY,
                }[self.response_fault]
            return Response(201, {"key": returned}) if spaces else self.envelope(returned)
        if method == "DELETE":
            self.deletes.append(path.rsplit("/", 1)[1])
            self.item = None
            return Response(204, {}) if spaces else self.envelope({"id": self.selected})
        assert method == "GET"
        if "?" not in path:
            return Response(404, {}) if self.item is None else self.envelope(self.item)
        items = [] if self.item is None else [self.item]
        return (
            Response(200, {"keys": items, "meta": {"total": len(items)}})
            if spaces
            else Response(
                200,
                {
                    "success": True,
                    "result": items,
                    "result_info": {
                        "page": 1,
                        "count": len(items),
                        "total_pages": 1,
                        "total_count": len(items),
                    },
                },
            )
        )

    @staticmethod
    def envelope(value: object) -> Response:
        return Response(200, {"success": True, "result": value})

    def provider(self) -> Spaces | Cloudflare:
        return (
            Spaces(cast(Api, self))
            if self.kind == "spaces"
            else Cloudflare(
                cast(Api, self),
                account=TARGETS.account_id if self.kind == "cloudflare-account" else None,
            )
        )


def provision(case: Case, api: CreationApi) -> tuple[Intent, Credential]:
    case.lifecycle.providers = {api.kind: api.provider()}
    return case.lifecycle.provision(
        run_id=case.run_id,
        role="archive" if api.kind == "spaces" else "page-rules",
        source="e" * 40,
        helper="f" * 40,
        targets=TARGETS,
        provider=api.kind,
        scope=SCOPE
        if api.kind == "spaces"
        else {"permissions": {"e" * 32: "Page Rules Read"}, "resources": TARGETS.zone_resources},
        authority=case.authority,
    )


@pytest.mark.parametrize("kind", ["spaces", "cloudflare-account", "cloudflare-user"])
@pytest.mark.parametrize("secret", ["missing", "empty", "non-string"])
@pytest.mark.parametrize("wrong_scope", [False, True])
def test_incomplete_creation_retains_exact_identity_for_independent_cleanup(
    tmp_path: Path, kind: ProviderKind, secret: str, wrong_scope: bool
) -> None:
    case = Case(tmp_path)
    api = CreationApi(kind, response_fault=secret, wrong_scope=wrong_scope)
    with pytest.raises(LifecycleError, match="omitted its secret") as error:
        provision(case, api)
    intent = intents(case.journal)[0]
    assert known_id(case.journal, intent) == api.selected
    assert not any(row["kind"] == "cleanup" for row in case.journal.records())
    # A fresh, secretless actor must use the recorded ID and fresh provider reads.
    independent = Lifecycle(case.journal, {kind: api.provider()}, clock=lambda: NOW)
    independent.request_revocation(case.run_id)
    for _ in range(3):
        result = independent.reconcile(intent)
        assert result.status == "verified"
        assert result.negative_authentication == "unavailable"
    with pytest.raises(LifecycleError, match="cannot be replayed"):
        provision(case, api)
    assert api.creates == 1 and api.deletes == [api.selected]
    assert CANARY not in str(error.value)
    assert CANARY not in repr(case.journal.records())


@pytest.mark.parametrize("kind", ["spaces", "cloudflare-account", "cloudflare-user"])
@pytest.mark.parametrize("invalid", [None, "short", "bad/identity", [CANARY]])
def test_invalid_returned_identity_is_not_adopted_or_reissued(
    tmp_path: Path, kind: ProviderKind, invalid: object
) -> None:
    case = Case(tmp_path)
    api = CreationApi(kind, response_fault="missing", wrong_scope=True)
    api.response_id = invalid
    with pytest.raises(LifecycleError, match="invalid credential identity"):
        provision(case, api)
    intent = intents(case.journal)[0]
    assert known_id(case.journal, intent) is None
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.reconcile(intent).status == "unresolved"
    assert api.deletes == [] and api.creates == 1
    with pytest.raises(LifecycleError, match="cannot be replayed"):
        provision(case, api)


@pytest.mark.parametrize("kind", ["spaces", "cloudflare-account", "cloudflare-user"])
def test_returned_baseline_identity_never_authorizes_deletion(
    tmp_path: Path, kind: ProviderKind
) -> None:
    case = Case(tmp_path)
    api = CreationApi(kind, response_fault="missing", wrong_scope=True)
    api.item = {
        "access_key" if kind == "spaces" else "id": api.selected,
        "name": "existing-production-credential",
        "created_at" if kind == "spaces" else "issued_on": stamp(NOW),
    }
    with pytest.raises(LifecycleError, match="omitted its secret"):
        provision(case, api)
    intent = intents(case.journal)[0]
    assert api.selected in intent.baseline_ids
    assert known_id(case.journal, intent) == api.selected
    case.lifecycle.request_revocation(case.run_id)
    for _ in range(3):
        assert case.lifecycle.reconcile(intent).status == "unresolved"
    assert api.deletes == []
