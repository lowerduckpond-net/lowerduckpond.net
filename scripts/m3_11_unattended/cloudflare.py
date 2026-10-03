"""Exact account/user token policy, ownership, activity and native expiry checks."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from http import HTTPStatus
from urllib.parse import urlencode

from scripts.check_m3_7_production_edge import validate_account_token_policy
from scripts.m3_11_unattended.http import Api, collection
from scripts.m3_11_unattended.lifecycle import identifier
from scripts.m3_11_unattended.model import (
    Credential,
    Intent,
    LifecycleError,
    ProviderKind,
    Targets,
    instant,
    strings,
)
from scripts.qualification_budget import MINIMUM_TOKEN_REMAINING

ORIGIN = "https://api.cloudflare.com/client/v4"
PAGE_SIZE = 50
MAX_PAGES = 100
PERMISSIONS = {
    "caddy": frozenset({"Zone Read", "DNS Write"}),
    "observer": frozenset({"Zone Read", "DNS Read"}),
    "audit": frozenset({"Account API Tokens Read"}),
    "page-rules": frozenset({"Page Rules Read"}),
}


def result(response_status: int, body: dict[str, object]) -> object:
    if response_status != HTTPStatus.OK or body.get("success") is not True or "result" not in body:
        raise LifecycleError("Cloudflare request was not authenticated and acknowledged")
    return body["result"]


def policy_scope(item: dict[str, object]) -> dict[str, object]:  # noqa: PLR0911 - fail closed by field
    """Normalize complete allow policies, including each permission's resources."""
    policies = item.get("policies")
    if not isinstance(policies, list) or not policies or item.get("condition") not in (None, {}):
        return {"unrecognized": True}
    permissions: dict[str, str] = {}
    resources: dict[str, str] = {}
    for policy in policies:
        if not isinstance(policy, dict):
            return {"unrecognized": True}
        groups, bindings = policy.get("permission_groups"), policy.get("resources")
        if not isinstance(groups, list) or not isinstance(bindings, dict):
            return {"unrecognized": True}
        for group in groups:
            if (
                not isinstance(group, dict)
                or not isinstance(group.get("id"), str)
                or not isinstance(group.get("name"), str)
            ):
                return {"unrecognized": True}
            permissions[group["id"]] = group["name"]
        try:
            resources.update(strings(bindings))
        except LifecycleError:
            return {"unrecognized": True}
    try:
        validate_account_token_policy(
            {**item, "status": "active"},
            expected_id=identifier(item.get("id")),
            expected_permissions=permissions,
            expected_resources=frozenset(resources),
            label="managed fixture",
        )
    except RuntimeError, ValueError:
        return {"unrecognized": True}
    return {"permissions": permissions, "resources": resources}


class Cloudflare:
    def __init__(self, api: Api, *, account: str | None) -> None:
        if account is not None and re.fullmatch(r"[0-9a-f]{32}", account) is None:
            raise LifecycleError("invalid Cloudflare account identity")
        self.api = api
        self.kind: ProviderKind = "cloudflare-user" if account is None else "cloudflare-account"
        self.path = "/user/tokens" if account is None else f"/accounts/{account}/tokens"

    def _get(self, path: str) -> object:
        response = self.api.request("GET", path)
        return result(response.status, response.body)

    @staticmethod
    def _metadata(item: dict[str, object]) -> dict[str, object]:
        return {
            "id": identifier(item.get("id")),
            "name": item.get("name"),
            "created_at": item.get("issued_on"),
            "scope": policy_scope(item),
            "status": item.get("status"),
            "expires_at": item.get("expires_on"),
        }

    def inventory(self) -> list[dict[str, object]]:
        values: list[dict[str, object]] = []
        expected: tuple[int, int] | None = None
        for page in range(1, MAX_PAGES + 1):
            response = self.api.request("GET", f"{self.path}?page={page}&per_page={PAGE_SIZE}")
            items = collection(result(response.status, response.body))
            info = response.body.get("result_info")
            if not isinstance(info, dict):
                raise LifecycleError("Cloudflare inventory pagination is missing")
            pages, total = info.get("total_pages"), info.get("total_count")
            if (
                type(pages) is not int
                or type(total) is not int
                or not 0 <= pages <= MAX_PAGES
                or not 0 <= total <= PAGE_SIZE * MAX_PAGES
                or info.get("page") != page
                or info.get("count") != len(items)
                or len(items) > PAGE_SIZE
                or (total and not pages)
                or (expected is not None and expected != (pages, total))
            ):
                raise LifecycleError("Cloudflare inventory pagination is invalid or changed")
            expected = pages, total
            values.extend(self._metadata(item) for item in items)
            if page >= pages:
                if len(values) != total or len({item["id"] for item in values}) != total:
                    raise LifecycleError("Cloudflare inventory is incomplete or ambiguous")
                return values
        raise LifecycleError("Cloudflare inventory exceeds its page bound")

    def inspect(self, selected: str) -> dict[str, object] | None:
        response = self.api.request("GET", f"{self.path}/{identifier(selected)}")
        if response.status == HTTPStatus.NOT_FOUND:
            return None
        item = result(response.status, response.body)
        if not isinstance(item, dict) or item.get("id") != selected:
            raise LifecycleError("Cloudflare credential identity changed")
        return self._metadata(item)

    def scope(self, role: str, targets: Targets) -> dict[str, object]:
        names = PERMISSIONS[role]
        expected_scope = (
            "com.cloudflare.api.account" if role == "audit" else "com.cloudflare.api.account.zone"
        )
        permissions: dict[str, str] = {}
        # User permission_groups is not paginated; account groups support a
        # name filter. Match both the exact name and the resource scope.
        for name in sorted(names):
            query = "?" + urlencode({"name": name}) if self.kind == "cloudflare-account" else ""
            groups = collection(self._get(self.path + "/permission_groups" + query))
            selected = [
                group
                for group in groups
                if group.get("name") == name
                and isinstance(scopes := group.get("scopes"), list)
                and expected_scope in scopes
            ]
            if len(selected) != 1:
                raise LifecycleError("Cloudflare permission identity is missing or ambiguous")
            permissions[identifier(selected[0].get("id"))] = name
        resources = (
            {f"com.cloudflare.api.account.{targets.account_id}": "*"}
            if role == "audit"
            else targets.zone_resources
        )
        return {"permissions": permissions, "resources": resources}

    def create(self, intent: Intent) -> Credential:
        permissions = strings(intent.scope.get("permissions"))
        body: dict[str, object] = {
            "name": intent.name,
            "expires_on": intent.deadline,
            "not_before": intent.requested_at,
            "policies": [
                {
                    "effect": "allow",
                    "permission_groups": [{"id": key} for key in sorted(permissions)],
                    "resources": intent.scope["resources"],
                }
            ],
        }
        response = self.api.request("POST", self.path, body)
        item = result(response.status, response.body)
        if not isinstance(item, dict):
            raise LifecycleError("Cloudflare creation response was not acknowledged")
        selected, secret = identifier(item.get("id")), item.get("value")
        if not isinstance(secret, str) or not secret:
            raise LifecycleError("Cloudflare creation omitted its secret; reconcile its intent")
        return Credential(selected, secret, self._metadata(item))

    def delete(self, selected: str) -> None:
        response = self.api.request("DELETE", f"{self.path}/{identifier(selected)}")
        if response.status == HTTPStatus.NOT_FOUND:
            return
        item = result(response.status, response.body)
        if not isinstance(item, dict) or item.get("id") != selected:
            raise LifecycleError("Cloudflare deletion identity was not acknowledged")

    def verify(self, intent: Intent, credential: Credential, *, now: datetime) -> None:
        metadata = self.inspect(credential.identifier)
        if metadata is None or metadata["scope"] != intent.scope or metadata["status"] != "active":
            raise LifecycleError("Cloudflare credential policy or active status differs")
        expiry = instant(metadata.get("expires_at"))
        maximum = (
            timedelta(days=8 if intent.role == "audit" else 91)
            if intent.role in {"audit", "page-rules"}
            else timedelta(hours=14)
        )
        if (
            expiry != instant(intent.deadline)
            or not MINIMUM_TOKEN_REMAINING <= expiry - now <= maximum
        ):
            raise LifecycleError("Cloudflare fixture credential lifetime differs from approval")
        response = Api(ORIGIN, credential.secret).request("GET", self.path + "/verify")
        verified = result(response.status, response.body)
        if (
            not isinstance(verified, dict)
            or verified.get("id") != credential.identifier
            or verified.get("status") != "active"
        ):
            raise LifecycleError("Cloudflare fixture credential ownership did not verify")
        if verified.get("not_before") and instant(verified["not_before"]) > now:
            raise LifecycleError("Cloudflare fixture credential is not valid yet")

    def denied(self, intent: Intent, credential: Credential) -> bool:
        try:
            response = Api(ORIGIN, credential.secret).request("GET", self.path + "/verify")
            if response.status in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}:
                return True
            item = result(response.status, response.body)
            return (
                isinstance(item, dict)
                and item.get("id") == credential.identifier
                and item.get("status") in {"disabled", "expired"}
            )
        except LifecycleError, OSError:
            return False
