"""Synthetic provider HTTP and S3 replies; real policy and lifecycle checks remain active."""

from __future__ import annotations

import hashlib
import io
import json
import urllib.request
from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from urllib.parse import parse_qs, urlsplit

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from scripts.m3_11_unattended import spaces
from scripts.m3_11_unattended.model import Targets, stamp

from .cloudflare_transport_support import mock_urlopen
from .operator_flow_support import Services
from .test_m3_11_lease_configuration import mapping


class Cloud:
    def __init__(self, services: Services, monkeypatch: pytest.MonkeyPatch) -> None:
        self.services = services
        self.targets = Targets.parse(services.manifest["targets"])
        self.keys: dict[str, dict[str, object]] = {}
        self.objects: dict[tuple[str, str], tuple[str, bytes]] = {}
        self.tokens: dict[str, dict[str, object]] = {}
        self.secret_ids: dict[str, str] = {}
        self.calls: list[dict[str, object]] = []
        self.creates: list[str] = []
        names = (
            "API Tokens Write",
            "Account API Tokens Write",
            "Account API Tokens Read",
            "DNS Write",
            "DNS Read",
            "Zone Read",
            "Page Rules Read",
        )
        # Deterministic synthetic IDs retain the provider's 32-hex-character shape.
        self.groups = [
            {
                "id": hashlib.sha256(name.encode()).hexdigest()[:32],
                "name": name,
                "scopes": [
                    "com.cloudflare.api.user"
                    if name == "API Tokens Write"
                    else "com.cloudflare.api.account"
                    if name.startswith("Account")
                    else "com.cloudflare.api.account.zone"
                ],
            }
            for name in names
        ]
        for raw in mapping(services.manifest["providers"]).values():
            refs = mapping(mapping(raw)["references"])
            for role in ("cloudflare_account", "cloudflare_user"):
                secret = services.operator.secrets[str(refs[role])]
                _, _, vault, item, field = str(refs[role]).split("/")
                cast(list[dict[str, object]], services.items[vault, item]["fields"]).append(
                    {"id": field, "label": field, "type": "CONCEALED", "value": secret}
                )
                selected = hashlib.sha256(secret.encode()).hexdigest()[:32]
                self.secret_ids[secret] = selected
                user = role.endswith("user")
                group = next(
                    row
                    for row in self.groups
                    if row["name"] == ("API Tokens Write" if user else "Account API Tokens Write")
                )
                self.tokens[selected] = {
                    "id": selected,
                    "name": "SYNTHETIC-AUTHORITY",
                    "status": "active",
                    "issued_on": services.manifest["introduced_at"],
                    "expires_on": mapping(mapping(raw)["expires_at"])[
                        "cloudflare-user" if user else "cloudflare-account"
                    ],
                    "policies": [
                        {
                            "effect": "allow",
                            "permission_groups": [{"id": group["id"], "name": group["name"]}],
                            "resources": {
                                (
                                    "com.cloudflare.api.user." + self.targets.user_id
                                    if user
                                    else "com.cloudflare.api.account." + self.targets.account_id
                                ): "*"
                            },
                        }
                    ],
                }
        services.http_handler = self.exchange
        monkeypatch.setattr(spaces, "create_client", self.s3)
        monkeypatch.setattr("scripts.m3_11_backup_fixture.create_client", self.s3)
        self.production_secret = "SYNTHETIC-PRODUCTION-CADDY-SECRET-ONLY"  # noqa: S105 - synthetic test value only
        selected = hashlib.sha256(self.production_secret.encode()).hexdigest()[:32]
        self.secret_ids[self.production_secret] = selected
        self.tokens[selected] = {
            "id": selected,
            "name": "SYNTHETIC-PRODUCTION-CADDY",
            "status": "active",
            "issued_on": services.manifest["introduced_at"],
            "expires_on": None,
            "policies": [
                {
                    "effect": "allow",
                    "permission_groups": [
                        {"id": group["id"], "name": group["name"]}
                        for group in self.groups
                        if group["name"] in {"DNS Write", "Zone Read"}
                    ],
                    "resources": self.targets.zone_resources,
                }
            ],
        }
        for name, reference in mapping(services.manifest["production_references"]).items():
            _, _, vault, item, field = str(reference).split("/")
            row = services.items.setdefault(
                (vault, item),
                {
                    "id": item,
                    "version": 1,
                    "title": "Synthetic production",
                    "vault": {"id": vault},
                    "category": "PASSWORD",
                    "fields": [],
                },
            )
            cast(list[dict[str, object]], row["fields"]).append(
                {
                    "id": field,
                    "label": field,
                    "type": "CONCEALED",
                    "value": self.production_secret
                    if name == "CADDY_CLOUDFLARE_API_TOKEN"
                    else "SYNTHETIC-PRODUCTION-" + name,
                }
            )
        cloud = self

        class Response(io.BytesIO):
            status = 200

        def urlopen(request: urllib.request.Request, **_kwargs: object) -> Response:
            parsed = urlsplit(request.full_url)
            assert parsed.netloc == "api.cloudflare.com"
            result = cloud.exchange(
                {
                    "origin": "https://api.cloudflare.com/client/v4",
                    "path": parsed.path.removeprefix("/client/v4")
                    + ("?" + parsed.query if parsed.query else ""),
                    "token": str(request.get_header("Authorization")).removeprefix("Bearer "),
                    "method": "GET",
                    "body": None,
                }
            )
            assert result["status"] == 200  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
            return Response(json.dumps(result["body"]).encode())

        mock_urlopen(monkeypatch, urlopen)

    def s3(self, *, access_key_id: str, **_kwargs: object) -> object:
        def listing(**_parameters: object) -> dict[str, object]:
            if access_key_id not in self.keys:
                raise ClientError(
                    {
                        "Error": {"Code": "InvalidAccessKeyId"},
                        "ResponseMetadata": {"HTTPStatusCode": 403},
                    },
                    "ListObjectsV2",
                )
            return {"Contents": []}

        def versions(**parameters: str) -> dict[str, object]:
            listing()
            return {
                "IsTruncated": False,
                "Versions": [
                    {"Key": key, "VersionId": row[0], "IsLatest": True}
                    for (bucket, key), row in self.objects.items()
                    if bucket == parameters["Bucket"] and key.startswith(parameters["Prefix"])
                ],
                "DeleteMarkers": [],
            }

        def get(**parameters: str) -> dict[str, object]:
            listing()
            version, data = self.objects[parameters["Bucket"], parameters["Key"]]
            assert parameters["VersionId"] == version
            return {"Body": io.BytesIO(data), "VersionId": version, "ContentLength": len(data)}

        return SimpleNamespace(
            list_objects_v2=listing, list_object_versions=versions, get_object=get
        )

    def exchange(self, request: dict[str, object]) -> dict[str, object]:  # noqa: PLR0911, PLR0912 - explicit external protocol branches
        self.calls.append(deepcopy(request))
        path, method, token = str(request["path"]), request["method"], str(request["token"])
        body = deepcopy(request["body"])
        if request["origin"] == "https://api.digitalocean.com":
            assert token in self.services.operator.secrets.values()
            if method == "GET":
                return {
                    "status": 200,
                    "body": {
                        "meta": {"total": len(self.keys)},
                        "keys": list(deepcopy(self.keys).values()),
                    },
                }
            if method == "POST":
                assert isinstance(body, dict)
                selected = "SYNTHETICKEY" + str(len(self.creates))
                self.keys[selected] = {
                    **body,
                    "access_key": selected,
                    "secret_key": "SYNTHETIC-CHILD-" + selected,
                    "created_at": stamp(datetime.now(UTC)),
                }
                self.creates.append(selected)
                return {"status": 201, "body": {"key": deepcopy(self.keys[selected])}}
            assert method == "DELETE"
            self.keys.pop(path.rsplit("/", 1)[1], None)
            return {"status": 204, "body": {}}
        assert request["origin"] == "https://api.cloudflare.com/client/v4"
        base = urlsplit(path).path
        if base.endswith("/verify"):
            selected = self.secret_ids.get(token, "")
            if selected not in self.tokens:
                return {"status": 401, "body": {}}
            return {
                "status": 200,
                "body": {"success": True, "result": {"id": selected, "status": "active"}},
            }
        assert token in self.secret_ids
        if base.startswith("/zones/"):
            zone = base.rsplit("/", 1)[1]
            name = "lowerduckpond.net" if zone == self.targets.zone_id else "lowerduckpond.com"
            result: object = {
                "id": zone,
                "name": name,
                "status": "active",
                "account": {"id": self.targets.account_id},
            }
        elif base.endswith("/permission_groups"):
            names = parse_qs(urlsplit(path).query).get("name")
            result = [
                deepcopy(group) for group in self.groups if names is None or group["name"] in names
            ]
        elif method == "POST":
            assert isinstance(body, dict)
            selected = hashlib.md5(str(body["name"]).encode(), usedforsecurity=False).hexdigest()
            for policy in cast(list[dict[str, object]], body["policies"]):
                policy["permission_groups"] = [
                    {"id": group["id"], "name": group["name"]}
                    for group in self.groups
                    if group["id"]
                    in {
                        row["id"] for row in cast(list[dict[str, str]], policy["permission_groups"])
                    }
                ]
            secret = "SYNTHETIC-CHILD-" + selected
            self.tokens[selected] = {
                **body,
                "id": selected,
                "status": "active",
                "issued_on": body["not_before"],
            }
            self.secret_ids[secret] = selected
            self.creates.append(selected)
            result = {**deepcopy(self.tokens[selected]), "value": secret}
        elif method == "DELETE":
            selected = base.rsplit("/", 1)[1]
            self.tokens.pop(selected, None)
            result = {"id": selected}
        elif base.endswith("/tokens"):
            result = list(deepcopy(self.tokens).values())
            return {
                "status": 200,
                "body": {
                    "success": True,
                    "result": result,
                    "result_info": {
                        "page": 1,
                        "total_pages": 1,
                        "total_count": len(result),
                        "count": len(result),
                    },
                },
            }
        else:
            selected = base.rsplit("/", 1)[1]
            if selected not in self.tokens:
                return {"status": 404, "body": {}}
            result = deepcopy(self.tokens[selected])
        return {"status": 200, "body": {"success": True, "result": result}}
