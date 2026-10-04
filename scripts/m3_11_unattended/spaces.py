"""DigitalOcean Spaces key creation and exact-identity revocation only."""

from __future__ import annotations

from datetime import datetime
from http import HTTPStatus

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import create_client

from scripts.m3_11_unattended.http import Api, collection
from scripts.m3_11_unattended.lifecycle import identifier
from scripts.m3_11_unattended.model import Credential, Intent, LifecycleError, ProviderKind

PAGE_SIZE = 200
MAX_PAGES = 25


class Spaces:
    kind: ProviderKind = "spaces"

    def __init__(self, api: Api) -> None:
        self.api = api
        self.authority_sha256 = api.credential_sha256

    @staticmethod
    def _metadata(value: dict[str, object]) -> dict[str, object]:
        return {
            "id": identifier(value.get("access_key")),
            "name": value.get("name"),
            "created_at": value.get("created_at"),
            "scope": {"grants": value.get("grants")},
            # The Spaces metadata has no status/expiry fields. Presence PLUS the
            # authenticated S3 probe establishes activity, not a fictional TTL.
            "status": "active",
            "expires_at": None,
        }

    def inventory(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        expected: int | None = None
        for page in range(1, MAX_PAGES + 1):
            response = self.api.request(
                "GET",
                f"/v2/spaces/keys?per_page={PAGE_SIZE}&page={page}&sort=created_at&sort_direction=asc",
            )
            metadata = response.body.get("meta")
            if response.status != HTTPStatus.OK or not isinstance(metadata, dict):
                raise LifecycleError("Spaces key inventory was not authenticated")
            total = metadata.get("total")
            if type(total) is not int or not 0 <= total <= PAGE_SIZE * MAX_PAGES:
                raise LifecycleError("Spaces key inventory pagination is invalid")
            if expected is not None and total != expected:
                raise LifecycleError("Spaces key inventory changed during pagination")
            expected = total
            items = collection(response.body.get("keys"))
            if len(items) > PAGE_SIZE or (not items and len(result) != total):
                raise LifecycleError("Spaces key inventory pagination is incomplete")
            result.extend(self._metadata(item) for item in items)
            if len(result) >= total:
                if len(result) != total or len({item["id"] for item in result}) != total:
                    raise LifecycleError("Spaces key inventory is ambiguous")
                return result
        raise LifecycleError("Spaces key inventory exceeds its page bound")

    def inspect(self, selected: str) -> dict[str, object] | None:
        identifier(selected)
        return next((item for item in self.inventory() if item["id"] == selected), None)

    def create(self, intent: Intent) -> Credential:
        response = self.api.request(
            "POST", "/v2/spaces/keys", {"name": intent.name, **intent.scope}
        )
        item = response.body.get("key")
        if response.status != HTTPStatus.CREATED or not isinstance(item, dict):
            raise LifecycleError("Spaces credential creation response was not acknowledged")
        selected, secret = identifier(item.get("access_key")), item.get("secret_key")
        if not isinstance(secret, str) or not secret:
            raise LifecycleError("Spaces creation omitted its secret; reconcile its intent")
        return Credential(selected, secret, self._metadata(item))

    def delete(self, selected: str) -> None:
        response = self.api.request("DELETE", f"/v2/spaces/keys/{identifier(selected)}")
        if response.status not in {HTTPStatus.NO_CONTENT, HTTPStatus.NOT_FOUND}:
            raise LifecycleError("Spaces credential deletion was not acknowledged")

    @staticmethod
    def _probe(intent: Intent, credential: Credential) -> None:
        client = create_client(
            access_key_id=credential.identifier,
            secret_access_key=credential.secret,
            region=intent.targets.region,
            endpoint_url=f"https://{intent.targets.region}.digitaloceanspaces.com",
        )
        bucket = (
            intent.targets.backup_bucket
            if intent.role == "backup"
            else intent.targets.archive_bucket
        )
        client.list_objects_v2(Bucket=bucket, MaxKeys=1)

    def verify(self, intent: Intent, credential: Credential, *, now: datetime) -> None:
        try:
            self._probe(intent, credential)
        except BotoCoreError, ClientError, OSError:
            raise LifecycleError("Spaces credential activity probe failed") from None

    def denied(self, intent: Intent, credential: Credential) -> bool:
        try:
            self._probe(intent, credential)
        except ClientError as error:
            # Authorization failures can occur while the key remains usable on
            # another bucket. Only invalid authentication proves revocation.
            return error.response.get("Error", {}).get(
                "Code"
            ) == "InvalidAccessKeyId" and error.response.get("ResponseMetadata", {}).get(
                "HTTPStatusCode"
            ) in {
                HTTPStatus.FORBIDDEN,
                HTTPStatus.UNAUTHORIZED,
            }
        except BotoCoreError, OSError:
            return False
        return False
