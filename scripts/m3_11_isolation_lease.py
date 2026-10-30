"""Once-only three-role issuance and owned cleanup, separate from qualification.

The isolated controller supplies the diagnostic-only Connect journal and native
shared-volume reservation. Native seven-role journals do not accept these
records. File-only transport doubles are insufficient for live admission.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid7

from scripts.m3_11_isolation_contract import ROLES, Intent, Plan, provider_id, require_three
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.cloudflare import ORIGIN, Cloudflare, result
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.model import Credential, LifecycleError, digest


class IndependentJournal(Protocol):
    """The live implementation must use a distinct tag/schema and exact readback."""

    def persist(self, value: dict[str, object]) -> None: ...

    def records(self) -> list[dict[str, object]]: ...

    def reserve(self, run_id: str, value: dict[str, object]) -> None:
        """Atomic create-only reservation; another output directory cannot replay."""
        ...


class Provider:
    """Only Cloudflare account-token paths; no DNS mutation or other provider."""

    def __init__(self, api: Api, *, account: str) -> None:
        if api.origin != ORIGIN:
            raise ValueError("isolation permits only the Cloudflare account-token API")
        self.account = provider_id(account)
        self.api = api
        self.authority_sha256 = api.credential_sha256
        self.path = f"/accounts/{self.account}/tokens"

    def inventory(self) -> list[str]:
        # Keep native complete-pagination, duplicate-ID and changed-total guards.
        return [
            provider_id(item["id"])
            for item in Cloudflare(self.api, account=self.account).inventory()
        ]

    def inspect(self, selected: str) -> dict[str, object] | None:
        response = self.api.request("GET", f"{self.path}/{provider_id(selected)}")
        if response.status == 404:  # noqa: PLR2004 - HTTP not found
            return None
        item = result(response.status, response.body)
        if not isinstance(item, dict) or item.get("id") != selected:
            raise LifecycleError("isolated credential readback was not acknowledged")
        return item

    def require_scope(self, intent: Intent) -> None:
        if (
            self.account != intent.plan.account_id
            or Cloudflare(self.api, account=self.account).permission_groups(intent.role)
            != intent.permission_ids
        ):
            raise ValueError("isolated permission IDs differ before creation")

    def create(self, intent: Intent, record: Callable[[str, str | None], None]) -> Credential:
        if intent.plan.account_id != self.account:
            raise ValueError("isolation issuance account changed")
        response = self.api.request(
            "POST",
            self.path,
            {
                "name": intent.plan.token_name(intent.role),
                "not_before": intent.requested_at,
                "expires_on": intent.expires_at,
                "policies": [
                    {
                        "effect": "allow",
                        "permission_groups": [{"id": key} for key in sorted(intent.permission_ids)],
                        "resources": dict.fromkeys(sorted(intent.plan.resources(intent.role)), "*"),
                    }
                ],
            },
        )
        item = result(response.status, response.body)
        if not isinstance(item, dict):
            raise LifecycleError("isolated creation response is unresolved")
        selected, secret = provider_id(item.get("id")), item.get("value")
        record(selected, secret if isinstance(secret, str) and secret else None)
        if not isinstance(secret, str) or not secret:
            raise LifecycleError("isolated creation omitted private credential bytes")
        return Credential(
            selected, secret, {key: value for key, value in item.items() if key != "value"}
        )

    def delete(self, selected: str) -> None:
        Cloudflare(self.api, account=self.account).delete(provider_id(selected))

    def denied(self, selected: str, secret: str) -> bool:
        # The native method treats network/transport failures as unproven.
        response = Api(ORIGIN, secret).request("GET", self.path + "/verify")
        if response.status in {401, 403}:
            return True
        value = result(response.status, response.body)
        return (
            isinstance(value, dict)
            and value.get("id") == selected
            and value.get("status") in {"disabled", "expired"}
        )

    def active(self, selected: str, secret: str) -> bool:
        response = Api(ORIGIN, secret).request("GET", self.path + "/verify")
        value = result(response.status, response.body)
        return (
            isinstance(value, dict)
            and value.get("id") == selected
            and value.get("status") == "active"
        )


class Lease:
    """A consumed CREATE is never retried, including after a lost acknowledgment."""

    def __init__(
        self, directory: Path | None, intents: tuple[Intent, ...], journal: IndependentJournal
    ) -> None:
        if len(intents) != len(ROLES) or {item.role for item in intents} != ROLES:
            raise ValueError("isolated lease requires exactly three intents")
        self._directory, self.intents, self.journal = directory, intents, journal
        self.plan_sha256 = intents[0].plan.sha256
        self.intent_sha256 = {item.role: item.sha256 for item in intents}

    @property
    def directory(self) -> Path:
        if self._directory is None:
            raise ValueError("remote isolation cleanup has no host private files")
        return self._directory

    def _bindings(self, provider: Provider, *, cleanup: bool = False) -> Plan:
        plan = self.intents[0].plan
        if plan.sha256 != self.plan_sha256 or any(
            intent.plan.sha256 != self.plan_sha256
            or intent.sha256 != self.intent_sha256[intent.role]
            or provider.account != plan.account_id
            or provider.authority_sha256
            != (intent.cleanup_authority_sha256 if cleanup else intent.issuer_authority_sha256)
            for intent in self.intents
        ):
            raise ValueError("isolated lease bindings or cleanup authority changed")
        return plan

    def _record(self, kind: str, payload: dict[str, object]) -> dict[str, object]:
        return {
            "format": "lowerduckpond-isolated-public-ca-obligation-v1",
            "plan_sha256": self.plan_sha256,
            "kind": kind,
            "payload": payload,
        }

    def _publish(self, kind: str, payload: dict[str, object]) -> None:
        self.journal.persist(self._record(kind, payload))

    def issue(
        self,
        provider: Provider,
        *,
        now: Callable[[], datetime],
        require_prearmed: Callable[[], None],
    ) -> dict[str, str]:
        self._bindings(provider)
        require_three(self.intents, now=now())
        require_prearmed()
        if self.journal.records():
            raise ValueError("isolated run has prior obligations; creation cannot be replayed")
        reservation = self._record(
            "reservation", {"reservation_id": str(uuid7()), "intents": self.intent_sha256}
        )
        self.journal.reserve(self.intents[0].plan.run_id, reservation)
        # The caller holds its native single-writer lease. O_EXCL also prevents
        # reuse by a second process after a crash; no reset/retry API exists.
        write_private(
            self.directory / "issue-entered.json",
            {"plan_sha256": self.plan_sha256, "reservation_sha256": digest(reservation)},
        )
        self._publish("intents", {"intents": [item.document() for item in self.intents]})
        selected: dict[str, str] = {}
        for intent in sorted(self.intents, key=lambda item: item.role):
            self._bindings(provider)
            require_three(self.intents, now=now())
            require_prearmed()
            provider.require_scope(intent)
            if set(provider.inventory()) != set(intent.baseline_ids) | set(selected.values()):
                raise ValueError("isolated pre-CREATE account inventory changed")
            # An intent+entered marker precede every POST. Unknown outcomes
            # remain obligations; remaining roles must not be submitted.
            write_private(
                self.directory / f"{intent.role}-entered.json", {"intent_sha256": intent.sha256}
            )
            self._publish("entered", {"intent_sha256": intent.sha256})
            # Prearm and independent-journal I/O do not renew admission.
            self._bindings(provider)
            require_three(self.intents, now=now())

            def record(identifier: str, secret: str | None, *, intent: Intent = intent) -> None:
                identifier = provider_id(identifier)
                value: dict[str, object] = {
                    "intent_sha256": intent.sha256,
                    "credential_id": identifier,
                }
                write_private(self.directory / f"{intent.role}-created.json", value)
                if secret is not None:
                    write_private(self.directory / f"{intent.role}.credential", {"value": secret})
                self._publish("created", value)

            credential = provider.create(intent, record)
            item = provider.inspect(credential.identifier)
            if item is None or intent.require_owned(item) != credential.identifier:
                raise ValueError("isolated credential did not verify after creation")
            if not provider.active(credential.identifier, credential.secret):
                raise ValueError("isolated credential authentication did not verify")
            selected[intent.role] = credential.identifier
        write_private(
            self.directory / "issued.json", {"plan_sha256": self.plan_sha256, "ids": selected}
        )
        self._publish("issued", {"ids": selected})
        return selected

    def _created(
        self, intent: Intent, records: list[dict[str, object]] | None
    ) -> dict[str, object] | None:
        path = None if self._directory is None else self.directory / f"{intent.role}-created.json"
        values = [read_private(path)] if path is not None and path.exists() else []
        for row in records or []:
            value = row.get("payload")
            if (
                row.get("kind") == "created"
                and isinstance(value, dict)
                and value.get("intent_sha256") == intent.sha256
            ):
                values.append(value)
        if not values:
            return None
        if any(
            set(value) != {"intent_sha256", "credential_id"}
            or value["intent_sha256"] != intent.sha256
            or value != values[0]
            for value in values
        ):
            raise ValueError("isolated created identity is invalid or conflicting")
        provider_id(values[0]["credential_id"])
        return values[0]

    def _require_not_submitted(
        self, intent: Intent, records: list[dict[str, object]] | None
    ) -> None:
        if records is None:
            raise ValueError("isolated not-submitted proof is unavailable")
        contrary = (
            self._directory is not None
            and (
                (self.directory / f"{intent.role}-entered.json").exists()
                or (self.directory / f"{intent.role}.credential").exists()
            )
        ) or self._created(intent, records) is not None
        for row in records:
            payload = row.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("isolated obligation payload is invalid")
            contrary |= (
                row.get("kind") == "entered" and payload.get("intent_sha256") == intent.sha256
            ) or row.get("kind") == "issued"
        if contrary:
            raise ValueError("isolated not-submitted claim has contrary creation evidence")

    def _cleanup_one(
        self, provider: Provider, intent: Intent, records: list[dict[str, object]] | None
    ) -> dict[str, object]:
        created = self._created(intent, records)
        entered = self.directory / f"{intent.role}-entered.json"
        entered_digest = digest({"intent_sha256": intent.sha256})
        remote_entered = any(
            row.get("kind") == "entered" and digest(row["payload"]) == entered_digest
            for row in records or []
        )
        if created is None and not entered.exists() and not remote_entered:
            self._require_not_submitted(intent, records)
            return {"creation": "not-submitted"}
        if created is None:
            # No replay of POST after a lost ACK. Retire exact matches but retain
            # the uncertainty; absence cannot prove a late request impossible.
            matches = []
            for selected in provider.inventory():
                if selected in intent.baseline_ids:
                    continue
                item = provider.inspect(selected)
                if item is not None and item.get("name") == intent.plan.token_name(intent.role):
                    matches.append(intent.require_owned(item, active=False))
            if len(matches) == 1:
                provider.delete(matches[0])
            raise ValueError("isolated CREATE remains unresolved; closure is not proven")
        selected = provider_id(created["credential_id"])
        if selected in intent.baseline_ids:
            raise ValueError("isolated cleanup refuses pre-existing credentials")
        item = provider.inspect(selected)
        if item is not None:
            intent.require_owned(item, active=False)
            provider.delete(selected)
        if selected in provider.inventory() or provider.inspect(selected) is not None:
            raise ValueError("isolated provider absence is not proven")
        retained = read_private(self.directory / f"{intent.role}.credential")
        secret = retained.get("value")
        if set(retained) != {"value"} or not isinstance(secret, str) or not secret:
            raise ValueError("isolated retained credential is invalid")
        if not provider.denied(selected, secret):
            raise ValueError("isolated negative authentication is not proven")
        return {"credential_id": selected, "provider_absent": True, "authentication": "denied"}

    def _records(self) -> list[dict[str, object]]:
        records = self.journal.records()
        if any(
            record.get("format") != "lowerduckpond-isolated-public-ca-obligation-v1"
            or record.get("plan_sha256") != self.plan_sha256
            for record in records
        ):
            raise ValueError("isolated journal contains foreign obligations")
        reservations = [record for record in records if record.get("kind") == "reservation"]
        if self._directory is None:
            if (
                len(reservations) != 1
                or cast(dict[str, object], reservations[0].get("payload", {})).get("intents")
                != self.intent_sha256
            ):
                raise ValueError("isolated remote reservation differs from the exact intents")
            return records
        marker = read_private(self.directory / "issue-entered.json")
        if (
            set(marker) != {"plan_sha256", "reservation_sha256"}
            or marker["plan_sha256"] != self.plan_sha256
            or len(reservations) != 1
            or digest(reservations[0]) != marker["reservation_sha256"]
        ):
            raise ValueError("isolated global issue reservation is not proven")
        return records

    def cleanup(self, provider: Provider, *, require_issuer_stopped: Callable[[], None]) -> str:
        """Try all owned obligations; a failed role cannot strand the other two."""
        self._bindings(provider, cleanup=True)
        require_issuer_stopped()
        records = None
        statuses: dict[str, object] = {}
        failed = False
        try:
            records = self._records()
        except Exception:
            # A journal outage cannot suppress owned local revocation. It does
            # prevent all not-submitted and independent-closure claims.
            failed = True
        for intent in self.intents:
            # Identity/fence failure stops all effects; an individual provider
            # failure does not prevent safe cleanup of the remaining roles.
            self._bindings(provider, cleanup=True)
            require_issuer_stopped()
            try:
                statuses[intent.role] = self._cleanup_one(provider, intent, records)
            except Exception as error:
                failed = True
                statuses[intent.role] = {"cleanup": "pending", "error_type": type(error).__name__}
        value: dict[str, object] = {"plan_sha256": self.plan_sha256, "roles": statuses}
        if failed:
            write_private(self.directory / f"cleanup-pending-{uuid7()}.json", value)
            with suppress(Exception):
                self._publish("cleanup-pending", value)
            raise ValueError("isolated cleanup remains pending; inspect private evidence")
        try:
            self._publish("closed", value)
        except Exception:
            write_private(self.directory / f"closure-unpublished-{uuid7()}.json", value)
            raise ValueError("isolated closure publication remains unverified") from None
        path = self.directory / "closed.json"
        if path.exists():
            if read_private(path) != value:
                raise ValueError("isolated closure evidence changed")
        else:
            write_private(path, value)
        return digest(value)

    def independent_readback(
        self, provider: Provider, *, expected: str, require_issuer_stopped: Callable[[], None]
    ) -> dict[str, object]:
        """GET-only check; an independent actor must execute this on real backends."""
        from scripts.m3_11_unattended.http import read_only_requests  # noqa: PLC0415

        self._bindings(provider, cleanup=True)
        require_issuer_stopped()
        with read_only_requests():
            records = self._records()
            closures = [row["payload"] for row in records if row.get("kind") == "closed"]
            if (
                not closures
                or not isinstance(closures[0], dict)
                or any(row != closures[0] for row in closures)
            ):
                raise ValueError("isolated remote closure is unavailable or conflicting")
            value = closures[0]
            if (
                self._directory is not None
                and read_private(self.directory / "closed.json") != value
            ):
                raise ValueError("isolated local and remote closure differ")
            if digest(value) != expected or value.get("plan_sha256") != self.plan_sha256:
                raise ValueError("isolated closure digest differs")
            remote = [
                row["payload"]
                for row in self.journal.records()
                if row.get("kind") == "closed" and row.get("plan_sha256") == self.plan_sha256
            ]
            if not remote or any(row != value for row in remote):
                raise ValueError("isolated independent journal closure is unavailable")
            roles = value.get("roles")
            if not isinstance(roles, dict) or set(roles) != ROLES:
                raise ValueError("isolated closure role set differs")
            inventory = provider.inventory()
            for intent in self.intents:
                row = roles[intent.role]
                if row == {"creation": "not-submitted"}:
                    self._require_not_submitted(intent, records)
                    continue
                if (
                    not isinstance(row, dict)
                    or set(row) != {"credential_id", "provider_absent", "authentication"}
                    or row.get("provider_absent") is not True
                    or row.get("authentication") != "denied"
                ):
                    raise ValueError("isolated closure is incomplete")
                selected = provider_id(row["credential_id"])
                created = self._created(intent, records)
                if created != {"intent_sha256": intent.sha256, "credential_id": selected}:
                    raise ValueError("isolated closure differs from its exact creation identity")
                if (
                    selected in intent.baseline_ids
                    or selected in inventory
                    or provider.inspect(selected) is not None
                ):
                    raise ValueError("isolated independent provider absence is not proven")
            return {
                "format": "lowerduckpond-isolated-public-ca-independent-readback-v1",
                "plan_sha256": self.plan_sha256,
                "closure_sha256": expected,
                "provider_absent": True,
                "journal_matches": True,
            }

    def revoke_remote(  # noqa: PLR0912 - try every bounded owned role
        self,
        provider: Provider,
        *,
        require_issuer_stopped: Callable[[], None],
        allow_not_submitted: bool = True,
    ) -> dict[str, object]:
        """Credential-only revocation; missing host denied probes remain pending.

        A journal outage cannot suppress revocation of an exact full-policy
        match. It can never establish a not-submitted or closure fact.
        """
        self._bindings(provider, cleanup=True)
        require_issuer_stopped()
        try:
            records = self._records()
        except Exception:
            records = None
        outcomes: dict[str, object] = {}
        for intent in self.intents:
            self._bindings(provider, cleanup=True)
            require_issuer_stopped()
            try:
                created = self._created(intent, records)
                if created is None:
                    try:
                        if not allow_not_submitted:
                            raise ValueError("not-submitted proof requires positive issuer stop")
                        self._require_not_submitted(intent, records)
                        outcomes[intent.role] = {"creation": "not-submitted"}
                        continue
                    except ValueError:
                        pass  # Unknown POST: only exact full-policy matches may be revoked.
                    matches = []
                    for selected in provider.inventory():
                        if selected in intent.baseline_ids:
                            continue
                        item = provider.inspect(selected)
                        if item is not None and item.get("name") == intent.plan.token_name(
                            intent.role
                        ):
                            matches.append(intent.require_owned(item, active=False))
                    if len(matches) != 1:
                        raise ValueError("isolated unknown creation remains unresolved")
                    selected = matches[0]
                else:
                    selected = provider_id(created["credential_id"])
                    if selected in intent.baseline_ids:
                        raise ValueError("isolated remote cleanup refuses pre-existing credentials")
                    item = provider.inspect(selected)
                    if item is not None:
                        intent.require_owned(item, active=False)
                if provider.inspect(selected) is not None:
                    provider.delete(selected)
                if selected in provider.inventory() or provider.inspect(selected) is not None:
                    raise ValueError("isolated remote provider absence is unproven")
                outcomes[intent.role] = {
                    "credential_id": selected,
                    "provider_absent": True,
                    "authentication": "unavailable",
                }
            except Exception as error:
                outcomes[intent.role] = {"cleanup": "pending", "error_type": type(error).__name__}
        return {
            "plan_sha256": self.plan_sha256,
            "roles": outcomes,
            "status": "awaiting-host-denial-proof",
        }
