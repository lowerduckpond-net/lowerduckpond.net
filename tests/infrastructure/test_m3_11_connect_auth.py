"""Native Connect policy must match authenticated signed claims and approved vaults."""

from __future__ import annotations

import base64
import copy
import json
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from scripts.m3_11_unattended import connect_auth as auth
from scripts.m3_11_unattended.connect_api import Connect, Response
from scripts.m3_11_unattended.model import LifecycleError, stamp

NOW = datetime(2026, 10, 4, 21, tzinfo=UTC)
CANARY = "Connect-policy-secret-canary"
SERVER, TOKEN, ACCOUNT = "S" * 26, "T" * 26, "A" * 26
VAULT, JOURNAL, FORBIDDEN = "v" * 26, "j" * 26, "f" * 26
# Literal CLI-observed grants, independent of the parser under test. See the
# vendor bit definitions and observation limits in fixtures/onepassword/provenance.json.
EXPECTED = {VAULT: 48, JOURNAL: 1008}


def encoded(value: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def example() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    expires = NOW + timedelta(days=7)
    payload: dict[str, object] = {
        "sub": SERVER,
        "jti": TOKEN,
        "iss": "example-issuer",
        "aud": "example-connect",
        "exp": int(expires.timestamp()),
        "iat": int(NOW.timestamp()),
        "1password.com/auuid": ACCOUNT,
        "1password.com/token": CANARY,
        "1password.com/fts": ["vaultaccess"],
        "1password.com/vts": [
            {"u": VAULT.upper(), "a": 48},
            {"u": JOURNAL.upper(), "a": 1008},
        ],
    }
    entry: dict[str, object] = {
        "server": SERVER,
        "name": "example-cleanup",
        "expires_at": stamp(expires),
    }
    metadata: dict[str, object] = {
        "checked_at": stamp(NOW),
        "server": {"id": SERVER, "state": "ACTIVE"},
        "tokens": [
            {
                "id": TOKEN,
                "integration_id": SERVER,
                "state": "ACTIVE",
                "name": entry["name"],
                "issuer": "example-issuer",
                "audience": "example-connect",
                "features": ["vaultaccess"],
                "created_at": stamp(NOW),
                "expires_at": stamp(expires),
                "vaults": [
                    {"id": VAULT.upper(), "acl": ["allow_viewing"]},
                    {"id": JOURNAL.upper(), "acl": ["allow_viewing", "allow_editing"]},
                ],
            }
        ],
    }
    return entry, metadata, payload


def token(entry: dict[str, object], payload: dict[str, object], *, algorithm: str = "ES256") -> str:
    result = encoded({"alg": algorithm, "typ": "JWT"}) + "." + encoded(payload) + ".c2lnbmF0dXJl"
    entry["token"] = result
    return result


class Endpoint(Connect):
    def __init__(self, credential: str) -> None:
        super().__init__("https://connect.example.test", credential)
        self.visible = set(EXPECTED)
        self.denial = 403
        self.accepted = True
        self.paths: list[str] = []

    def vaults(self) -> list[dict[str, object]]:
        if not self.accepted:
            raise LifecycleError("Connect authentication rejected")
        return [{"id": value} for value in self.visible]

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        assert method == "GET" and body is None
        self.paths.append(path)
        return Response(self.denial, None)


def test_native_signed_policy_and_authenticated_separation() -> None:
    entry, metadata, payload = example()
    client = Endpoint(token(entry, payload))
    access = auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)
    assert access.server_id == SERVER
    assert access.grants == EXPECTED
    assert access.receipt()["authenticated"] is False
    receipt = auth.authenticate(client, access, forbidden={FORBIDDEN})
    assert receipt["authenticated"] is True
    assert receipt["forbidden_vaults_denied"] == 1
    assert client.paths == ["/v1/vaults/" + FORBIDDEN]
    assert CANARY not in json.dumps(receipt)
    assert CANARY not in repr(access)


@pytest.mark.parametrize("array", [False, True])
def test_exact_single_audience_representation(array: bool) -> None:
    entry, metadata, payload = example()
    if array:
        payload["aud"] = [payload["aud"]]
    token(entry, payload)
    assert auth.inspect(entry, metadata, expected=EXPECTED, now=NOW).grants == EXPECTED


@pytest.mark.parametrize(
    "audience", [[], ["example-connect", "unexpected"], ["example-connect"] * 2, [None], None, 1]
)
def test_single_audience_does_not_accept_additional_or_malformed_values(audience: object) -> None:
    entry, metadata, payload = example()
    payload["aud"] = audience
    token(entry, payload)
    with pytest.raises(LifecycleError, match="exact policy differs"):
        auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)


@pytest.mark.parametrize("native_offset", [-1, 0, 1, 2])
def test_native_expiry_representation_never_extends_signed_lifetime(native_offset: int) -> None:
    entry, metadata, payload = example()
    signed_expiry = NOW + timedelta(days=7)
    native = cast(list[dict[str, object]], metadata["tokens"])[0]
    native["expires_at"] = stamp(signed_expiry + timedelta(seconds=native_offset))
    payload["aud"] = [payload["aud"]]
    token(entry, payload)
    if native_offset not in {0, 1}:
        with pytest.raises(LifecycleError, match="lifetimes differ"):
            auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)
        return
    access = auth.inspect(
        entry, metadata, expected=EXPECTED, now=NOW, approved_expires_at=signed_expiry
    )
    assert access.expires_at == signed_expiry
    assert access.receipt()["expires_at"] == stamp(signed_expiry)
    with pytest.raises(LifecycleError, match="lifetimes differ"):
        auth.inspect(entry, metadata, expected=EXPECTED, now=signed_expiry)
    with pytest.raises(LifecycleError, match="lifetimes differ"):
        auth.inspect(
            entry,
            metadata,
            expected=EXPECTED,
            now=NOW,
            approved_expires_at=signed_expiry + timedelta(seconds=1),
        )
    entry["expires_at"] = stamp(signed_expiry + timedelta(seconds=1))
    with pytest.raises(LifecycleError, match="lifetimes differ"):
        auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)


@pytest.mark.parametrize("permission", [496, 48, True, False, "1008", 1008.0, None, -1])
def test_journal_rejects_incomplete_grants_and_noninteger_permissions(permission: object) -> None:
    entry, metadata, payload = example()
    policies = cast(list[dict[str, object]], payload["1password.com/vts"])
    policies[1]["a"] = permission
    token(entry, payload)
    with pytest.raises(LifecycleError) as caught:
        auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)
    assert CANARY not in str(caught.value)
    assert str(entry["token"]) not in str(caught.value)


@pytest.mark.parametrize(
    "extra_bit", [1, 2, 4, 8, 1024, 1 << 20, 1 << 21, 1 << 22, 1 << 23, 1 << 31]
)
def test_journal_rejects_additional_permissions_and_unknown_bits(extra_bit: int) -> None:
    entry, metadata, payload = example()
    policies = cast(list[dict[str, object]], payload["1password.com/vts"])
    policies[1]["a"] = 1008 | extra_bit
    token(entry, payload)
    with pytest.raises(LifecycleError):
        auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)


@pytest.mark.parametrize("native", [False, True])
def test_casefolded_duplicate_grants_remain_rejected(native: bool) -> None:
    entry, metadata, payload = example()
    if native:
        record = cast(list[dict[str, object]], metadata["tokens"])[0]
        policies = cast(list[dict[str, object]], record["vaults"])
        duplicate = {**policies[1], "id": JOURNAL.lower()}
    else:
        policies = cast(list[dict[str, object]], payload["1password.com/vts"])
        duplicate = {**policies[1], "u": JOURNAL.lower()}
    policies.append(duplicate)
    token(entry, payload)
    with pytest.raises(LifecycleError, match="unknown or ambiguous grants"):
        auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)


@pytest.mark.parametrize(
    "failure",
    [
        "extra-vault",
        "write-bootstrap",
        "unknown-bits",
        "boolean-bits",
        "duplicate-vault",
        "extra-feature",
        "subject",
        "token-id",
        "account-id",
        "issuer",
        "audience",
        "inactive",
        "native-grant",
        "duplicate-native",
        "expired",
        "long-life",
        "future-issue",
        "native-expiry",
        "saved-expiry",
        "algorithm",
    ],
)
def test_mismatched_policy_or_lifetime_is_rejected_without_secret_output(  # noqa: PLR0912 - policy fault table
    failure: str,
) -> None:
    entry, metadata, payload = example()
    policies = cast(list[dict[str, object]], payload["1password.com/vts"])
    records = cast(list[dict[str, object]], metadata["tokens"])
    native = records[0]
    if failure == "extra-vault":
        policies.append({"u": FORBIDDEN, "a": auth.READ})
    elif failure == "write-bootstrap":
        policies[0]["a"] = auth.READ_WRITE
    elif failure == "unknown-bits":
        policies[0]["a"] = auth.READ | 1
    elif failure == "boolean-bits":
        policies[0]["a"] = True
    elif failure == "duplicate-vault":
        policies.append(copy.deepcopy(policies[0]))
    elif failure == "extra-feature":
        payload["1password.com/fts"] = ["vaultaccess", "unexpected"]
    elif failure in {"subject", "token-id", "account-id", "issuer", "audience"}:
        field = {
            "subject": "sub",
            "token-id": "jti",
            "account-id": "1password.com/auuid",
            "issuer": "iss",
            "audience": "aud",
        }[failure]
        payload[field] = "unexpected"
    elif failure == "inactive":
        native["state"] = "REVOKED"
    elif failure == "native-grant":
        native["vaults"] = [{"id": VAULT, "acl": ["allow_editing"]}]
    elif failure == "duplicate-native":
        records.append(copy.deepcopy(native))
    elif failure == "expired":
        payload["exp"] = int(NOW.timestamp())
    elif failure == "long-life":
        payload["exp"] = int((NOW + timedelta(days=90)).timestamp())
    elif failure == "future-issue":
        payload["iat"] = int((NOW + timedelta(hours=1)).timestamp())
    elif failure == "native-expiry":
        native["expires_at"] = stamp(NOW + timedelta(days=6))
    elif failure == "saved-expiry":
        entry["expires_at"] = stamp(NOW + timedelta(days=6))
    token(entry, payload, algorithm="none" if failure == "algorithm" else "ES256")
    with pytest.raises(LifecycleError) as caught:
        auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)
    assert CANARY not in str(caught.value)
    assert str(entry["token"]) not in str(caught.value)


@pytest.mark.parametrize(
    "failure", ["revoked", "extra-visible", "missing-visible", "forbidden", "different-client"]
)
def test_policy_decoding_cannot_substitute_for_authentication(failure: str) -> None:
    entry, metadata, payload = example()
    client = Endpoint(token(entry, payload))
    access = auth.inspect(entry, metadata, expected=EXPECTED, now=NOW)
    if failure == "revoked":
        client.accepted = False
    elif failure == "extra-visible":
        client.visible.add(FORBIDDEN)
    elif failure == "missing-visible":
        client.visible.remove(JOURNAL)
    elif failure == "forbidden":
        client.denial = 200
    else:
        client = Endpoint("different.token.signature")
    with pytest.raises(LifecycleError):
        auth.authenticate(client, access, forbidden={FORBIDDEN})


def test_reject_duplicate_claims_and_malformed_json() -> None:
    header = encoded({"alg": "ES256", "typ": "JWT"})
    duplicate = base64.urlsafe_b64encode(b'{"exp":1,"exp":2}').decode().rstrip("=")
    with pytest.raises(LifecycleError, match="ambiguous"):
        auth.claims(header + "." + duplicate + ".c2ln")
    with pytest.raises(LifecycleError):
        auth.claims(header + ".not-json.c2ln")
