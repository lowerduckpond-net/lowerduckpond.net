"""Independent, read-only observations of the run's private DNS-01 names.

No API here creates or deletes records. Only the installed Caddy probe uses the
runtime credential. These original observations remain private and cannot, by
themselves, assert that certificate issuance or the installed assertions passed.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS

from scripts import m3_11_qualification_evidence as evidence
from scripts.check_m3_7_production_edge import (
    ZONE_ID_PATTERN,
    CloudflareClient,
    _require_zone_identity,
)
from scripts.check_m3_10_provider import check_caddy_token, required
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private, write_private

FORMAT = "lowerduckpond-m3-11-private-dns-observation-v1"
POLL_INTERVAL_SECONDS = 5
# Both polling loops share the original coordinator deadline. Allow every
# periodic sample, each loop's immediate first sample, then baseline, cleanup,
# and the two teardown observations; evidence accounting must not shorten it.
MAX_OBSERVATIONS = math.ceil(COORDINATOR_SECONDS / POLL_INTERVAL_SECONDS) + 2 + 4
MAX_RECORDS_PER_NAME = 4
MAX_TYPE_LENGTH = 16
MAX_CONTENT_LENGTH = 4096
ZONES = (
    ("lowerduckpond.net", "CLOUDFLARE_ZONE_ID"),
    ("lowerduckpond.com", "CLOUDFLARE_TENANT_ZONE_ID"),
)
Kind = Literal["baseline", "activity", "cleanup", "teardown"]


def _digest(value: object) -> str:
    return hashlib.sha256(evidence.canonical_bytes(value)).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Observation:
    path: Path = field(repr=False)
    sha256: str
    active_zones: frozenset[str]
    record_count: int


@dataclass
class DnsWitness:
    directory: Path = field(repr=False)
    client: CloudflareClient = field(repr=False)
    context_sha256: str
    names_sha256: str
    coordinates: tuple[tuple[str, str, str], ...] = field(repr=False)
    sequence: int = 0
    observed_zones: set[str] = field(default_factory=set)
    _failed: bool = field(default=False, init=False, repr=False)

    @classmethod
    def begin(cls, directory: Path, storage: LiveStorage) -> DnsWitness:
        """Refuse pre-existing names before the caller may start public issuance."""
        storage.require_source(storage.environment)
        if directory != Path(storage.environment["M3_10_INSTALLED_REPORT"]).parent:
            raise ValueError("public DNS observations need their original owned run directory")
        observations = directory / "public-dns"
        if observations.exists() or observations.is_symlink():
            raise ValueError("public DNS original observations are already allocated")
        context = read_private(directory / "combined-context.json")
        names = read_private(directory / "combined-names.json")
        evidence.fields(
            context,
            {
                "format",
                "run_id",
                "captured_at",
                *evidence.BINDING_FIELDS,
                *evidence.IDENTITY_FIELDS,
            },
        )
        evidence.validate_names(directory / "combined-names.json", context)
        if (
            context["format"] != evidence.CONTEXT_FORMAT
            or context["run_id"] != storage.target.run_id
            or any(context[key] != storage.binding[key] for key in evidence.BINDING_FIELDS)
        ):
            raise ValueError("public DNS context differs from the original storage attempt")
        zone_ids = tuple(required(storage.environment, variable) for _, variable in ZONES)
        if len(set(zone_ids)) != len(ZONES) or any(
            ZONE_ID_PATTERN.fullmatch(zone_id) is None for zone_id in zone_ids
        ):
            raise ValueError("public DNS requires the two distinct configured zones")
        client = CloudflareClient(required(storage.environment, "CLOUDFLARE_API_TOKEN"))
        accounts = {
            _require_zone_identity(client, zone_id, domain)
            for (domain, _), zone_id in zip(ZONES, zone_ids, strict=True)
        }
        if len(accounts) != 1:
            raise ValueError("public DNS zones belong to different accounts")
        check_caddy_token(storage.environment, account_id=accounts.pop(), now=datetime.now(UTC))
        # Allocation is exclusive even when the first observation fails. A retry
        # must retain that failure rather than replace a nonempty baseline.
        (directory / "public-dns").mkdir(mode=0o700)
        nonce = evidence.uuid7(names["nonce"])
        witness = cls(
            directory,
            client,
            _digest(context),
            _digest(names),
            tuple(
                (domain, zone_id, f"_acme-challenge.m3-11-{nonce.hex}.{domain}")
                for (domain, _), zone_id in zip(ZONES, zone_ids, strict=True)
            ),
        )
        witness.require_absent("baseline")
        return witness

    def _records(self, zone_id: str, name: str) -> list[dict[str, str]]:
        # Ask for every type: a pre-existing CNAME must not appear to be an empty
        # challenge name merely because the caller filtered for TXT records.
        values = self.client.get_collection(f"/zones/{zone_id}/dns_records", query={"name": name})
        if len(values) > MAX_RECORDS_PER_NAME:
            raise ValueError("public DNS observation exceeds its record bound")
        records: list[dict[str, str]] = []
        for value in values:
            if not isinstance(value, dict):
                raise ValueError("public DNS returned a malformed record")
            record = {key: value.get(key) for key in ("id", "name", "type", "content")}
            if any(not isinstance(item, str) for item in record.values()):
                raise ValueError("public DNS returned malformed record coordinates")
            strings = {key: item for key, item in record.items() if isinstance(item, str)}
            if (
                strings["name"] != name
                or ZONE_ID_PATTERN.fullmatch(strings["id"]) is None
                or len(strings["type"]) > MAX_TYPE_LENGTH
                or len(strings["content"]) > MAX_CONTENT_LENGTH
            ):
                raise ValueError("public DNS returned foreign or unbounded record coordinates")
            records.append(strings)
        if len({record["id"] for record in records}) != len(records):
            raise ValueError("public DNS returned duplicate record identities")
        return sorted(records, key=lambda record: record["id"])

    def sample(self, kind: Kind = "activity") -> Observation:
        if self._failed:
            raise ValueError("public DNS observation previously failed in this attempt")
        # An incomplete provider read or durable write ends this attempt. A
        # controller must not catch it and refresh the same run into a pass.
        self._failed = True
        if kind not in {"baseline", "activity", "cleanup", "teardown"}:
            raise ValueError("public DNS observation kind is invalid")
        if self.sequence >= MAX_OBSERVATIONS:
            raise ValueError("public DNS observation count exceeds its bound")
        if (
            _digest(read_private(self.directory / "combined-context.json")) != self.context_sha256
            or _digest(read_private(self.directory / "combined-names.json")) != self.names_sha256
        ):
            raise ValueError("public DNS original context or private names changed")
        started = _now()
        inventories = {
            domain: self._records(zone_id, name) for domain, zone_id, name in self.coordinates
        }
        zones = {
            domain: {"zone_id": zone_id, "name": name, "records": inventories[domain]}
            for domain, zone_id, name in self.coordinates
        }
        document = {
            "format": FORMAT,
            "context_sha256": self.context_sha256,
            "names_sha256": self.names_sha256,
            "kind": kind,
            "sequence": self.sequence,
            "started_at": started,
            "completed_at": _now(),
            "zones": zones,
        }
        path = self.directory / "public-dns" / f"{self.sequence:04d}.json"
        write_private(path, document)
        self.sequence += 1
        records = [record for inventory in inventories.values() for record in inventory]
        active = frozenset(domain for domain, inventory in inventories.items() if inventory)
        if kind == "activity":
            # Retain the actual response above, then reject unrelated contents.
            if any(
                record["type"] != "TXT"
                or re.fullmatch(r"[A-Za-z0-9_-]{43}", record["content"]) is None
                for record in records
            ):
                raise ValueError("public DNS activity is not an ACME DNS-01 challenge")
            self.observed_zones.update(active)
        self._failed = False
        return Observation(path, _digest(document), active, len(records))

    def require_absent(self, kind: Literal["baseline", "cleanup", "teardown"]) -> Observation:
        result = self.sample(kind)
        if result.record_count:
            self._failed = True
            raise ValueError("public DNS challenge names are not empty")
        return result

    def require_both_zones_observed(self) -> None:
        if self.observed_zones != {domain for domain, _ in ZONES}:
            raise ValueError("public DNS-01 activity was not independently observed in both zones")


def removal_absence(directory: Path, storage: LiveStorage) -> Observation:
    """Append a cleanup-only observation without replacing the failed live attempt.

    The caller has validated its prior teardown authorization. No runtime token,
    new baseline, certificate issuance, or qualification receipt is created here.
    """
    context = read_private(directory / "combined-context.json")
    names = read_private(directory / "combined-names.json")
    evidence.validate_names(directory / "combined-names.json", context)
    intent = read_private(directory / "owned-teardown/intent.json")
    if (
        context["run_id"] != storage.target.run_id
        or any(context[key] != storage.binding[key] for key in evidence.BINDING_FIELDS)
        or intent.get("context_sha256") != _digest(context)
    ):
        raise ValueError("DNS cleanup lacks its original teardown context")
    baseline = read_private(directory / "public-dns/0000.json")
    zones = evidence.fields(baseline.get("zones"), {domain for domain, _ in ZONES})
    nonce = evidence.uuid7(names["nonce"])
    coordinates = tuple(
        (
            domain,
            required(storage.environment, variable),
            f"_acme-challenge.m3-11-{nonce.hex}.{domain}",
        )
        for domain, variable in ZONES
    )
    if (
        baseline.get("kind") != "baseline"
        or len({zone_id for _, zone_id, _ in coordinates}) != len(ZONES)
        or any(
            ZONE_ID_PATTERN.fullmatch(zone_id) is None
            or zones[domain] != {"zone_id": zone_id, "name": name, "records": []}
            for domain, zone_id, name in coordinates
        )
    ):
        raise ValueError("DNS cleanup original zone ownership changed")
    paths = []
    for path in (directory / "public-dns").iterdir():
        paths.append(path)
        if len(paths) >= MAX_OBSERVATIONS:
            raise ValueError("DNS cleanup observation count exceeds its bound")
    hashes = []
    for sequence, path in enumerate(sorted(paths)):
        value = read_private(path)
        if (
            path.name != f"{sequence:04d}.json"
            or value.get("format") != FORMAT
            or value.get("sequence") != sequence
            or value.get("context_sha256") != _digest(context)
            or value.get("names_sha256") != _digest(names)
        ):
            raise ValueError("DNS cleanup original observation sequence changed")
        hashes.append(_digest(value))
    if intent.get("dns_sha256") not in hashes:
        raise ValueError("DNS cleanup lost its original authorization observation")
    client = CloudflareClient(required(storage.environment, "CLOUDFLARE_API_TOKEN"))
    if (
        len({_require_zone_identity(client, zone_id, domain) for domain, zone_id, _ in coordinates})
        != 1
    ):
        raise ValueError("DNS cleanup zones belong to different accounts")
    witness = DnsWitness(
        directory, client, _digest(context), _digest(names), coordinates, len(paths)
    )
    return witness.require_absent("teardown")
