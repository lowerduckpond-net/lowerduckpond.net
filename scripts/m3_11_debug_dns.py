"""Bind explicit stale-challenge retirement to prior failed diagnostic observations."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from scripts.m3_11_combined_inputs import _directory
from scripts.m3_11_debug_dns_probe import records
from scripts.m3_11_debug_files import require_original_unchanged
from scripts.m3_11_dns_witness import FORMAT, MAX_OBSERVATIONS, DnsWitness
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes


def _inventory(value: dict[str, object], witness: DnsWitness) -> list[dict[str, str]]:
    zones = value.get("zones")
    if (
        value.get("format") != FORMAT
        or value.get("context_sha256") != witness.context_sha256
        or value.get("names_sha256") != witness.names_sha256
        or not isinstance(zones, dict)
        or set(zones) != {domain for domain, _, _ in witness.coordinates}
    ):
        raise ValueError("diagnostic DNS retirement observation belongs to another context")
    result = []
    for domain, zone_id, name in witness.coordinates:
        zone = zones[domain]
        if not isinstance(zone, dict) or zone.get("zone_id") != zone_id or zone.get("name") != name:
            raise ValueError("diagnostic DNS retirement observation changed coordinates")
        entries = zone.get("records")
        if not isinstance(entries, list):
            raise ValueError("diagnostic DNS retirement observation is malformed")
        for item in entries:
            if not isinstance(item, dict) or item.get("name") != name:
                raise ValueError("diagnostic DNS retirement observation has foreign records")
            result.append({**item, "zone_id": zone_id})
    if not result:
        return []
    nonce = str(read_private(witness.directory / "combined-names.json")["nonce"])
    return records(result, nonce)


def retire(witness: DnsWitness, call: Callable[..., dict[str, object]]) -> dict[str, object]:
    root = witness.directory
    require_original_unchanged(root)
    current = witness.output_directory
    if current is None or current.parent != root / "diagnostic-dns":
        raise ValueError("stale DNS retirement is restricted to diagnostic observations")
    # diagnostic_prepare has stopped the owned issuer; observe what actually remains.
    before = witness.sample("activity")
    wanted = _inventory(read_private(before.path), witness)
    if not wanted:
        return {"retired_records": 0, "qualification_authority": "none"}
    parents = sorted(current.parent.iterdir())
    if len(parents) > 128:  # noqa: PLR2004 - bounded private diagnostic history
        raise ValueError("diagnostic DNS retirement history exceeds its bound")
    known: set[bytes] = set()
    proofs: dict[str, str] = {}
    for parent in parents:
        _directory(parent)
        if parent.resolve() != parent:
            raise ValueError("diagnostic DNS retirement history is redirected")
        if parent.name >= current.name:
            continue
        paths = sorted(parent.glob("[0-9][0-9][0-9][0-9].json"))
        if len(paths) > MAX_OBSERVATIONS:
            raise ValueError("diagnostic DNS retirement observation count exceeds its bound")
        if not paths:
            continue
        value = read_private(paths[-1])
        if value.get("kind") != "cleanup":
            continue
        observed = _inventory(value, witness)
        known.update(canonical_bytes(item) for item in observed)
        proofs[str(paths[-1].relative_to(root))] = hashlib.sha256(
            canonical_bytes(value)
        ).hexdigest()
    if not {canonical_bytes(item) for item in wanted} <= known:
        raise ValueError("DNS retirement requires exact records from a prior cleanup failure")
    parent = root / "diagnostic-dns-retirements"
    parent.mkdir(mode=0o700, exist_ok=True)
    _directory(parent)
    if parent.resolve() != parent:
        raise ValueError("diagnostic DNS retirement receipt directory is redirected")
    directory = parent / current.name
    directory.mkdir(mode=0o700)
    write_private(
        directory / "plan.json",
        {
            "context_sha256": witness.context_sha256,
            "before_sha256": before.sha256,
            "prior_observations": proofs,
            "records": wanted,
            "qualification_authority": "none",
        },
    )
    result = call("diagnostic_retire_dns", expected=wanted)
    after = witness.require_absent("cleanup")
    result = {**result, "absence_sha256": after.sha256}
    write_private(directory / "result.json", result)
    return result
