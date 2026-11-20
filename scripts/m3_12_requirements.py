"""Validate the M3.12 requirement and proof-slot inventory against its source prose."""

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from scripts.m3_12_contracts import (
    DISPOSABLE,
    INSTALLED,
    PRODUCTION,
    Document,
    Evidence,
    digest,
    instant,
    require,
)

SECTIONS = {
    "ADR0022": (
        ("docs/adr/0022-test-static-publication-as-a-security-boundary.md", "Decision"),
        ("docs/adr/0022-test-static-publication-as-a-security-boundary.md", "Consequences"),
    ),
    "M3": (
        ("docs/plans/milestone-3.md", "M3.12: qualify and enable production"),
        ("docs/plans/milestone-3.md", "10. Milestone completion evidence"),
    ),
}
ENVIRONMENT = {
    "component": "P3",
    "installed": "P3",
    "droplet": "P4",
    "restore-target": "P4",
    "browser": "P4",
    "production-read-only": "P6",
    "production-canary": "P6",
}
COVERAGE_KIND = {
    "component": INSTALLED,
    "installed": INSTALLED,
    "droplet": DISPOSABLE,
    "restore-target": DISPOSABLE,
    "browser": DISPOSABLE,
    "production-read-only": PRODUCTION,
    "production-canary": PRODUCTION,
}
HEADING = re.compile(r"^(#{1,6}) (.+)$")
LIST_ITEM = re.compile(r"^(?:- |[0-9]+\. )")


def paragraphs(source: str, heading: str) -> Iterator[tuple[int, str]]:
    """Normalize line wrapping while keeping individual list items distinct."""
    start: int | None = None
    current: list[str] = []
    level = 0
    for number, line in enumerate(source.splitlines(), start=1):
        match = HEADING.fullmatch(line)
        if level == 0:
            if match and match[2] == heading:
                level = len(match[1])
            continue
        ends_section = bool(match and len(match[1]) <= level)
        if start is not None and (not line.strip() or LIST_ITEM.match(line) or ends_section):
            yield start, " ".join(current)
            current.clear()
            start = None
        if ends_section:
            break
        if line.strip():
            start = start if start is not None else number
            current.append(line.strip())
    if start is not None:
        yield start, " ".join(current)


def source_fingerprints(root: Path) -> dict[tuple[str, str, str], int]:
    result: dict[tuple[str, str, str], int] = {}
    for boundaries in SECTIONS.values():
        for path, heading in boundaries:
            source = (root / path).read_text(encoding="utf-8")
            for line, paragraph in paragraphs(source, heading):
                key = (path, heading, sha256(paragraph.encode("utf-8")).hexdigest())
                require(key not in result, "duplicate-source-paragraph")
                result[key] = line
    return result


def validate_inventory(root: Path, inventory: Document) -> None:
    """A proof slot can only reference one known requirement and environment."""
    expected = source_fingerprints(root)
    seen: set[tuple[str, str, str]] = set()
    identifiers: set[str] = set()
    require(
        set(inventory) == {"format", "requirements"}
        and inventory["format"] == "lowerduckpond-m3-12-requirements-v1",
        "invalid-inventory",
    )
    for item in inventory["requirements"]:
        require(
            set(item) == {"id", "source", "section", "sha256", "proofs"} and bool(item["proofs"]),
            "invalid-requirement",
        )
        key = (item["source"], item["section"], item["sha256"])
        identifier = item["id"]
        require(key in expected and key not in seen, "missing-or-stale-requirement")
        require(
            bool(
                re.fullmatch(
                    r"(?:ADR0022|M3)-[0-9]{3}",
                    identifier,
                )
            )
            and (item["source"], item["section"]) in SECTIONS[identifier.split("-")[0]]
            and identifier not in identifiers,
            "invalid-requirement-id",
        )
        seen.add(key)
        identifiers.add(identifier)
        slots = set()
        for proof in item["proofs"]:
            slot = proof["environment"]
            require(
                slot in ENVIRONMENT
                and slot not in slots
                and proof["slot"] == f"{identifier}/{slot}",
                "invalid-proof-slot",
            )
            slots.add(slot)
            if proof["state"] == "pending":
                require(
                    set(proof) == {"environment", "slot", "state", "slice"}
                    and proof["slice"] == ENVIRONMENT[slot],
                    "invalid-pending-proof",
                )
            else:
                require(
                    proof["state"] == "mapped"
                    and set(proof) == {"environment", "slot", "state", "nodes"}
                    and bool(proof["nodes"])
                    and len(set(proof["nodes"])) == len(proof["nodes"]),
                    "invalid-proof-mapping",
                )
                for node in proof["nodes"]:
                    file, separator, test = node.partition("::")
                    require(
                        bool(separator)
                        and bool(re.fullmatch(r"(?:packages|tests|config)/[a-z_0-9/-]+\.py", file))
                        and bool(re.fullmatch(r"test_[a-z0-9_]+", test))
                        and bool(re.search(rf"^def {test}\(", (root / file).read_text(), re.M)),
                        "stale-test-node",
                    )
    require(seen == expected.keys(), "missing-source-requirement")


@dataclass(frozen=True)
class CoverageScope:
    production: bool
    bindings: Mapping[str, Document]
    finished_by: datetime


def validate_coverage(
    inventory: Document, scope: CoverageScope, receipt_keys: Iterable[str], evidence: Evidence
) -> datetime:
    """Require original passing proof for each reviewed slot; return the oldest start.

    The caller first validates the reviewed inventory and independently establishes the
    binding per slot. Different restore and installed targets have their own bindings.
    A disposable functional seal excludes the later production-only obligations.
    """
    required = {
        proof["slot"]: proof
        for item in inventory["requirements"]
        for proof in item["proofs"]
        if scope.production or not proof["environment"].startswith("production-")
    }
    require(bool(required) and required.keys() == scope.bindings.keys(), "missing-coverage-binding")
    require(all(proof["state"] == "mapped" for proof in required.values()), "unmapped-proof")
    inventory_digest = digest(inventory)
    received: set[str] = set()
    times: list[datetime] = []
    for key in receipt_keys:
        receipt = evidence.read(key, "requirement-proof")
        slot = receipt["slot"]
        require(slot in required and slot not in received, "unknown-or-duplicate-proof")
        check = required[slot]
        binding = scope.bindings[slot]
        start = instant(receipt["startedAt"])
        require(
            receipt["inventorySha256"] == inventory_digest
            and receipt["binding"] == binding
            and binding["targetKind"] == COVERAGE_KIND[check["environment"]]
            and receipt["nodes"] == check["nodes"]
            and start <= instant(receipt["finishedAt"]) <= scope.finished_by,
            "wrong-requirement-proof",
        )
        received.add(slot)
        times.append(start)
    require(received == required.keys(), "missing-requirement-proof")
    return min(times)
