from __future__ import annotations

import json
from pathlib import Path

from lowerduckpond_m3_qualification.domains import ATTESTATION_SCHEMA, run_domain_checks


def write_attestation(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": ATTESTATION_SCHEMA,
                "domains": {
                    "lowerduckpond.com": {
                        "auto_renew_enabled": True,
                        "registrant_controlled": True,
                    },
                    "lowerduckpond.net": {
                        "auto_renew_enabled": True,
                        "registrant_controlled": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def test_domain_checks_combine_attestation_with_active_cloudflare_zone(tmp_path: Path) -> None:
    attestation = tmp_path / "attestation.json"
    write_attestation(attestation)

    checks = run_domain_checks(
        attestation_path=attestation,
        zone_ids={"lowerduckpond.net": "net", "lowerduckpond.com": "com"},
        api_token="x" * 20,
        zone_client=lambda zone_id, token: {
            "name": f"lowerduckpond.{zone_id}",
            "status": "active",
            "paused": False,
            "name_servers": ["one.ns.cloudflare.com", "two.ns.cloudflare.com"],
        },
    )

    assert all(check.status == "passed" for check in checks)


def test_domain_checks_fail_closed_on_incomplete_attestation(tmp_path: Path) -> None:
    attestation = tmp_path / "attestation.json"
    write_attestation(attestation)
    value = json.loads(attestation.read_text(encoding="utf-8"))
    value["domains"]["lowerduckpond.com"]["auto_renew_enabled"] = False
    attestation.write_text(json.dumps(value), encoding="utf-8")

    checks = run_domain_checks(
        attestation_path=attestation,
        zone_ids={"lowerduckpond.net": "net", "lowerduckpond.com": "com"},
        api_token="x" * 20,
        zone_client=lambda zone_id, token: {
            "name": f"lowerduckpond.{zone_id}",
            "status": "active",
            "paused": False,
            "name_servers": ["one.ns.cloudflare.com", "two.ns.cloudflare.com"],
        },
    )

    by_id = {check.check_id: check for check in checks}
    assert by_id["m3.0.domain.lowerduckpond-com"].status == "failed"
    assert by_id["m3.0.domain.lowerduckpond-net"].status == "passed"
