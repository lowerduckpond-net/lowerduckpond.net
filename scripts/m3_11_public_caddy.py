"""Fixed disposable public-CA policy for the owned reconstruction fixture.

This is a separate dependency proof, not the production subject configuration.
The controller binds these inputs to the original private combined context.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

INPUTS = Path("/etc/lowerduckpond-m3-11-public")
STORAGE = Path("/var/lib/lowerduckpond-m3-11-public-caddy")
UNIT = "lowerduckpond-m3-11-public-caddy.service"
ISSUER = "https://acme-v02.api.letsencrypt.org/directory"
ISSUER_STORAGE = "acme-v02.api.letsencrypt.org-directory"
RECOVERY = Path("/var/lib/lowerduckpond/recovery")
MAXIMUM_BYTES = 1024 * 1024


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def disposable_subjects(nonce: str) -> tuple[str, ...]:
    if str(uuid.UUID(nonce, version=7)) != nonce:
        raise ValueError("public probe requires a canonical private UUIDv7 nonce")
    prefix = "m3-11-" + uuid.UUID(nonce).hex
    return tuple(
        sorted(
            wildcard + prefix + "." + zone
            for wildcard in ("", "*.")
            for zone in ("lowerduckpond.net", "lowerduckpond.com")
        )
    )


def configuration(nonce: str) -> bytes:
    subjects = disposable_subjects(nonce)
    return canonical(
        {
            "admin": {"disabled": True},
            "storage": {"module": "file_system", "root": str(STORAGE)},
            "apps": {
                "http": {
                    "servers": {
                        "public_dependency": {
                            "listen": [":443"],
                            "automatic_https": {"disable_redirects": True},
                            "tls_connection_policies": [{}],
                            "routes": [
                                {
                                    "match": [{"host": subjects}],
                                    "handle": [{"handler": "static_response", "status_code": 204}],
                                }
                            ],
                        }
                    }
                },
                "tls": {
                    "certificates": {"automate": subjects},
                    "automation": {
                        "policies": [
                            {
                                "subjects": subjects,
                                "issuers": [
                                    {
                                        "module": "acme",
                                        "ca": ISSUER,
                                        # CertMagic otherwise supplies its staging CA on retry.
                                        # Bind every attempt to the same public issuer.
                                        "test_ca": ISSUER,
                                        "challenges": {
                                            "http": {"disabled": True},
                                            "tls-alpn": {"disabled": True},
                                            "dns": {
                                                "provider": {
                                                    "name": "cloudflare",
                                                    "api_token": "{env.CLOUDFLARE_API_TOKEN}",
                                                }
                                            },
                                        },
                                    }
                                ],
                            }
                        ]
                    },
                },
            },
        }
    )


def service(binary: str) -> bytes:
    if (
        re.fullmatch(
            r"/usr/local/lib/lowerduckpond/caddy-[0-9.]+-xcaddy-[0-9.]+-cloudflare-[0-9.]+",
            binary,
            flags=re.ASCII,
        )
        is None
    ):
        raise ValueError("public probe requires the pinned immutable Caddy path")
    # No Install section: resume is explicit only after checking the rebooted
    # gate and original account/certificate bytes. Native Caddy stays disabled.
    return f"""[Unit]
Description=Owned M3.11 public-CA dependency proof
Requires=lowerduckpond-restore-gate.service
After=network-online.target lowerduckpond-restore-gate.service
Wants=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
EnvironmentFile={INPUTS}/environment
Environment=XDG_CONFIG_HOME={STORAGE}/config
Environment=XDG_DATA_HOME={STORAGE}/data
Environment=SSL_CERT_FILE={INPUTS}/roots.pem
Environment=SSL_CERT_DIR={INPUTS}/empty-roots
BindReadOnlyPaths={INPUTS}/hosts:/etc/hosts
BindReadOnlyPaths={INPUTS}/resolv.conf:/etc/resolv.conf
BindReadOnlyPaths={RECOVERY}
ExecStartPre=!/usr/local/libexec/lowerduckpond/host-restore-gate --caddy
ExecStart={binary} run --config {INPUTS}/caddy.json
Restart=no
TimeoutStartSec=120s
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
NoNewPrivileges=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths={STORAGE}
UMask=0077
""".encode("ascii")
