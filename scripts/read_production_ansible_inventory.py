#!/usr/bin/env python3
"""Read the exact production Ansible transport identity from OpenTofu output."""

from __future__ import annotations

import ipaddress
import json
import sys
from typing import NoReturn


def _fail() -> NoReturn:
    raise SystemExit("Production state returned an invalid Ansible inventory.")


def main() -> int:
    try:
        inventory = json.load(sys.stdin)
    except UnicodeError, json.JSONDecodeError:
        _fail()
    if not isinstance(inventory, dict) or set(inventory) != {"all"}:
        _fail()
    all_group = inventory["all"]
    if not isinstance(all_group, dict) or set(all_group) != {"hosts"}:
        _fail()
    hosts = all_group["hosts"]
    if not isinstance(hosts, dict) or set(hosts) != {"lowerduckpond_production_01"}:
        _fail()
    host = hosts["lowerduckpond_production_01"]
    if not isinstance(host, dict) or set(host) != {
        "ansible_host",
        "ansible_user",
        "private_ip",
    }:
        _fail()
    if host["ansible_user"] != "ldp-admin":
        _fail()
    try:
        public_address = ipaddress.ip_address(host["ansible_host"])
        private_address = ipaddress.ip_address(host["private_ip"])
    except TypeError, ValueError:
        _fail()
    if (
        not isinstance(public_address, ipaddress.IPv4Address)
        or not public_address.is_global
        or not isinstance(private_address, ipaddress.IPv4Address)
        or not private_address.is_private
        or private_address == public_address
    ):
        _fail()
    print(public_address)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
