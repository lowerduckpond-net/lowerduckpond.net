"""Own both reconstruction hosts and the controlled ACME service as one fixture.

Source evidence remains fenced and intact until the reconstructed destination
has completed, ordinary destination accounting is settled, and storage absence
has been independently established. A failure never tears down these resources.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from scripts.qualification_case import private_document
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV, RUN_ENV, host_name
from scripts.qualification_probe import bounded_command, document

KINDS = ("destination", "acme")
GATE = "/var/lib/lowerduckpond/recovery/restore-gate.json"


def observations(environment: dict[str, str]) -> dict[str, object]:
    """Inspect only recorded container IDs; missing/changed hosts remain unknown."""
    result: dict[str, object] = {}
    for kind in ("source", *KINDS):
        try:
            receipt = document(directory(environment) / f"{kind}.json")
            identity = str(receipt["id"])
            current = inspect(environment, identity)
            if any(current[key] != receipt[key] for key in ("id", "name", "owner", "image")):
                raise ValueError("restore diagnostic ownership changed")
            raw = bounded_command(
                ["docker", "exec", "--interactive", identity, "/usr/bin/python3", "-I", "-B", "-"],
                timeout=20,
                environment=environment,
                stdin=Path(__file__).with_name("qualification_restore_probe.py").read_bytes(),
            )
            if raw is None:
                raise ValueError("restore diagnostic unavailable")
            result[kind] = json.loads(raw)
        except Exception:
            result[kind] = "unknown"
    return result


def directory(environment: dict[str, str]) -> Path:
    host_name(environment)
    if not environment.get(RUN_ENV):
        raise ValueError("reconstruction requires an owned fixture")
    return Path(environment[ARTIFACT_ENV]).parent.parent / "restore"


def command(
    environment: dict[str, str], *args: str, timeout: int = 60, stdin: bytes = b""
) -> bytes:
    result = bounded_command(list(args), environment=environment, timeout=timeout, stdin=stdin)
    if result is None:
        raise ValueError("owned reconstruction fixture command failed")
    return result


def inspect(environment: dict[str, str], identity: str) -> dict[str, object]:
    value: dict[str, object] = json.loads(
        command(
            environment,
            "docker",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"name":{{json .Name}},"owner":'
            '{{json (index .Config.Labels "lowerduckpond.qualification.run")}},'
            '"image":{{json .Image}},"running":{{json .State.Running}}}',
            identity,
        )
    )
    if (
        value.get("owner") != environment[RUN_ENV]
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("id"))) is None
    ):
        raise ValueError("restore fixture ownership changed")
    return value


def identities(environment: dict[str, str]) -> dict[str, str]:
    result = {}
    for kind in KINDS:
        receipt = document(directory(environment) / f"{kind}.json")
        identity = str(receipt.get("id"))
        current = inspect(environment, identity)
        expected_name = f"/ldp-m3-{environment[RUN_ENV]}-{kind}"
        if receipt.get("name") != expected_name or any(
            current[key] != receipt[key] for key in ("id", "name", "owner", "image")
        ):
            raise ValueError("restore fixture identity changed")
        result[kind] = identity
    return result


def create(environment: dict[str, str], kind: str) -> str:
    if kind not in KINDS:
        raise ValueError("unknown restore fixture resource")
    root = directory(environment)
    if (root / f"{kind}.json").exists():
        raise ValueError("a restore resource cannot be recreated")
    # A source fence is proved before docker creates any destination resource.
    source_fenced(environment)
    source = inspect(environment, environment[HOST_ENV])
    name = f"ldp-m3-{environment[RUN_ENV]}-{kind}"
    identity = (
        command(
            environment,
            "docker",
            "create",
            "--name",
            name,
            "--label",
            f"lowerduckpond.qualification.run={environment[RUN_ENV]}",
            *(
                ["--privileged"]
                if kind == "destination"
                else ["--init", "--stop-signal", "SIGTERM"]
            ),
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "--tmpfs",
            "/tmp",  # noqa: S108 - private container tmpfs mount
            *(["--publish", "0:22"] if kind == "destination" else []),
            str(source["image"]),
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            Path(__file__).with_name("qualification_restore_init.py").read_text(),
            kind,
        )
        .decode()
        .strip()
    )
    current = inspect(environment, identity)
    private_document(root, f"{kind}.json", current)
    # The controlled ACME service starts directly after its fixed inputs are
    # copied. It needs neither systemd nor the destination's mount privileges.
    if kind == "destination":
        command(environment, "docker", "start", identity)
    return identity


def source_fenced(environment: dict[str, str]) -> None:
    root = directory(environment)
    receipt = document(root / "source.json")
    current = inspect(environment, environment[HOST_ENV])
    if any(current[key] != receipt[key] for key in ("id", "name", "owner", "image")):
        raise ValueError("source host identity changed")
    gate = command(environment, "docker", "exec", str(current["id"]), "cat", GATE)
    if hashlib.sha256(gate).hexdigest() != receipt.get("gateSha256"):
        raise ValueError("source restore gate changed")
    # Fixed selected-artifact code; no operation is executed and no lease reset.
    code = """
import sys
from pathlib import Path
selected = Path('/opt/lowerduckpond/static-host-agent/current').resolve()
sys.path.insert(0, str(selected / 'site-packages'))
from lowerduckpond_static_host_agent.host_restore_services import require_quiescent
require_quiescent()
"""
    command(environment, "docker", "exec", str(current["id"]), "python3", "-I", "-B", "-c", code)


def acme_accounting(environment: dict[str, str], identity: str, *, negative: bool = False) -> None:
    code = """
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:8056/status', timeout=10) as response:
    value = json.load(response)
assert value['fault'] == 'none'
assert value['deleted'] == value['created'] and value['remaining'] == 0
"""
    code += (
        "assert value['created'] == 0 and value['acmeRequests'] == 0\n"
        if negative
        else "assert value['created'] >= 4 and value['acmeRequests'] > 0\n"
    )
    command(environment, "docker", "exec", identity, "python3", "-I", "-B", "-c", code)


def paired_proof(environment: dict[str, str]) -> dict[str, str]:
    from scripts.qualification_retirement import local_proof  # noqa: PLC0415

    pair = identities(environment)
    receipt = document(directory(environment) / "completed.json")
    if receipt.get("identities") != pair or receipt.get("status") != "passed":
        raise ValueError("restore scenario lacks completed paired accounting")
    source_fenced(environment)
    if receipt.get("outcome") == "blocked-as-expected":
        blocked_proof(environment, pair["destination"], receipt)
        acme_accounting(environment, pair["acme"], negative=True)
        return pair
    if local_proof(environment, pair["destination"]) != "quiescent-installed":
        raise ValueError("restored destination is not quiescent")
    status = json.loads(
        command(
            environment,
            "docker",
            "exec",
            pair["destination"],
            "/usr/local/sbin/restore-static-host",
            "--status",
        )
    )
    if status.get("phase") != "complete" or status.get("activationPending") is not False:
        raise ValueError("restored destination did not finish activation")
    acme_accounting(environment, pair["acme"])
    return pair


def installed_roots_digest(environment: dict[str, str], identity: str) -> str:
    code = """
import hashlib, json, os, stat
from pathlib import Path
entries = []
total = 0
for root in ('/etc/caddy', '/srv/lowerduckpond', '/var/lib/lowerduckpond/static'):
    for path in sorted((Path(root), *Path(root).rglob('*'))):
        info = path.lstat()
        value = [str(path), info.st_mode, info.st_uid, info.st_gid]
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            assert total <= 64 * 1024 * 1024
            value.append(hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISLNK(info.st_mode):
            value.append(os.readlink(path))
        else:
            assert stat.S_ISDIR(info.st_mode)
        entries.append(value)
        assert len(entries) <= 10000
print(hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest())
"""
    value = command(environment, "docker", "exec", identity, "python3", "-I", "-B", "-c", code)
    digest = value.decode().strip()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("invalid installed root digest")
    return digest


def blocked_proof(environment: dict[str, str], identity: str, receipt: dict[str, object]) -> None:
    if installed_roots_digest(environment, identity) != receipt.get("installedRootsSha256"):
        raise ValueError("negative restore modified installed authority")
    code = """
import json, sys
from pathlib import Path
selected = Path('/opt/lowerduckpond/static-host-agent/current').resolve()
sys.path.insert(0, str(selected / 'site-packages'))
from lowerduckpond_static_host_agent.host_restore_services import require_quiescent
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore, RestorePhase
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.host_restore_gate import GATE_SCHEMA
with RestoreStore.locked(Path('/var/lib/lowerduckpond/recovery')) as store:
    journal = store.read()
    assert journal is not None
    assert journal.phase in {RestorePhase.PREPARED, RestorePhase.RESTORED, RestorePhase.VALIDATED}
    gate = canonical_json_bytes({'schema': GATE_SCHEMA, 'restoreId': journal.restore_id})
    assert store.read_bytes('restore-gate.json') == gate
    require_quiescent()
print('blocked-as-expected')
"""
    command(environment, "docker", "exec", identity, "python3", "-I", "-B", "-c", code)


def remove_pair(environment: dict[str, str], expected: dict[str, str]) -> None:
    from scripts.qualification_restore_removal import remove_pair as resume  # noqa: PLC0415

    resume(environment, expected)
