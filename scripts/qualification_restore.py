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
MIN_READY_REQUESTS = 2


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


def source_idempotence_receipt(
    environment: dict[str, str], *, archived_prefix: bool
) -> dict[str, object]:
    from scripts.qualification_retirement import artifact_digest  # noqa: PLC0415

    source = inspect(environment, host_name(environment))
    return {
        "format": "lowerduckpond-restore-source-idempotence-v1",
        "run_id": environment[RUN_ENV],
        "source": {key: source[key] for key in ("id", "name", "owner", "image")},
        "artifact_sha256": artifact_digest(Path(environment[ARTIFACT_ENV])),
        "publication": True,
        "recovery": True,
        "rotation": archived_prefix,
        "changed": 0,
        "unreachable": 0,
        "failed": 0,
    }


def require_source_idempotence(
    environment: dict[str, str], *, archived_prefix: bool | None = None
) -> None:
    receipt = document(directory(environment).parent / "source-idempotence.json")
    rotation = receipt.get("rotation")
    if (
        not isinstance(rotation, bool)
        or any(type(receipt.get(key)) is not int for key in ("changed", "unreachable", "failed"))
        or any(receipt.get(key) is not True for key in ("publication", "recovery"))
        or (archived_prefix is not None and rotation is not archived_prefix)
        or receipt != source_idempotence_receipt(environment, archived_prefix=rotation)
    ):
        raise ValueError("source lacks its configured idempotence proof")


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
    current = create_stopped(environment, kind)
    identity = str(current["id"])
    private_document(root, f"{kind}.json", current)
    # The controlled ACME service starts directly after its fixed inputs are
    # copied. It needs neither systemd nor the destination's mount privileges.
    if kind == "destination":
        command(environment, "docker", "start", identity)
    return identity


def create_stopped(environment: dict[str, str], kind: str) -> dict[str, object]:
    """Allocate an empty owned container without starting PID 1 or copying inputs.

    The combined producer reserves the destination identity before its first
    phase. Its adoption path must prove source fencing before any startup.
    """
    host_name(environment)
    if kind not in KINDS or not environment.get(RUN_ENV):
        raise ValueError("unknown or unowned restore fixture resource")
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
    if (
        current.get("name") != "/" + name
        or current.get("image") != source["image"]
        or current.get("running") is not False
    ):
        raise ValueError("new restore fixture is not the expected stopped image")
    return current


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
    readiness = document(directory(environment) / "acme-readiness.json")
    baseline = readiness.get("acmeRequests")
    if (
        readiness.get("identity") != identity
        or type(baseline) is not int
        or baseline < MIN_READY_REQUESTS
    ):
        raise ValueError("unbound ACME readiness accounting")
    code = """
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:8056/status', timeout=10) as response:
    value = json.load(response)
assert value['fault'] == 'none'
assert value['deleted'] == value['created'] and value['remaining'] == 0
"""
    code += (
        f"assert value['created'] == 0 and value['acmeRequests'] == {baseline}\n"
        if negative
        else f"assert value['created'] >= 4 and value['acmeRequests'] > {baseline}\n"
    )
    command(environment, "docker", "exec", identity, "python3", "-I", "-B", "-c", code)


def paired_proof(environment: dict[str, str]) -> dict[str, str]:
    from scripts.qualification_retirement import local_proof  # noqa: PLC0415

    require_source_idempotence(environment)
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
