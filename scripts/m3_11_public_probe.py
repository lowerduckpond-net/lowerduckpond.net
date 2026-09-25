"""Installed-fixture actions for one public-CA interruption/reboot attempt.

The controller runs this with the selected installed artifact on its owned
destination. This helper never emits a qualification report or retries a failed
transition. A retained incomplete action is diagnostic evidence, not success.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import re
import stat
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_activation import finish_public_ingress
from lowerduckpond_static_host_agent.host_restore_gate import (
    INGRESS,
    close_gate,
    gate_pending,
    ingress_record,
    open_gate,
    restore_admission,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_process import require_command
from lowerduckpond_static_host_agent.host_restore_tls import verify_cold_tls

from scripts import m3_11_public_caddy as policy

UNIT_PATH = Path("/etc/systemd/system") / policy.UNIT
DNS_UNIT = "restore-fixture-dns.service"
COORDINATOR = "lowerduckpond-host-restore.service"
_RECOVERABLE = {
    "restore_tls_peer_unavailable",
    "restore_tls_peer_unverified",
    "restore_tls_subjects_unavailable",
}


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(path: Path, *, owner: int = 0, maximum: int = policy.MAXIMUM_BYTES) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("public probe input is unsafe")
        raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)

        def identity(value: os.stat_result) -> tuple[int, int, int, int]:
            return value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

        if (
            len(raw) != before.st_size
            or identity(before) != identity(after)
            or identity(before) != identity(path.stat(follow_symlinks=False))
        ):
            raise ValueError("public probe input changed while reading")
        return raw


def _write(path: Path, raw: bytes, *, mode: int = 0o400, group: int = 0) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchown(stream.fileno(), 0, group)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _record(name: str, value: object) -> dict[str, object]:
    path = policy.INPUTS / (name + ".json")
    _write(path, policy.canonical(value))
    return {"sha256": _digest(_read(path)), "value": value}


def _document(name: str) -> dict[str, object]:
    raw = _read(policy.INPUTS / (name + ".json"))
    value = json.loads(raw)
    if not isinstance(value, dict) or raw != policy.canonical(value):
        raise ValueError("public probe record is not its original canonical document")
    return cast("dict[str, object]", value)


def _systemctl(*arguments: str) -> bytes:
    return require_command(
        ("/usr/bin/systemctl", *arguments), failure="public_probe_service_failed", timeout=120
    ).strip()


def _inactive(unit: str) -> None:
    if _systemctl("show", "--property=ActiveState", "--value", unit) != b"inactive":
        raise ValueError("public probe requires the original stopped service")


def _journal(store: RestoreStore) -> str:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise ValueError("public probe requires the genuine completed reconstruction")
    return _digest(journal.to_bytes())


def _fixture() -> None:
    if os.geteuid() != 0 or _read(Path("/run/systemd/container")).strip() != b"docker":
        raise ValueError("public probe is restricted to the owned Docker fixture")


def _guard(context_sha256: str) -> dict[str, object]:
    _fixture()
    marker = _document("original")
    if marker["context_sha256"] != context_sha256:
        raise ValueError("public probe belongs to another combined context")
    for name, digest in cast("dict[str, str]", marker["files"]).items():
        if _digest(_read(policy.INPUTS / name)) != digest:
            raise ValueError("public probe original inputs changed")
    binary = Path(str(marker["binary"]))
    if _digest(_read(binary, maximum=256 * policy.MAXIMUM_BYTES)) != marker["binary_sha256"]:
        raise ValueError("public probe selected Caddy binary changed")
    if _read(UNIT_PATH) != policy.service(str(binary)):
        raise ValueError("public probe service changed")
    roots = policy.INPUTS / "empty-roots"
    metadata = roots.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or any(roots.iterdir())
    ):
        raise ValueError("public probe acquired an additional certificate trust source")
    with RestoreStore.locked(policy.RECOVERY) as store:
        if _journal(store) != marker["journal_sha256"]:
            raise ValueError("public probe original restore journal changed")
    _inactive(COORDINATOR)
    _inactive("caddy.service")
    _inactive(DNS_UNIT)
    return marker


def _closed() -> None:
    with RestoreStore.locked(policy.RECOVERY) as store:
        if not gate_pending(store):
            raise ValueError("public probe lost its durable closed gate")
    if restore_admission() or not restore_admission(caddy=True):
        raise ValueError("public probe restore admission is inconsistent")
    require_command(
        ("/usr/sbin/nft", "list", "table", "inet", "lowerduckpond_restore"),
        failure="public_probe_gate_missing",
    )
    services.require_quiescent()


def install(value: dict[str, object]) -> dict[str, object]:
    """No public process starts here; retain the actual empty-store observation."""
    _fixture()
    if set(value) != {"context_sha256", "binary", "binary_sha256", "nonce", "files", "token"}:
        raise ValueError("public probe inputs are malformed")
    binary, nonce = str(value["binary"]), str(value["nonce"])
    unit, configuration = policy.service(binary), policy.configuration(nonce)
    token = value["token"]
    if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{40}", token) is None:
        raise ValueError("public probe requires its audited runtime DNS credential")
    for field in ("context_sha256", "binary_sha256"):
        if (
            not isinstance(value[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", str(value[field])) is None
        ):
            raise ValueError("public probe binding is malformed")
    if _digest(_read(Path(binary), maximum=256 * policy.MAXIMUM_BYTES)) != value["binary_sha256"]:
        raise ValueError("public probe Caddy differs from the original context")
    files = value["files"]
    if not isinstance(files, dict) or set(files) != {"roots.pem", "hosts", "resolv.conf"}:
        raise ValueError("public probe clean dependencies are incomplete")
    decoded = {name: base64.b64decode(content, validate=True) for name, content in files.items()}
    if any(not 0 < len(raw) <= policy.MAXIMUM_BYTES for raw in decoded.values()):
        raise ValueError("public probe dependency exceeds its bound")
    # These exclusively created paths latch partial setup failures. Never clean
    # and retry into a purported cold start within the same owned run.
    policy.INPUTS.mkdir(mode=0o750)
    account = pwd.getpwnam("caddy")
    os.chown(policy.INPUTS, 0, account.pw_gid)
    policy.STORAGE.mkdir(mode=0o700)
    os.chown(policy.STORAGE, account.pw_uid, account.pw_gid)
    (policy.INPUTS / "empty-roots").mkdir(mode=0o755)
    _systemctl("stop", COORDINATOR)
    if _systemctl("is-enabled", "caddy.service", DNS_UNIT) != b"enabled\nenabled":
        raise ValueError("public probe requires the restored native service enablement")
    with RestoreStore.locked(policy.RECOVERY) as store:
        journal_sha256 = _journal(store)
        journal = store.read()
        assert journal is not None  # noqa: S101 - _journal requires the completed journal
        close_gate(store, journal.restore_id)
        services.close_public_ingress()
        services.quiesce_host()
    _systemctl("disable", "caddy.service", DNS_UNIT)
    _systemctl("stop", DNS_UNIT)
    require_command(
        ("/usr/sbin/nft", "destroy", "table", "ip", "restore_fixture_dns"),
        failure="public_probe_controlled_dns_remove_failed",
    )
    decoded["caddy.json"] = configuration
    decoded["environment"] = f"CLOUDFLARE_API_TOKEN={token}\n".encode("ascii")
    for name, raw in decoded.items():
        _write(
            policy.INPUTS / name,
            raw,
            mode=0o400 if name == "environment" else 0o440,
            group=account.pw_gid,
        )
    _write(UNIT_PATH, unit, mode=0o444)
    _systemctl("daemon-reload")
    if any(policy.STORAGE.iterdir()):
        raise ValueError("public probe certificate/account storage is not initially empty")
    marker = {
        "context_sha256": value["context_sha256"],
        "binary": binary,
        "binary_sha256": value["binary_sha256"],
        "nonce": nonce,
        "files": {name: _digest(raw) for name, raw in decoded.items()},
        "journal_sha256": journal_sha256,
    }
    result = _record("original", marker)
    _guard(str(value["context_sha256"]))
    _closed()
    return result


def _inventory() -> dict[str, str]:
    """Only while stopped; preserve all account and certificate bytes over reboot."""
    _inactive(policy.UNIT)
    owner = pwd.getpwnam("caddy").pw_uid
    result = {}
    entries = 0
    for parent, directories, files in os.walk(policy.STORAGE, followlinks=False):
        for name in sorted((*directories, *files)):
            entries += 1
            path = Path(parent) / name
            metadata = path.lstat()
            if entries > 512 or metadata.st_uid != owner or stat.S_ISLNK(metadata.st_mode):  # noqa: PLR2004 - bounded disposable Caddy store
                raise ValueError("public probe storage inventory is unsafe or exceeds its bound")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            result[str(path.relative_to(policy.STORAGE))] = _digest(_read(path, owner=owner))
    return result


def _tls(marker: dict[str, object]) -> dict[str, object]:
    account = pwd.getpwnam("caddy")
    return verify_cold_tls(
        policy.STORAGE / "certificates",
        issuer=policy.ISSUER_STORAGE,
        subjects=policy.disposable_subjects(str(marker["nonce"])),
        trust=policy.INPUTS / "roots.pem",
        owner=account.pw_uid,
        group=account.pw_gid,
    )


def ready(context_sha256: str) -> dict[str, object]:
    marker = _guard(context_sha256)
    _closed()
    try:
        return {"ready": True, "tls": _tls(marker)}
    except FileNotFoundError:
        return {"ready": False}
    except HostRestoreError as error:
        if str(error) not in _RECOVERABLE:
            raise
        return {"ready": False}


def start(context_sha256: str, *, resume: bool = False) -> dict[str, object]:
    _guard(context_sha256)
    _closed()
    if resume and _document("rebooted")["storage"] != _inventory():
        raise ValueError("public probe account/certificate bytes changed before resume")
    _record(
        "resuming" if resume else "starting",
        {"pid_one": Path("/proc/1/stat").read_text().split()[21]},
    )
    _systemctl("start", policy.UNIT)
    return {"started": True}


def interrupt(context_sha256: str) -> dict[str, object]:
    # The controller independently observed an actual DNS challenge before this
    # call. Require issuance still incomplete; a completed run cannot be relabeled
    # as an interruption, even if the observation raced the CA response.
    if ready(context_sha256)["ready"]:
        raise ValueError("public issuance already completed before its interruption")
    _document("starting")
    _record("interrupting", {"context_sha256": context_sha256})
    _systemctl("stop", policy.UNIT)
    inventory = _inventory()
    if not any(name.startswith("acme/") and name.endswith(".key") for name in inventory):
        raise ValueError("public interruption did not retain an actual ACME account")
    return _record(
        "interrupted",
        {"storage": inventory, "pid_one": Path("/proc/1/stat").read_text().split()[21]},
    )


def rebooted(context_sha256: str) -> dict[str, object]:
    _guard(context_sha256)
    _closed()
    before = _document("interrupted")
    pid_one = Path("/proc/1/stat").read_text().split()[21]
    if before["pid_one"] == pid_one or before["storage"] != _inventory():
        raise ValueError("public reboot did not preserve the stopped account/certificate bytes")
    return _record("rebooted", {"pid_one": pid_one, "storage": before["storage"]})


def open_verified(context_sha256: str, expected: dict[str, object]) -> dict[str, object]:
    marker = _guard(context_sha256)
    _document("resuming")
    _closed()
    with RestoreStore.locked(policy.RECOVERY) as store:
        actual = _tls(marker)
        if actual != expected or _journal(store) != marker["journal_sha256"]:
            raise ValueError("public TLS or original restore provenance changed before opening")
        _record("verified", actual)
        store.immutable(INGRESS[0], ingress_record(store))
        open_gate(store)
        finish_public_ingress(store)
    if not restore_admission():
        raise ValueError("public probe failed to restore ordinary admission")
    return _record("opened", {"tls_sha256": _digest(policy.canonical(actual))})


def restore_native(context_sha256: str, *, audit_rotation: bool) -> dict[str, object]:
    marker = _guard(context_sha256)
    _document("opened")
    _record("restoring", {"context_sha256": context_sha256})
    _systemctl("stop", policy.UNIT)
    _systemctl("enable", "--now", DNS_UNIT)
    services.start_caddy()
    with RestoreStore.locked(policy.RECOVERY) as store:
        if _journal(store) != marker["journal_sha256"]:
            raise ValueError("public proof changed the original completed restore")
        journal = store.read()
        assert journal is not None  # noqa: S101 - completed journal checked above
        services.SCHEDULES_READY.parent.mkdir(mode=0o700, exist_ok=True)
        with DurableDirectory.open(
            services.SCHEDULES_READY.parent, expected_owner=0, expected_directory_mode=0o700
        ) as directory:
            directory.replace((services.SCHEDULES_READY.name,), journal.to_bytes(), mode=0o600)
        services.restore_schedules(audit_rotation=audit_rotation)
    return _record("restored", {"journal_sha256": marker["journal_sha256"]})


def stop_failed(context_sha256: str) -> dict[str, object]:
    """Stop further issuance and retain the closed original fixture on failure."""
    _fixture()
    marker = _document("original")
    if marker["context_sha256"] != context_sha256 or _read(UNIT_PATH) != policy.service(
        str(marker["binary"])
    ):
        raise ValueError("failed public probe no longer has its original owned inputs")
    with RestoreStore.locked(policy.RECOVERY) as store:
        if _journal(store) != marker["journal_sha256"]:
            raise ValueError("failed public probe lost its original reconstruction")
        journal = store.read()
        assert journal is not None  # noqa: S101 - completed journal checked above
        close_gate(store, journal.restore_id)
        services.close_public_ingress()
        services.quiesce_host()
        _systemctl("stop", policy.UNIT)
    return _record("failed", {"context_sha256": context_sha256})
