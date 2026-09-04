"""Bounded, crash-safe local hash-chained audit segments."""

from __future__ import annotations

import os
import re
import stat
from copy import deepcopy
from dataclasses import dataclass
from typing import Final

from lowerduckpond_static_contracts import (
    MAX_CANONICAL_BYTES,
    ContractError,
    ContractKind,
    audit_entry_digest,
    canonical_json_bytes,
    decode_contract,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.durable import (
    DurableDirectory,
    FailureHook,
    validate_state_directory,
)
from lowerduckpond_static_host_agent.state_inventory import (
    DEFAULT_STATE_INVENTORY_LIMITS,
)

MEBIBYTE: Final = 1024 * 1024
_INITIAL_MAXIMUM_SEGMENT_BYTES: Final = 8 * MEBIBYTE
_INITIAL_MAXIMUM_ORDINARY_BYTES: Final = 128 * MEBIBYTE
_INITIAL_MAXIMUM_ADMINISTRATOR_RESERVE_BYTES: Final = 8 * MEBIBYTE
_SEGMENT_PATTERN: Final = re.compile(r"segment-([0-9]{20})\.jsonl", flags=re.ASCII)
_BLOCK_BYTES: Final = 512
_DIRECTORY_SCAN_MARGIN: Final = 1
_TENANT_STATE_TRANSITIONS: Final = frozenset(
    {
        "create",
        "deploy",
        "rollback",
        "suspend",
        "resume",
        "rename",
        "import",
        "archive",
        "restore",
        "delete",
        "reconcile",
    }
)
_DEPLOYMENT_EVIDENCE_OPERATIONS: Final = frozenset(
    {
        "deploy",
        "rollback",
        "suspend",
        "resume",
        "export",
        "import",
        "archive",
        "restore",
    }
)


class AuditError(RuntimeError):
    """The local audit chain is invalid or cannot be advanced."""


class AuditCapacityError(AuditError):
    """An audit append would consume protected local capacity."""


@dataclass(frozen=True, slots=True)
class AuditLimits:
    """Initial M3 local segment and ordinary/administrator ceilings."""

    maximum_segment_bytes: int = _INITIAL_MAXIMUM_SEGMENT_BYTES
    maximum_ordinary_bytes: int = _INITIAL_MAXIMUM_ORDINARY_BYTES
    maximum_administrator_reserve_bytes: int = _INITIAL_MAXIMUM_ADMINISTRATOR_RESERVE_BYTES

    def __post_init__(self) -> None:
        values = (
            self.maximum_segment_bytes,
            self.maximum_ordinary_bytes,
            self.maximum_administrator_reserve_bytes,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("audit limits must be nonnegative integers")
        if self.maximum_segment_bytes < MAX_CANONICAL_BYTES:
            raise ValueError("audit segments must admit one maximum canonical entry")
        if (
            self.maximum_segment_bytes > _INITIAL_MAXIMUM_SEGMENT_BYTES
            or self.maximum_ordinary_bytes > _INITIAL_MAXIMUM_ORDINARY_BYTES
            or self.maximum_administrator_reserve_bytes
            > _INITIAL_MAXIMUM_ADMINISTRATOR_RESERVE_BYTES
        ):
            raise ValueError("audit limits cannot weaken the committed M3 boundaries")

    @property
    def maximum_administrator_bytes(self) -> int:
        return self.maximum_ordinary_bytes + self.maximum_administrator_reserve_bytes

    @property
    def maximum_segments(self) -> int:
        # Every accepted nonempty segment must account for at least one POSIX
        # st_blocks unit. This bounds sparse packing without assuming that
        # variable-sized entries fill every segment to its byte ceiling.
        return self.maximum_administrator_bytes // _BLOCK_BYTES


@dataclass(frozen=True, slots=True)
class AuditState:
    """Verified chain position and local allocation."""

    entry_count: int
    segment_count: int
    allocated_bytes: int
    terminal_digest: dict[str, str] | None


@dataclass(frozen=True, slots=True)
class AuditCorrelationSnapshot:
    """One bounded correlation lookup paired with its exact chain state."""

    state: AuditState
    entry: dict[str, object] | None
    previous_tenant_state_transition: dict[str, object] | None
    has_later_tenant_state_transition: bool


@dataclass(frozen=True, slots=True)
class AuditTransition:
    """One bounded projection of a successful tenant-state audit entry."""

    sequence: int
    correlation_id: str
    tenant_id: str
    operation: str
    result_digest: dict[str, object]


@dataclass(frozen=True, slots=True)
class AuditAppend:
    """The committed digest and verified resulting chain state."""

    entry_digest: dict[str, str]
    state: AuditState


@dataclass(frozen=True, slots=True)
class _Segment:
    number: int
    name: str
    data: bytes
    allocated_bytes: int


DEFAULT_AUDIT_LIMITS: Final = AuditLimits()


def inspect_audit(
    root: DurableDirectory,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
) -> AuditState:
    """Validate every local segment and return the exact terminal chain state."""

    audit_directory = root.open_descendant(("audit",))
    try:
        segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
    finally:
        audit_directory.close()
    return _validate_chain(segments, limits=limits)


def tenant_has_deployment_audit_history(  # noqa: PLR0913 - storage contract is explicit
    root: DurableDirectory,
    tenant_id: object,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
) -> bool:
    """Prove whether the complete audit chain records a deployed tenant."""

    canonical_tenant_id = validate_uuid7(tenant_id)
    audit_directory = root.open_descendant(("audit",))
    try:
        segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
    finally:
        audit_directory.close()
    return _tenant_audit_history(
        segments,
        limits=limits,
        tenant_id=canonical_tenant_id,
    )[1]


def deployment_audit_history_tenant_ids(  # noqa: PLR0913
    root: DurableDirectory,
    tenant_ids: tuple[str, ...],
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
) -> frozenset[str]:
    """Validate the chain once and project deployment history for bounded tenants."""

    canonical_ids = tuple(validate_uuid7(tenant_id) for tenant_id in tenant_ids)
    if canonical_ids != tuple(sorted(set(canonical_ids))):
        raise ValueError("deployment-history tenant IDs must be sorted and unique")
    if len(canonical_ids) > DEFAULT_STATE_INVENTORY_LIMITS.maximum_tenants:
        raise ValueError("deployment-history tenant IDs exceed the tenant boundary")
    audit_directory = root.open_descendant(("audit",))
    try:
        segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
    finally:
        audit_directory.close()
    matches: set[str] = set()
    _validate_chain_records(
        segments,
        limits=limits,
        correlation_id=None,
        history_tenant_id=None,
        deployment_history_candidates=frozenset(canonical_ids),
        deployment_history_matches=matches,
    )
    return frozenset(matches)


def tenant_has_identity_audit_history(  # noqa: PLR0913 - storage contract is explicit
    root: DurableDirectory,
    tenant_id: object,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
) -> bool:
    """Prove whether the complete audit chain records a tenant identity."""

    canonical_tenant_id = validate_uuid7(tenant_id)
    audit_directory = root.open_descendant(("audit",))
    try:
        segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
    finally:
        audit_directory.close()
    return _tenant_audit_history(
        segments,
        limits=limits,
        tenant_id=canonical_tenant_id,
    )[0]


def inspect_audit_correlation(  # noqa: PLR0913 - keep every audit boundary explicit
    root: DurableDirectory,
    correlation_id: object,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
) -> AuditCorrelationSnapshot:
    """Validate the complete chain and return at most one exact correlation."""

    canonical_correlation_id = validate_uuid7(correlation_id)
    audit_directory = root.open_descendant(("audit",))
    try:
        segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
    finally:
        audit_directory.close()
    (
        state,
        entry,
        previous_tenant_state_transition,
        has_later_tenant_state_transition,
        _has_tenant_history,
        _has_deployment_history,
    ) = _validate_chain_records(
        segments,
        limits=limits,
        correlation_id=canonical_correlation_id,
        history_tenant_id=None,
    )
    return AuditCorrelationSnapshot(
        state=state,
        entry=entry,
        previous_tenant_state_transition=previous_tenant_state_transition,
        has_later_tenant_state_transition=has_later_tenant_state_transition,
    )


def inspect_later_audit_transitions(  # noqa: PLR0913 - storage contract is explicit
    root: DurableDirectory,
    correlation_id: object,
    *,
    maximum_transitions: int,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
) -> tuple[AuditTransition, ...]:
    """Return a capped slim projection after one verified correlation."""

    if (
        type(maximum_transitions) is not int
        or maximum_transitions < 0
        or maximum_transitions > DEFAULT_STATE_INVENTORY_LIMITS.maximum_authorization_records
    ):
        raise ValueError("later audit transition limit is outside the committed boundary")
    canonical_correlation_id = validate_uuid7(correlation_id)
    audit_directory = root.open_descendant(("audit",))
    try:
        segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
    finally:
        audit_directory.close()
    (
        _state,
        matching_entry,
        _previous_tenant_state_transition,
        _has_later_tenant_state_transition,
        _has_tenant_history,
        _has_deployment_history,
    ) = _validate_chain_records(
        segments,
        limits=limits,
        correlation_id=canonical_correlation_id,
        history_tenant_id=None,
    )
    return _later_audit_transitions(
        segments,
        matching_entry=matching_entry,
        maximum_transitions=maximum_transitions,
    )


def append_audit(  # noqa: PLR0913 - keep every security boundary explicit
    root: DurableDirectory,
    document: dict[str, object],
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    administrator: bool,
    limits: AuditLimits = DEFAULT_AUDIT_LIMITS,
    failure_hook: FailureHook | None = None,
) -> AuditAppend:
    """Atomically append one correctly chained entry through a segment generation."""

    if type(document) is not dict:
        raise TypeError("audit entry must be a contract object")
    candidate = deepcopy(document)
    validate_contract(candidate, expected_kind=ContractKind.AUDIT_ENTRY)
    canonical = canonical_json_bytes(candidate)

    audit_directory = root.open_descendant(("audit",))
    try:
        segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
        state = _validate_chain(segments, limits=limits)
        if candidate["sequence"] != state.entry_count:
            raise AuditError("audit sequence does not extend the verified chain")
        if candidate["previousEntryDigest"] != state.terminal_digest:
            raise AuditError("audit predecessor does not match the verified chain")

        if segments and len(segments[-1].data) + len(canonical) <= limits.maximum_segment_bytes:
            target = segments[-1]
            replacement = target.data + canonical
            projected = (
                state.allocated_bytes
                + audit_directory.allocation_upper_bound(len(replacement))
                + audit_directory.namespace_allocation_upper_bound(1)
            )
            _admit_capacity(projected, administrator=administrator, limits=limits)
            audit_directory.replace(
                (target.name,),
                replacement,
                mode=expected_record_mode,
                failure_hook=failure_hook,
            )
        else:
            next_number = len(segments)
            if next_number >= limits.maximum_segments:
                raise AuditCapacityError("audit segment count is exhausted")
            projected = (
                state.allocated_bytes
                + audit_directory.allocation_upper_bound(len(canonical))
                + audit_directory.namespace_allocation_upper_bound(1)
            )
            _admit_capacity(projected, administrator=administrator, limits=limits)
            audit_directory.create_immutable(
                (_segment_name(next_number),),
                canonical,
                mode=expected_record_mode,
                failure_hook=failure_hook,
            )

        resulting_segments = _read_segments(
            audit_directory,
            expected_owner=expected_owner,
            expected_directory_mode=expected_directory_mode,
            expected_record_mode=expected_record_mode,
            limits=limits,
        )
        resulting_state = _validate_chain(resulting_segments, limits=limits)
        _admit_capacity(
            resulting_state.allocated_bytes,
            administrator=administrator,
            limits=limits,
        )
    finally:
        audit_directory.close()

    digest = audit_entry_digest(candidate).to_dict()
    if resulting_state.terminal_digest != digest:  # pragma: no cover - defensive
        raise AuditError("audit append did not produce the expected terminal digest")
    return AuditAppend(entry_digest=digest, state=resulting_state)


def _read_segments(
    directory: DurableDirectory,
    *,
    expected_owner: int,
    expected_directory_mode: int,
    expected_record_mode: int,
    limits: AuditLimits,
) -> list[_Segment]:
    directory.remove_abandoned_publication_temporaries(
        expected_owner=expected_owner,
        expected_mode=expected_record_mode,
        maximum_entries=limits.maximum_segments + _DIRECTORY_SCAN_MARGIN,
    )
    descriptor = directory.duplicate_descriptor()
    try:
        before = validate_state_directory(
            descriptor,
            expected_owner=expected_owner,
            expected_mode=expected_directory_mode,
        )
        names: list[str] = []
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) > limits.maximum_segments:
                    raise AuditCapacityError("audit directory exceeds its segment ceiling")
        names.sort()
        after = validate_state_directory(
            descriptor,
            expected_owner=expected_owner,
            expected_mode=expected_directory_mode,
        )
        if _metadata_generation(before) != _metadata_generation(after):
            raise AuditError("audit directory changed while it was inventoried")

        segments: list[_Segment] = []
        for expected_number, name in enumerate(names):
            match = _SEGMENT_PATTERN.fullmatch(name)
            if match is None or int(match.group(1)) != expected_number:
                raise AuditError("audit segment names are not one contiguous sequence")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            _validate_segment_metadata(
                metadata,
                expected_owner=expected_owner,
                expected_mode=expected_record_mode,
                maximum_bytes=limits.maximum_segment_bytes,
            )
            data = directory.read_regular(
                (name,),
                expected_owner=expected_owner,
                expected_mode=expected_record_mode,
                maximum_bytes=limits.maximum_segment_bytes,
            )
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _metadata_generation(metadata) != _metadata_generation(current):
                raise AuditError("audit segment changed while it was read")
            segments.append(
                _Segment(
                    number=expected_number,
                    name=name,
                    data=data,
                    allocated_bytes=metadata.st_blocks * _BLOCK_BYTES,
                )
            )
        final_names: list[str] = []
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                final_names.append(entry.name)
                if len(final_names) > limits.maximum_segments:
                    raise AuditCapacityError("audit directory exceeds its segment ceiling")
        final_names.sort()
        final = validate_state_directory(
            descriptor,
            expected_owner=expected_owner,
            expected_mode=expected_directory_mode,
        )
        if final_names != names or _metadata_generation(after) != _metadata_generation(final):
            raise AuditError("audit directory changed while its segments were read")
        return segments
    finally:
        os.close(descriptor)


def _validate_chain(
    segments: list[_Segment],
    *,
    limits: AuditLimits,
) -> AuditState:
    (
        state,
        _entry,
        _previous_tenant_state_transition,
        _has_later_tenant_state_transition,
        _has_tenant_history,
        _has_deployment_history,
    ) = _validate_chain_records(
        segments,
        limits=limits,
        correlation_id=None,
        history_tenant_id=None,
    )
    return state


def _tenant_audit_history(
    segments: list[_Segment],
    *,
    limits: AuditLimits,
    tenant_id: str,
) -> tuple[bool, bool]:
    """Validate the chain and inspect one tenant without retaining all identities."""

    (
        _state,
        _entry,
        _previous_tenant_state_transition,
        _has_later_tenant_state_transition,
        has_tenant_history,
        has_deployment_history,
    ) = _validate_chain_records(
        segments,
        limits=limits,
        correlation_id=None,
        history_tenant_id=tenant_id,
    )
    return has_tenant_history, has_deployment_history


def _validate_chain_records(  # noqa: PLR0912,PLR0913 - one bounded validation pass
    segments: list[_Segment],
    *,
    limits: AuditLimits,
    correlation_id: str | None,
    history_tenant_id: str | None,
    deployment_history_candidates: frozenset[str] | None = None,
    deployment_history_matches: set[str] | None = None,
) -> tuple[
    AuditState,
    dict[str, object] | None,
    dict[str, object] | None,
    bool,
    bool,
    bool,
]:
    if (deployment_history_candidates is None) != (deployment_history_matches is None):
        raise ValueError("deployment-history projection requires candidates and matches")
    sequence = 0
    terminal: dict[str, str] | None = None
    allocated = 0
    previous_segment_bytes: int | None = None
    matching_entry: dict[str, object] | None = None
    has_later_tenant_state_transition = False
    has_tenant_history = False
    has_deployment_history = False
    for segment in segments:
        if not segment.data or not segment.data.endswith(b"\n"):
            raise AuditError("audit segment is not nonempty canonical JSON lines")
        allocated += segment.allocated_bytes
        lines = segment.data.splitlines(keepends=True)
        if (
            previous_segment_bytes is not None
            and previous_segment_bytes + len(lines[0]) <= limits.maximum_segment_bytes
        ):
            raise AuditError("audit segment rotation is not canonically packed")
        for line in lines:
            if len(line) > MAX_CANONICAL_BYTES:
                raise AuditError("audit entry exceeds its canonical byte ceiling")
            try:
                document = decode_contract(
                    line,
                    expected_kind=ContractKind.AUDIT_ENTRY,
                    maximum_raw_bytes=MAX_CANONICAL_BYTES,
                )
            except ContractError as error:
                raise AuditError("audit segment contains an invalid entry") from error
            if canonical_json_bytes(document) != line:
                raise AuditError("audit entry is not its exact canonical representation")
            if document["sequence"] != sequence:
                raise AuditError("audit entry sequence is not contiguous")
            if document["previousEntryDigest"] != terminal:
                raise AuditError("audit entry predecessor breaks the chain")
            if correlation_id is not None and document["correlationId"] == correlation_id:
                if matching_entry is not None:
                    raise AuditError("audit correlation appears multiple times")
                matching_entry = document
            has_later_tenant_state_transition = (
                has_later_tenant_state_transition
                or _is_later_tenant_state_transition(matching_entry, document)
            )
            tenant_id = document["tenantId"]
            operation = document["operation"]
            deletion_evidence = document.get("deletionEvidence")
            if (
                tenant_id == history_tenant_id
                and document["resultStatus"] == "succeeded"
                and operation in _TENANT_STATE_TRANSITIONS
            ):
                has_tenant_history = True
            deployment_evidence = document["resultStatus"] == "succeeded" and (
                operation in _DEPLOYMENT_EVIDENCE_OPERATIONS
                or (
                    operation == "delete"
                    and type(deletion_evidence) is dict
                    and deletion_evidence.get("mode") != "never-deployed"
                )
            )
            if tenant_id == history_tenant_id and deployment_evidence:
                has_deployment_history = True
            if (
                deployment_evidence
                and deployment_history_candidates is not None
                and deployment_history_matches is not None
                and tenant_id in deployment_history_candidates
            ):
                deployment_history_matches.add(tenant_id)
            terminal = audit_entry_digest(document).to_dict()
            sequence += 1
        previous_segment_bytes = len(segment.data)
    if allocated > limits.maximum_administrator_bytes:
        raise AuditCapacityError("audit allocation exceeds its absolute ceiling")
    previous_tenant_state_transition = _previous_tenant_state_transition(
        segments,
        matching_entry,
    )
    return (
        AuditState(
            entry_count=sequence,
            segment_count=len(segments),
            allocated_bytes=allocated,
            terminal_digest=terminal,
        ),
        matching_entry,
        previous_tenant_state_transition,
        has_later_tenant_state_transition,
        has_tenant_history,
        has_deployment_history,
    )


def _previous_tenant_state_transition(
    segments: list[_Segment],
    matching_entry: dict[str, object] | None,
) -> dict[str, object] | None:
    """Find one predecessor without retaining a map of every tenant identity."""

    if matching_entry is None or type(matching_entry["tenantId"]) is not str:
        return None
    tenant_id = matching_entry["tenantId"]
    matching_sequence = matching_entry["sequence"]
    previous: dict[str, object] | None = None
    for segment in segments:
        for line in segment.data.splitlines(keepends=True):
            document = decode_contract(
                line,
                expected_kind=ContractKind.AUDIT_ENTRY,
                maximum_raw_bytes=MAX_CANONICAL_BYTES,
            )
            if document["sequence"] == matching_sequence:
                return previous
            if (
                document["tenantId"] == tenant_id
                and document["resultStatus"] == "succeeded"
                and document["operation"] in _TENANT_STATE_TRANSITIONS
            ):
                previous = document
    return previous


def _later_audit_transitions(
    segments: list[_Segment],
    *,
    matching_entry: dict[str, object] | None,
    maximum_transitions: int,
) -> tuple[AuditTransition, ...]:
    """Project only fixed-size transition authority, never complete entries."""

    if matching_entry is None:
        return ()
    matching_sequence = matching_entry["sequence"]
    if type(matching_sequence) is not int:  # pragma: no cover - schema validation proves this
        raise AuditError("matching audit sequence is malformed")
    transitions: list[AuditTransition] = []
    transition_correlations: set[str] = set()
    for segment in segments:
        for line in segment.data.splitlines(keepends=True):
            document = decode_contract(
                line,
                expected_kind=ContractKind.AUDIT_ENTRY,
                maximum_raw_bytes=MAX_CANONICAL_BYTES,
            )
            sequence = document["sequence"]
            correlation_id = document["correlationId"]
            if type(sequence) is not int or type(correlation_id) is not str:
                raise AuditError("audit transition identity is malformed")
            if sequence <= matching_sequence:
                continue
            tenant_id = document["tenantId"]
            operation = document["operation"]
            if (
                type(tenant_id) is not str
                or type(operation) is not str
                or document["resultStatus"] != "succeeded"
                or operation not in _TENANT_STATE_TRANSITIONS
            ):
                continue
            if correlation_id in transition_correlations:
                raise AuditError("later audit transition correlation appears multiple times")
            if len(transitions) >= maximum_transitions:
                raise AuditCapacityError("later audit transitions exceed their result bound")
            result_digest = document["resultDigest"]
            if type(result_digest) is not dict:  # pragma: no cover - schema validation proves this
                raise AuditError("audit result digest is malformed")
            transitions.append(
                AuditTransition(
                    sequence=sequence,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    operation=operation,
                    result_digest=dict(result_digest),
                )
            )
            transition_correlations.add(correlation_id)
    return tuple(transitions)


def _is_later_tenant_state_transition(
    matching_entry: dict[str, object] | None,
    candidate: dict[str, object],
) -> bool:
    return (
        matching_entry is not None
        and candidate["sequence"] != matching_entry["sequence"]
        and matching_entry["tenantId"] is not None
        and candidate["tenantId"] == matching_entry["tenantId"]
        and candidate["resultStatus"] == "succeeded"
        and candidate["operation"] in _TENANT_STATE_TRANSITIONS
    )


def _validate_segment_metadata(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_mode: int,
    maximum_bytes: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_nlink != 1
        or metadata.st_size > maximum_bytes
        or metadata.st_blocks <= 0
    ):
        raise AuditError("audit segment has an unsafe inode shape")


def _admit_capacity(
    projected_bytes: int,
    *,
    administrator: bool,
    limits: AuditLimits,
) -> None:
    ceiling = limits.maximum_administrator_bytes if administrator else limits.maximum_ordinary_bytes
    if projected_bytes > ceiling:
        raise AuditCapacityError("audit append would consume protected capacity")


def _segment_name(number: int) -> str:
    return f"segment-{number:020d}.jsonl"


def _metadata_generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_blocks,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
