"""Bounded discovery and revision-safe recovery planning for durable intents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from lowerduckpond_static_contracts import ContractKind

from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)
from lowerduckpond_static_host_agent.state_inventory import (
    DEFAULT_INTENT_INVENTORY_LIMITS,
    IntentInventoryLimits,
)

_REMOTE_INTENT_KINDS: Final = {
    ContractKind.ARCHIVE_CONSTRUCTION_INTENT,
    ContractKind.ARCHIVE_RETIREMENT_INTENT,
}


class IntentDiscoveryError(RuntimeError):
    """Active intents do not form one unambiguous recoverable operation."""


@dataclass(frozen=True, slots=True)
class DiscoveredIntent:
    """One validated intent path and its exact recovery revision."""

    path: StateRecordPath
    record: StoredContract

    @property
    def kind(self) -> ContractKind:
        return self.path.contract_kind


@dataclass(frozen=True, slots=True)
class IntentRecoveryPlan:
    """Stable intents in the only order in which recovery may inspect them."""

    intents: tuple[DiscoveredIntent, ...]
    recovery_order: tuple[StateRecordPath, ...]


class IntentDiscovery:
    """Discover active intents without guessing authority from external state."""

    def __init__(
        self,
        repository: StateRepository,
        *,
        limits: IntentInventoryLimits = DEFAULT_INTENT_INVENTORY_LIMITS,
    ) -> None:
        self._repository = repository
        self._limits = limits

    def discover(self, *, blocking: bool = False) -> IntentRecoveryPlan:
        """Return one stable, relationship-checked recovery plan."""

        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=blocking,
        ) as transaction:
            before = transaction.measure_intent_records(limits=self._limits)
            intents = tuple(
                DiscoveredIntent(*transaction.read_intent(intent_id))
                for intent_id in before.intent_ids
            )
            after = transaction.measure_intent_records(limits=self._limits)
            if before != after:
                raise IntentDiscoveryError("intent store changed during recovery discovery")
            return _recovery_plan(intents)


def _recovery_plan(intents: tuple[DiscoveredIntent, ...]) -> IntentRecoveryPlan:
    by_kind: dict[ContractKind, DiscoveredIntent] = {}
    for intent in intents:
        if intent.kind in by_kind:
            raise IntentDiscoveryError("multiple active intents have the same authority kind")
        by_kind[intent.kind] = intent

    remote = tuple(intent for intent in intents if intent.kind in _REMOTE_INTENT_KINDS)
    if len(remote) > 1:
        raise IntentDiscoveryError("construction and retirement intents cannot coexist")
    transaction = by_kind.get(ContractKind.TRANSACTION_INTENT)
    order: tuple[StateRecordPath, ...]
    if transaction is not None and remote:
        _validate_relationship(transaction, remote[0])
        order = (transaction.path, remote[0].path)
    elif transaction is not None:
        order = (transaction.path,)
    elif remote:
        order = (remote[0].path,)
    else:
        order = ()
    return IntentRecoveryPlan(intents=intents, recovery_order=order)


def _validate_relationship(
    transaction: DiscoveredIntent,
    remote: DiscoveredIntent,
) -> None:
    transaction_document = transaction.record.document
    remote_document = remote.record.document
    if (
        transaction_document["tenantId"] != remote_document["tenantId"]
        or transaction_document["correlationId"] != remote_document["correlationId"]
    ):
        raise IntentDiscoveryError("related intents disagree on tenant or correlation authority")
    operation = transaction_document["operation"]
    if type(operation) is not str:
        raise IntentDiscoveryError("lifecycle intent has no operation")
    if remote.kind is ContractKind.ARCHIVE_CONSTRUCTION_INTENT:
        expected_operation = "archive"
    else:
        transition = remote_document["transition"]
        if type(transition) is not str:
            raise IntentDiscoveryError("retirement intent has no transition")
        expected_operation = transition
    if operation != expected_operation:
        raise IntentDiscoveryError("related intents disagree on the lifecycle transition")
