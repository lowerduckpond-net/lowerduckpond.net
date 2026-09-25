"""Differential checks against the unchanged published schema and reference resolver."""

from __future__ import annotations

import json
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from conftest import FIXTURE_ROOT
from jsonschema import Draft202012Validator, FormatChecker
from lowerduckpond_static_contracts import schema
from lowerduckpond_static_contracts.schema_expansion import COMMON_ID, expand_common_references
from referencing import Registry, Resource

DRAFT = "https://json-schema.org/draft/2020-12/schema"


def _member(value: dict[str, object], key: str) -> dict[str, object]:
    return cast(dict[str, object], value[key])


def _errors(validator: Draft202012Validator, value: object) -> list[tuple[str, str]]:
    # Match production's stable path ordering, including the first error code.
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
    return [(str(list(error.path)), str(error.validator)) for error in errors]


def _mutants(value: object) -> Iterator[object]:
    replacement: object
    if type(value) is dict:
        for key, item in value.items():
            missing = deepcopy(value)
            del missing[key]
            yield missing
            for replacement in (None, True, -1, "invalid\n", [], {}):
                yield {**deepcopy(value), key: replacement}
            for replacement in _mutants(item):
                yield {**deepcopy(value), key: replacement}
    elif type(value) is list:
        for position, item in enumerate(value):
            for replacement in _mutants(item):
                changed = deepcopy(value)
                changed[position] = replacement
                yield changed


@pytest.mark.parametrize(
    "path", sorted((FIXTURE_ROOT / "accepted").glob("*.json")), ids=lambda path: path.stem
)
def test_all_contracts_and_nested_hostile_fields_match_published_validator(path: Path) -> None:
    document = json.loads(path.read_bytes())
    kind = schema.ContractKind(document["kind"])
    original = schema.STRICT_DRAFT_202012_VALIDATOR(
        schema.schema_for(kind),
        registry=schema._registry(),  # type: ignore[arg-type]  # jsonschema stub is wider
        format_checker=FormatChecker(),
    )
    expanded = schema._validator(kind)
    assert not _errors(original, document) and not _errors(expanded, document)
    for mutation in _mutants(document):
        assert _errors(expanded, mutation) == _errors(original, mutation)


def _documents(definition: object) -> tuple[dict[str, object], dict[str, object]]:
    common: dict[str, object] = {"$schema": DRAFT, "$id": COMMON_ID, "$defs": {"test": definition}}
    root: dict[str, object] = {
        "$schema": DRAFT,
        "$id": COMMON_ID.replace("common.schema", "test.schema"),
        "type": "object",
        "properties": {"value": {"$ref": "common.schema.json#/$defs/test"}},
        "required": ["value"],
    }
    return root, common


def _pair(
    root: dict[str, object], common: dict[str, object]
) -> tuple[Draft202012Validator, Draft202012Validator]:
    registry = Registry().with_resources(
        [
            (str(common["$id"]), Resource.from_contents(common)),
            (str(root["$id"]), Resource.from_contents(root)),
        ]
    )
    return (
        schema.STRICT_DRAFT_202012_VALIDATOR(
            root, registry=registry, format_checker=FormatChecker()
        ),
        schema.STRICT_DRAFT_202012_VALIDATOR(
            expand_common_references(root, common),
            registry=registry,
            format_checker=FormatChecker(),
        ),
    )


def test_reference_siblings_keep_both_assertions_and_unknown_field_rejection() -> None:
    root, common = _documents(
        {"$ref": "#/$defs/base", "properties": {"format": {"const": "result"}}}
    )
    _member(common, "$defs")["base"] = {
        "type": "object",
        "required": ["format", "value"],
        "additionalProperties": False,
        "properties": {"format": {"type": "string"}, "value": {"type": "integer", "minimum": 0}},
    }
    original, expanded = _pair(root, common)
    good = {"value": {"format": "result", "value": 1}}
    assert not _errors(expanded, good)
    for item in (
        {"format": "other", "value": 1},
        {"format": "result", "value": True},
        {"format": "result", "value": 1.0},
        {"format": "result", "value": 1, "extra": 0},
    ):
        value = {"value": item}
        assert _errors(expanded, value) == _errors(original, value)
        assert _errors(expanded, value)


@pytest.mark.parametrize("keyword", ["const", "enum", "default", "examples"])
def test_reference_shaped_literal_data_is_unchanged(keyword: str) -> None:
    literal = {"$ref": "#/$defs/does-not-exist", "$id": "literal"}
    root, common = _documents({keyword: [literal] if keyword in {"enum", "examples"} else literal})
    before = deepcopy((root, common))
    expanded = expand_common_references(root, common)
    assert expanded is not root
    original, validator = _pair(root, common)
    for value in (literal, {}, None, "different"):
        assert _errors(validator, {"value": value}) == _errors(original, {"value": value})
    assert (root, common) == before
    _member(_member(expanded, "properties"), "value")[keyword] = "changed copy"
    assert (root, common) == before


@pytest.mark.parametrize(
    "definition",
    [
        {"$id": "other.json", "type": "string"},
        {"$anchor": "other", "type": "string"},
        {"$dynamicRef": "#other"},
        {"$dynamicAnchor": "other"},
        {"unevaluatedProperties": False},
        {"unknown-future-keyword": True},
        {"$ref": "#/$defs/test"},
        {"$ref": "other.json#/$defs/value"},
        {"$ref": "#/$defs/missing"},
    ],
)
def test_unsupported_common_scopes_and_cycles_use_original_document(definition: object) -> None:
    root, common = _documents(definition)
    before = deepcopy((root, common))
    assert expand_common_references(root, common) is root
    assert (root, common) == before


@pytest.mark.parametrize("keyword", ["$id", "$schema", "$dynamicAnchor", "unevaluatedItems"])
def test_unsupported_caller_scope_uses_original_document(keyword: str) -> None:
    root, common = _documents({"type": "string"})
    _member(root, "properties")["other"] = {keyword: "different"}
    assert expand_common_references(root, common) is root


def test_expansion_is_bounded_even_for_acyclic_exponential_references() -> None:
    root, common = _documents({"$ref": "#/$defs/0"})
    for number in range(15):
        _member(common, "$defs")[str(number)] = {"allOf": [{"$ref": f"#/$defs/{number + 1}"}] * 2}
    _member(common, "$defs")["15"] = {"type": "string"}
    assert expand_common_references(root, common) is root


def test_existing_document_references_retain_their_original_scope() -> None:
    root, common = _documents({"type": "integer"})
    root["$defs"] = {"local": {"type": "string"}}
    _member(root, "properties")["local"] = {"$ref": "#/$defs/local"}
    before = deepcopy((root, common))
    original, expanded = _pair(root, common)
    for value in ({"value": 1, "local": "yes"}, {"value": 1, "local": False}):
        assert _errors(expanded, value) == _errors(original, value)
    assert (root, common) == before


@pytest.mark.parametrize("definition", [True, False, {"type": "string", "format": "date-time"}])
def test_boolean_definitions_and_format_checks_are_unchanged(definition: object) -> None:
    root, common = _documents(definition)
    original, expanded = _pair(root, common)
    value: object
    for value in ("2026-09-25T00:00:00Z", "2026-99-99T00:00:00Z", None, True, {}, []):
        assert _errors(expanded, {"value": value}) == _errors(original, {"value": value})


def test_deep_schema_falls_back_before_python_recursion_exhaustion() -> None:
    definition: object = {"type": "string"}
    for _ in range(100):
        definition = {"properties": {"nested": definition}}
    root, common = _documents(definition)
    assert expand_common_references(root, common) is root


@pytest.mark.parametrize(
    "target", ["root-scope", "common-scope", "root-draft", "common-draft", "root-ref"]
)
def test_changed_document_scope_or_draft_retains_original(target: str) -> None:
    root, common = _documents({"type": "string"})
    if target == "root-scope":
        root["$id"] = "https://example.invalid/other.json"
    elif target == "common-scope":
        common["$id"] = "https://example.invalid/common.schema.json"
    elif target == "root-draft":
        root["$schema"] = "https://json-schema.org/draft-07/schema"
    elif target == "common-draft":
        common["$schema"] = "https://json-schema.org/draft-07/schema"
    else:
        root["$ref"] = "common.schema.json#/$defs/test"
    assert expand_common_references(root, common) is root
