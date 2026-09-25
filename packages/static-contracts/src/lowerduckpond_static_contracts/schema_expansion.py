"""Remove repeated common-definition lookups without changing schema assertions."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

_DRAFT = "https://json-schema.org/draft/2020-12/schema"
COMMON_ID = "https://schemas.lowerduckpond.net/static-publication/v1alpha1/common.schema.json"
_COMMON_REF = "common.schema.json#/$defs/"
_LOCAL_REF = "#/$defs/"
_MAPS = frozenset({"$defs", "properties", "patternProperties", "dependentSchemas"})
_ARRAYS = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})
_SINGLES = frozenset(
    {"additionalProperties", "items", "contains", "propertyNames", "not", "if", "then", "else"}
)
_LITERALS = frozenset(
    {
        "type",
        "const",
        "enum",
        "required",
        "format",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minContains",
        "maxContains",
        "minProperties",
        "maxProperties",
        "dependentRequired",
        "title",
        "description",
        "default",
        "examples",
        "readOnly",
        "writeOnly",
        "deprecated",
        "$comment",
    }
)


class _UnsupportedError(Exception):
    pass


class _Expansion:
    def __init__(self, definitions: dict[str, object]) -> None:
        self.definitions = definitions
        self.remaining = 4096

    def schema(  # noqa: PLR0912 - explicit schema-valued vocabulary boundaries
        self, value: object, stack: tuple[str, ...] = (), *, root: bool = False, depth: int = 0
    ) -> object:
        self.remaining -= 1
        if self.remaining < 0 or depth > 64:  # noqa: PLR2004 - bounded trusted expansion
            raise _UnsupportedError
        if type(value) is bool:
            return value
        if type(value) is not dict:
            raise _UnsupportedError
        result: dict[str, object] = {}
        for key, item in value.items():
            if key == "$ref":
                continue
            if key in _LITERALS or (root and key in {"$id", "$schema"}):
                # A literal example or constant containing "$ref" is data.
                result[key] = deepcopy(item)
            elif key in _MAPS and type(item) is dict:
                result[key] = {
                    name: self.schema(child, stack, depth=depth + 1) for name, child in item.items()
                }
            elif key in _ARRAYS and type(item) is list:
                result[key] = [self.schema(child, stack, depth=depth + 1) for child in item]
            elif key in _SINGLES:
                result[key] = self.schema(item, stack, depth=depth + 1)
            else:
                # Nested identifiers, dynamic/anchor/unevaluated vocabularies
                # and unknown future keywords retain the original resolver.
                raise _UnsupportedError
        if "$ref" not in value:
            return result
        reference = value["$ref"]
        if type(reference) is not str:
            raise _UnsupportedError
        prefix = _LOCAL_REF if stack else _COMMON_REF
        if not reference.startswith(prefix):
            if stack:
                # A common definition must be completely self-contained before
                # moving it into another document's lexical scope.
                raise _UnsupportedError
            return {"$ref": reference, **result}
        name = reference.removeprefix(prefix)
        if name not in self.definitions or name in stack or any(c in name for c in "/~"):
            raise _UnsupportedError
        expanded = self.schema(self.definitions[name], (*stack, name), depth=depth + 1)
        # $ref siblings are additional assertions, not dictionary overrides.
        if result:
            return {"allOf": [expanded, result]}
        # Keep a schema-object boundary for the validator's instance-path
        # propagation, including an always-failing boolean reference.
        return {"allOf": [expanded]} if type(expanded) is bool else expanded


def expand_common_references(
    schema: dict[str, object], common: dict[str, object]
) -> dict[str, object]:
    """Expand only the bounded static vocabulary; otherwise use the exact original.

    These inputs are the bundled, schema-checked documents, never user data.
    Published schemas and the registry retain their original bytes and scopes.
    """
    identifier = schema.get("$id")
    if (
        common.get("$id") != COMMON_ID
        or common.get("$schema") != _DRAFT
        or schema.get("$schema") != _DRAFT
        or "$ref" in schema
        or type(identifier) is not str
        or identifier.rsplit("/", 1)[0] != COMMON_ID.rsplit("/", 1)[0]
        or set(common) != {"$id", "$schema", "$defs"}
        or type(common.get("$defs")) is not dict
    ):
        return schema
    try:
        return cast(
            dict[str, object],
            _Expansion(cast(dict[str, object], common["$defs"])).schema(schema, root=True),
        )
    except _UnsupportedError:
        return schema
