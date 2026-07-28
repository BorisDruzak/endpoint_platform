import json
from math import isfinite
from typing import Annotated, TypeAliasType

from pydantic import Field

MAX_JSON_DEPTH = 8
MAX_JSON_STRING_LENGTH = 4096
MAX_JSON_LIST_ITEMS = 32
MAX_JSON_MAP_ITEMS = 32
MAX_JSON_NODES = 1024
MAX_JSON_SERIALIZED_BYTES = 65536

BoundedJsonKeyV1 = Annotated[str, Field(max_length=MAX_JSON_STRING_LENGTH)]
JsonScalarV1 = (
    Annotated[str, Field(max_length=MAX_JSON_STRING_LENGTH)]
    | int
    | float
    | bool
    | None
)


def _build_bounded_json_value_type() -> object:
    value_type: object = JsonScalarV1
    for depth in range(MAX_JSON_DEPTH, 0, -1):
        child_type = value_type
        max_list_items = 0 if depth == MAX_JSON_DEPTH else MAX_JSON_LIST_ITEMS
        max_map_items = 0 if depth == MAX_JSON_DEPTH else MAX_JSON_MAP_ITEMS
        value_type = TypeAliasType(
            f"BoundedJsonValueDepth{depth}",
            JsonScalarV1
            | Annotated[list[child_type], Field(max_length=max_list_items)]
            | Annotated[
                dict[BoundedJsonKeyV1, child_type],
                Field(max_length=max_map_items),
            ],
        )
    return value_type


BoundedJsonValueV1 = _build_bounded_json_value_type()


def _validate_bounded_json(
    value: object,
    *,
    depth: int,
    node_count: list[int],
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON value exceeds maximum nesting depth")

    node_count[0] += 1
    if node_count[0] > MAX_JSON_NODES:
        raise ValueError("JSON value exceeds maximum structural size")

    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING_LENGTH:
            raise ValueError("JSON string exceeds maximum length")
        return
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_MAP_ITEMS:
            raise ValueError("JSON map exceeds maximum size")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON map keys must be strings")
            _validate_bounded_json(key, depth=depth + 1, node_count=node_count)
            _validate_bounded_json(item, depth=depth + 1, node_count=node_count)
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_LIST_ITEMS:
            raise ValueError("JSON list exceeds maximum size")
        for item in value:
            _validate_bounded_json(item, depth=depth + 1, node_count=node_count)


def validate_bounded_json(value: object) -> None:
    _validate_bounded_json(value, depth=0, node_count=[0])
    serialized = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(serialized.encode("utf-8")) > MAX_JSON_SERIALIZED_BYTES:
        raise ValueError("JSON value exceeds maximum serialized size")
