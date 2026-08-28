from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from endpoint_contracts.modules import ModuleOperationDetailV1


def _detail(*, expected_step_count: int, sequences: list[int]) -> dict[str, object]:
    created_at = datetime(2026, 8, 29, tzinfo=UTC)
    return {
        "schema_version": "endpoint_module_operation_v1",
        "operation_id": UUID("22222222-2222-4222-8222-222222222222"),
        "device_id": UUID("11111111-1111-4111-8111-111111111111"),
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "status": "queued",
        "created_at": created_at,
        "deadline_at": created_at + timedelta(minutes=30),
        "completed_at": None,
        "expected_step_count": expected_step_count,
        "steps": [
            {
                "sequence": sequence,
                "capability": "dns.resolve",
                "status": "queued",
                "error_code": None,
                "safe_result": None,
            }
            for sequence in sequences
        ],
    }


def test_module_operation_detail_exposes_the_exact_expected_step_count() -> None:
    detail = ModuleOperationDetailV1.model_validate(
        _detail(expected_step_count=2, sequences=[0, 1])
    )

    assert detail.expected_step_count == 2


@pytest.mark.parametrize(
    ("expected_step_count", "sequences"),
    [(2, [0]), (2, [0, 2]), (1, [1]), (0, [])],
)
def test_module_operation_detail_rejects_non_exact_or_non_contiguous_steps(
    expected_step_count: int,
    sequences: list[int],
) -> None:
    with pytest.raises(ValidationError):
        ModuleOperationDetailV1.model_validate(
            _detail(expected_step_count=expected_step_count, sequences=sequences)
        )
