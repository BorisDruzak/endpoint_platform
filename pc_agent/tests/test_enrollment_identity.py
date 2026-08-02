from __future__ import annotations

from uuid import UUID

import pytest

from pc_agent.enrollment_identity import (
    EnrollmentIdentityError,
    canonical_enrollment_device_id,
)


@pytest.mark.parametrize(
    "value",
    [
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-6000-8000-000000000001",
    ],
)
def test_python_identity_rejects_uuids_outside_finalizer_grammar(value: str) -> None:
    """Catches Python accepting a UUID that claim finalization must reject."""
    with pytest.raises(EnrollmentIdentityError):
        canonical_enrollment_device_id(value)


def test_python_identity_accepts_canonical_server_uuid4() -> None:
    value = "00000000-0000-4000-8000-000000000001"

    assert canonical_enrollment_device_id(value) == UUID(value)
