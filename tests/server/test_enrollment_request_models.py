from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex

from endpoint_server.db.models import EnrollmentClaim, EnrollmentRequest


def test_request_model_persists_only_digested_bindings_and_decision_metadata() -> None:
    columns = set(EnrollmentRequest.__table__.columns.keys())

    assert {
        "installation_id_digest",
        "fingerprint_digest",
        "request_capability_digest",
        "selected_campaign_id",
        "status",
        "decision_reason",
        "decided_at",
        "decided_by",
        "expires_at",
    } <= columns
    assert not {"installation_id", "hardware_fingerprint", "request_capability", "claim"} & columns


def test_request_model_has_expiry_and_active_installation_indexes() -> None:
    indexes = {index.name: index for index in EnrollmentRequest.__table__.indexes}

    assert "ix_enrollment_requests_expires_at" in indexes
    rendered = str(
        CreateIndex(indexes["uq_enrollment_requests_active_installation"]).compile(
            dialect=postgresql.dialect()
        )
    )
    assert "UNIQUE" in rendered
    assert "installation_id_digest" in rendered
    assert "WHERE status IN" in rendered


def test_claim_links_to_at_most_one_originating_request() -> None:
    column = EnrollmentClaim.__table__.c.enrollment_request_id

    assert column.nullable
    assert column.unique
    assert column.foreign_keys
