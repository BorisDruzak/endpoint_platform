"""Restore observation freshness from completed historical collections.

Revision ID: 0027_context_observed_backfill
Revises: 0026_context_evidence_v2
"""

from __future__ import annotations

from alembic import op

revision = "0027_context_observed_backfill"
down_revision = "0026_context_evidence_v2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Revision 0026 initializes freshness from the last changed snapshot.
    # Older semantic-dedup collections may have observed the same state much
    # later. Their result timestamps remain after raw JSON cleanup.
    op.execute("""
        WITH latest AS (
            SELECT device_id, profile,
                   MAX(COALESCE(result_received_at, completed_at)) AS observed_at
            FROM context_collections
            WHERE status = 'completed'
            GROUP BY device_id, profile
        )
        UPDATE context_current AS current
        SET last_observed_at = GREATEST(current.updated_at, latest.observed_at)
        FROM latest
        WHERE current.device_id = latest.device_id
          AND current.profile = latest.profile
          AND latest.observed_at IS NOT NULL
          AND (current.last_observed_at IS NULL
               OR current.last_observed_at < latest.observed_at)
    """)


def downgrade() -> None:
    raise RuntimeError(
        "Observation backfill is forward-only; restore the verified database backup with the previous release"
    )
