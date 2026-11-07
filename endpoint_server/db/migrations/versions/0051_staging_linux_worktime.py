"""STAGING ONLY: join Linux support with retained Worktime history.

This overlay must never be included in the canonical production release.
Both original branch histories and their guards remain intact.
"""

revision = '0051_staging_linux_worktime'
down_revision = ('0050_linux_enrollment_binding', '0044_worktime_helpdesk')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
