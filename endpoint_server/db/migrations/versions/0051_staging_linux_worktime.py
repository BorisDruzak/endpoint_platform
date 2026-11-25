"""Join Linux support with retained Worktime history.

Originally staging-only; explicitly promoted for production parity on2026-11-09.
Keep this deployed revision ID and both original branch histories unchanged.
Promotion requires rehearsed preservation of populated0044 and production0050.
"""

revision = '0051_staging_linux_worktime'
down_revision = ('0050_linux_enrollment_binding', '0044_worktime_helpdesk')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
