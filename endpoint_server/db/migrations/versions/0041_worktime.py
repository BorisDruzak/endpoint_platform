"""Independent durable WorkTime personnel records.

Revision ID: 0041_worktime
Revises: 0040_identity_sso
"""
from alembic import op
import sqlalchemy as sa

revision = '0041_worktime'
down_revision = '0040_identity_sso'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('worktime_audit',
        sa.Column('person_id', sa.Uuid(), nullable=True),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('record_id', sa.Uuid(), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_worktime_audit_person_id', 'worktime_audit', ['person_id'], unique=False)
    op.create_table('worktime_categories',
        sa.Column('code', sa.String(length=40), nullable=False),
        sa.Column('label', sa.String(length=100), nullable=False),
        sa.Column('requires_comment', sa.Boolean(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('code', name=None),
    )
    op.create_table('worktime_retention_policies',
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('retention_days', sa.Integer(), nullable=True),
        sa.Column('inactivity_threshold_seconds', sa.Integer(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('retention_days IS NULL OR retention_days >= 1', name='ck_worktime_retention_days'),
        sa.CheckConstraint('inactivity_threshold_seconds >= 1200', name='ck_worktime_inactivity_threshold'),
    )
    op.create_table('worktime_state',
        sa.Column('person_id', sa.Uuid(), sa.ForeignKey('confirmed_identities.person_id', ondelete='RESTRICT'), primary_key=True, nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notification_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retention_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('records_expired_before', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('WORKING','BREAK','OFF_PC','ENDED')", name='ck_worktime_state_status'),
    )
    op.create_index('ix_worktime_state_notification_checked_at', 'worktime_state', ['notification_checked_at'], unique=False)
    op.create_index('ix_worktime_state_retention_checked_at', 'worktime_state', ['retention_checked_at'], unique=False)
    op.create_table('worktime_activity_bindings',
        sa.Column('person_id', sa.Uuid(), sa.ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('device_id', sa.Uuid(), sa.ForeignKey('devices.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('user_key', sa.String(length=300), nullable=False),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
        sa.Column('verified_by', sa.Uuid(), nullable=False),
        sa.Column('proof_reference', sa.String(length=256), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('valid_until > valid_from', name='ck_worktime_binding_bounds'),
    )
    op.create_index('ix_worktime_binding_lookup', 'worktime_activity_bindings', ['person_id', 'valid_from', 'valid_until'], unique=False)
    op.create_table('worktime_corrections',
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('person_id', sa.Uuid(), sa.ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('idempotency_key', sa.Uuid(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('ended_at > started_at', name='ck_worktime_correction_bounds'),
        sa.CheckConstraint("status IN ('WORKING','BREAK','OFF_PC','ENDED')", name='ck_worktime_correction_status'),
        sa.UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_correction_key'),
    )
    op.create_index('ix_worktime_corrections_person_id', 'worktime_corrections', ['person_id'], unique=False)
    op.create_table('worktime_events',
        sa.Column('action', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('person_id', sa.Uuid(), sa.ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('idempotency_key', sa.Uuid(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('WORKING','BREAK','OFF_PC','ENDED')", name='ck_worktime_event_status'),
        sa.UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_event_key'),
    )
    op.create_index('ix_worktime_event_person_time', 'worktime_events', ['person_id', 'occurred_at'], unique=False)
    op.create_index('ix_worktime_events_person_id', 'worktime_events', ['person_id'], unique=False)
    op.create_table('worktime_explanation_requests',
        sa.Column('person_id', sa.Uuid(), sa.ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('source', sa.String(length=32), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('ended_at > started_at', name='ck_worktime_request_bounds'),
        sa.UniqueConstraint('person_id', 'started_at', 'ended_at', name='uq_worktime_request_interval'),
    )
    op.create_index('ix_worktime_explanation_requests_person_id', 'worktime_explanation_requests', ['person_id'], unique=False)
    op.create_table('worktime_schedules',
        sa.Column('effective_from', sa.Date(), nullable=False),
        sa.Column('definition', sa.JSON(), nullable=False),
        sa.Column('person_id', sa.Uuid(), sa.ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('idempotency_key', sa.Uuid(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_schedule_key'),
    )
    op.create_index('ix_worktime_schedules_person_id', 'worktime_schedules', ['person_id'], unique=False)
    op.create_table('worktime_timesheets',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column('person_id',sa.Uuid(),sa.ForeignKey('worktime_state.person_id',ondelete='RESTRICT'),nullable=False),
        sa.Column('month',sa.Date(),nullable=False),sa.Column('version',sa.Integer(),nullable=False),
        sa.Column('timezone',sa.String(64),nullable=False),sa.Column('finalized_by',sa.Uuid(),nullable=False),
        sa.Column('finalized_at',sa.DateTime(timezone=True),nullable=False),sa.Column('reason',sa.Text(),nullable=False),
        sa.Column('source_digest',sa.String(64),nullable=False),sa.Column('totals',sa.JSON(),nullable=False),
        sa.Column('idempotency_key',sa.Uuid(),nullable=False),sa.Column('fingerprint',sa.String(64),nullable=False),
        sa.UniqueConstraint('person_id','month','version',name='uq_worktime_timesheet_version'),
        sa.UniqueConstraint('person_id','idempotency_key',name='uq_worktime_timesheet_key'),
        sa.CheckConstraint('version >= 1',name='ck_worktime_timesheet_version'),
        sa.CheckConstraint('finalized_by != person_id',name='ck_worktime_timesheet_independent'))
    op.create_index('ix_worktime_timesheets_person_id','worktime_timesheets',['person_id'])
    op.create_table('worktime_timesheet_days',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column('timesheet_id',sa.Uuid(),sa.ForeignKey('worktime_timesheets.id',ondelete='RESTRICT'),nullable=False),
        sa.Column('day',sa.Date(),nullable=False),sa.Column('work_seconds',sa.Integer(),nullable=False),
        sa.Column('off_pc_seconds',sa.Integer(),nullable=False),sa.Column('break_seconds',sa.Integer(),nullable=False),
        sa.Column('scheduled_seconds',sa.Integer(),nullable=False),sa.Column('payload',sa.JSON(),nullable=False),
        sa.UniqueConstraint('timesheet_id','day',name='uq_worktime_timesheet_day'),
        sa.CheckConstraint('work_seconds >= 0 AND work_seconds <= 86400',name='ck_worktime_timesheet_day_work'),
        sa.CheckConstraint('off_pc_seconds >= 0 AND off_pc_seconds <= work_seconds',name='ck_worktime_timesheet_day_offpc'),
        sa.CheckConstraint('break_seconds >= 0 AND break_seconds <= 86400',name='ck_worktime_timesheet_day_break'),
        sa.CheckConstraint('scheduled_seconds >= 0 AND scheduled_seconds <= 86400',name='ck_worktime_timesheet_day_schedule'))
    op.create_index('ix_worktime_timesheet_days_timesheet_id','worktime_timesheet_days',['timesheet_id'])
    if op.get_bind().dialect.name == 'postgresql':
        op.execute("""CREATE FUNCTION worktime_finalized_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Finalized WorkTime versions are immutable' USING ERRCODE='23514'; END;
            $$""")
        for table in ('worktime_timesheets','worktime_timesheet_days'):
            op.execute(f'CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} '
                       'FOR EACH ROW EXECUTE FUNCTION worktime_finalized_immutable()')
    op.create_table('worktime_approvals',
        sa.Column('correction_id', sa.Uuid(), sa.ForeignKey('worktime_corrections.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('decision', sa.String(length=16), nullable=False),
        sa.Column('comment', sa.Text(), nullable=False),
        sa.Column('idempotency_key', sa.Uuid(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('idempotency_key', name=None),
        sa.UniqueConstraint('correction_id', name=None),
        sa.CheckConstraint("decision IN ('approved','rejected')", name='ck_worktime_approval_decision'),
    )
    op.create_table('worktime_explanations',
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('category_code', sa.String(length=40), nullable=False),
        sa.Column('comment', sa.Text(), nullable=False),
        sa.Column('request_id', sa.Uuid(), sa.ForeignKey('worktime_explanation_requests.id', ondelete='RESTRICT'), nullable=True),
        sa.Column('person_id', sa.Uuid(), sa.ForeignKey('worktime_state.person_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('idempotency_key', sa.Uuid(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('id', sa.Uuid(), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('request_id', name=None),
        sa.CheckConstraint('ended_at > started_at', name='ck_worktime_explanation_bounds'),
        sa.UniqueConstraint('person_id', 'idempotency_key', name='uq_worktime_explanation_key'),
    )
    op.create_index('ix_worktime_explanations_person_id', 'worktime_explanations', ['person_id'], unique=False)


def downgrade():
    op.drop_table('worktime_timesheet_days')
    op.drop_table('worktime_timesheets')
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP FUNCTION worktime_finalized_immutable()')
    op.drop_table('worktime_explanations')
    op.drop_table('worktime_approvals')
    op.drop_table('worktime_schedules')
    op.drop_table('worktime_explanation_requests')
    op.drop_table('worktime_events')
    op.drop_table('worktime_corrections')
    op.drop_table('worktime_activity_bindings')
    op.drop_table('worktime_state')
    op.drop_table('worktime_retention_policies')
    op.drop_table('worktime_categories')
    op.drop_table('worktime_audit')
