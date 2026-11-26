-- Run on the Lab provider with psql -X -Atq -v ON_ERROR_STOP=1 -v assignment_id=UUID.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL TIME ZONE 'UTC';

SELECT jsonb_build_object(
    'schema_version', 1,
    'assignment_id', a.id,
    'attempt_id', a.attempt_id,
    'device_id', a.device_id,
    'status', a.status,
    'source_foundation_version', a.source_foundation_version,
    'assigned_at', a.assigned_at,
    'finished_at', a.finished_at,
    'release', jsonb_build_object(
        'id', r.id, 'version', r.version, 'source_revision', r.source_revision,
        'sha256', r.sha256, 'msi_sha256', r.msi_sha256
    ),
    'report', jsonb_build_object(
        'phase', a.last_report->'phase', 'safe_code', a.last_report->'safe_code',
        'attempt_id', a.last_report->'attempt_id',
        'proof', jsonb_build_object(
            'foundation_version', a.last_report->'proof'->'foundation_version',
            'core_version', a.last_report->'proof'->'core_version',
            'source_revision', a.last_report->'proof'->'source_revision',
            'msi_sha256', a.last_report->'proof'->'msi_sha256',
            'native_phase', a.last_report->'proof'->'native_phase',
            'exit_code', a.last_report->'proof'->'exit_code',
            'native_verified', a.last_report->'proof'->'native_verified',
            'core_verified', a.last_report->'proof'->'core_verified',
            'provenance_verified', a.last_report->'proof'->'provenance_verified',
            'pending', a.last_report->'proof'->'pending',
            'services_verified', a.last_report->'proof'->'services_verified',
            'companions_restored', a.last_report->'proof'->'companions_restored',
            'soak', jsonb_build_object(
                'samples', a.last_report->'proof'->'soak'->'samples',
                'sensor_count', a.last_report->'proof'->'soak'->'sensor_count',
                'duration_seconds', a.last_report->'proof'->'soak'->'duration_seconds',
                'services_stable', a.last_report->'proof'->'soak'->'services_stable',
                'companions_stable', a.last_report->'proof'->'soak'->'companions_stable',
                'connected', a.last_report->'proof'->'soak'->'connected'
            )
        )
    )
)
FROM setup_update_assignments AS a
JOIN setup_update_releases AS r ON r.id = a.release_id
WHERE a.id = :'assignment_id'::uuid;

COMMIT;
