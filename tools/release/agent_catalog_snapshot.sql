-- Read only. Run separately on each source provider with psql -X -Atq -v ON_ERROR_STOP=1.
-- These rows record catalog occupancy. Enrollment and rollout admissions are separate.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '5s';

WITH primary_download AS (
    SELECT id, version, agent_version, setup_sha256 AS sha256, created_at
    FROM windows_setup_releases
    WHERE download_published AND retired_at IS NULL
    ORDER BY created_at DESC, id DESC
    LIMIT 1
), full_setup_policy AS (
    SELECT p.revision, p.enabled, p.scope, p.updated_at, r.id AS release_id,
           r.version, r.sha256
    FROM setup_fleet_policy AS p
    LEFT JOIN setup_update_releases AS r ON r.id = p.release_id
    WHERE p.policy_key = 'windows-full-setup'
), active_assignments AS (
    SELECT status, count(*) AS total
    FROM setup_update_assignments
    WHERE status IN ('assigned', 'downloading', 'verified', 'installing',
                     'verifying', 'recovery_required')
    GROUP BY status
), core_versions AS (
    SELECT DISTINCT platform, channel, version
    FROM update_builds
), accepted_native_sources AS (
    SELECT e.payload->>'schema_version' AS native_contract,
           e.payload->'native'->>'version' AS version,
           e.payload->'native'->>'source_revision' AS source_revision,
           coalesce(e.payload->'native'->>'msi_sha256',
                    e.payload->'native'->>'core_rpm_sha256') AS package_sha256,
           e.payload->'native'->>'user_sensor_rpm_sha256' AS sensor_rpm_sha256,
           EXISTS (
               SELECT 1
               FROM device_sessions AS live
               WHERE live.device_id = s.device_id AND live.closed_at IS NULL
                 AND live.expires_at > transaction_timestamp()
           ) AS connected
    FROM installation_states AS s
    JOIN installation_events AS e ON e.id = s.event_id
    JOIN devices AS d ON d.id = s.device_id
    WHERE s.state = 'installed' AND d.retired_at IS NULL
      AND e.payload->>'schema_version' IN ('endpoint_installation_event_v1',
                                          'endpoint_linux_installation_event_v1')
), accepted_native_groups AS (
    SELECT native_contract, version, source_revision, package_sha256, sensor_rpm_sha256,
           count(*) AS accepted_devices,
           count(*) FILTER (WHERE connected) AS connected_devices
    FROM accepted_native_sources
    GROUP BY native_contract, version, source_revision, package_sha256, sensor_rpm_sha256
)
SELECT jsonb_build_object(
    'schema_version', 1,
    'observed_at', transaction_timestamp(),
    'database_revision', (SELECT version_num FROM alembic_version),
    'windows_primary', (SELECT to_jsonb(primary_download) FROM primary_download),
    'windows_delivery', (SELECT to_jsonb(full_setup_policy) FROM full_setup_policy),
    'windows_active_assignments', coalesce(
        (SELECT jsonb_object_agg(status, total) FROM active_assignments), '{}'::jsonb
    ),
    'accepted_native_installations', coalesce(
        (SELECT jsonb_agg(to_jsonb(accepted_native_groups)
                          ORDER BY native_contract, version, source_revision, package_sha256, sensor_rpm_sha256)
         FROM accepted_native_groups), '[]'::jsonb
    ),
    'occupied_versions', jsonb_build_object(
        'windows_installer', ARRAY(SELECT DISTINCT version FROM windows_setup_releases ORDER BY version),
        'windows_agent', ARRAY(SELECT DISTINCT agent_version FROM windows_setup_releases ORDER BY agent_version),
        'windows_full_setup', ARRAY(SELECT DISTINCT version FROM setup_update_releases ORDER BY version),
        'linux_native', ARRAY(SELECT DISTINCT version FROM linux_native_releases ORDER BY version),
        'core', coalesce(
            (SELECT jsonb_agg(to_jsonb(core_versions) ORDER BY platform, channel, version)
             FROM core_versions), '[]'::jsonb
        )
    )
);

COMMIT;
