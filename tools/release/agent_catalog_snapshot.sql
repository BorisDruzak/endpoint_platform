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
), active_native_jobs AS (
    SELECT device_id, status, release_id
    FROM setup_update_assignments
    WHERE status IN ('assigned', 'downloading', 'verified', 'installing', 'verifying', 'recovery_required')
), active_preparations AS (
    SELECT device_id, status, release_id
    FROM setup_update_preparations
    WHERE status IN ('preparing_client', 'restoring_core', 'recovering_client', 'recovering_source')
), active_core_jobs AS (
    SELECT t.device_id, t.status, b.version, b.sha256_digest AS sha256
    FROM update_targets t
    JOIN update_rollouts r ON r.id = t.rollout_id
    JOIN update_builds b ON b.id = r.build_id
    WHERE t.status IN ('assigned', 'requested', 'scheduled')
), planning_devices AS (
    SELECT d.id AS device_id, i.platform, i.agent_version AS core_version,
           i.launcher_version AS foundation_version, i.last_seen_at AS core_observed_at,
           s.state AS installation_state, s.event_id AS native_event_id,
           e.payload->>'schema_version' AS native_contract, e.payload->'native' AS native,
           CASE WHEN enrollment.installer_release_id LIKE 'ubuntu-deb:%'
                  OR enrollment.installer_release_id LIKE 'debian-deb:%' THEN 'deb' END AS enrollment_package_kind,
           c.client_version AS setup_client_version, c.last_seen_at AS setup_client_observed_at,
           sa.component_version AS support_version, sa.reported_at AS support_observed_at,
           j.status AS setup_status, j.release_id AS setup_target_id,
           p.status AS preparation_status, p.release_id AS preparation_target_id,
           u.status AS core_status, u.version AS core_target_version, u.sha256 AS core_target_sha256,
           coalesce(i.last_seen_at BETWEEN transaction_timestamp() - interval '90 seconds'
                         AND transaction_timestamp() + interval '30 seconds' AND EXISTS (
               SELECT 1 FROM device_sessions w
               WHERE w.device_instance_id = i.id AND w.device_id = d.id AND w.closed_at IS NULL
                 AND w.session_identifier LIKE 'gateway-%' AND w.expires_at > transaction_timestamp()
                 AND w.last_seen_at BETWEEN transaction_timestamp() - interval '90 seconds'
                         AND transaction_timestamp() + interval '30 seconds'
           ), false) AS seen_wss
    FROM devices d
    LEFT JOIN LATERAL (
        SELECT * FROM device_instances
        WHERE device_id = d.id
        ORDER BY last_seen_at DESC NULLS LAST, id DESC LIMIT 1
    ) i ON true
    LEFT JOIN installation_states s ON s.device_id = d.id
    LEFT JOIN installation_events e ON e.id = s.event_id
    LEFT JOIN LATERAL (
        SELECT r.installer_release_id FROM enrollment_requests r
        WHERE r.device_id = d.id AND r.platform = 'linux' AND r.status = 'completed'
        ORDER BY r.updated_at DESC, r.id DESC LIMIT 1
    ) enrollment ON i.platform = 'linux_amd64'
    LEFT JOIN setup_update_clients c ON c.device_id = d.id
    LEFT JOIN support_access sa ON sa.device_id = d.id
    LEFT JOIN active_native_jobs j ON j.device_id = d.id
    LEFT JOIN LATERAL (
        SELECT a.status, a.release_id
        FROM active_preparations a
        WHERE a.device_id = d.id
        ORDER BY (a.status IN ('recovering_source', 'recovering_client')) DESC, a.release_id LIMIT 1
    ) p ON true
    LEFT JOIN active_core_jobs u ON u.device_id = d.id
    WHERE d.retired_at IS NULL OR j.device_id IS NOT NULL OR p.release_id IS NOT NULL OR u.device_id IS NOT NULL
), eligible_campaign_sources AS (
    SELECT c.target_platform, release.key, count(*) AS catalog_campaign_count
    FROM enrollment_campaigns c
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(c.policy->CASE c.target_platform
            WHEN 'windows' THEN 'allowed_installer_releases' ELSE 'allowed_native_releases' END) = 'array'
        THEN c.policy->CASE c.target_platform
            WHEN 'windows' THEN 'allowed_installer_releases' ELSE 'allowed_native_releases' END
        ELSE '[]'::jsonb END
    ) AS release(key)
    WHERE c.target_platform IN ('windows', 'linux') AND c.revoked_at IS NULL AND c.disabled_at IS NULL
      AND c.expires_at > transaction_timestamp() AND c.use_count < c.max_uses
    GROUP BY c.target_platform, release.key
), planning_enrollment AS (
    SELECT 'windows' AS platform, w.id AS release_id, w.agent_version AS version, w.version AS installer_version,
           w.source_commit AS source_revision,
           w.setup_sha256 AS sha256, w.msi_sha256 AS package_sha256, NULL AS sensor_sha256,
           w.download_published, coalesce(c.catalog_campaign_count, 0) AS catalog_campaign_count, w.retired_at
    FROM windows_setup_releases w LEFT JOIN eligible_campaign_sources c ON c.target_platform = 'windows' AND c.key = w.version
    UNION ALL
    SELECT 'alt', a.id, a.version, a.version, a.source_revision, NULL, a.core_rpm_sha256, a.user_sensor_rpm_sha256,
           NULL, coalesce(c.catalog_campaign_count, 0), a.retired_at
    FROM linux_native_releases a LEFT JOIN eligible_campaign_sources c ON c.target_platform = 'linux' AND c.key = a.id::text
), planning_requests AS (
    SELECT CASE WHEN r.platform = 'windows' THEN 'windows' ELSE 'alt' END AS platform,
           r.installer_version AS version, r.installer_release_id AS release_id, r.status, count(*) AS count
    FROM enrollment_requests r
    LEFT JOIN linux_enrollment_bindings b ON b.enrollment_request_id = r.id
    WHERE (r.platform = 'windows' OR b.native_release_id IS NOT NULL)
      AND r.status IN ('created', 'validating', 'auto_approved', 'waiting_approval', 'review_required',
                       'claim_issued', 'enrolling', 'device_registered', 'waiting_wss')
    GROUP BY r.platform, r.installer_version, r.installer_release_id, r.status
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
    'release_planning', jsonb_build_object(
        'devices', coalesce((SELECT jsonb_agg(to_jsonb(d) ORDER BY d.device_id) FROM planning_devices d), '[]'::jsonb),
        'windows_targets', coalesce((SELECT jsonb_agg(jsonb_build_object('release_id', id, 'version', version,
            'sha256', sha256) ORDER BY id) FROM setup_update_releases), '[]'::jsonb),
        -- Only direct assignments can currently satisfy a matrix case.
        'windows_qualifications', coalesce((
            SELECT jsonb_agg(jsonb_build_object('qualification_id', q.id, 'release_id', q.release_id,
                'sha256', q.sha256, 'source_foundation', q.source_foundation,
                'source_core', j.source_core_version, 'source_setup_client', j.source_client_version,
                'evidence_assignment_id', q.evidence_assignment_id, 'qualified_at', q.qualified_at,
                'expires_at', q.expires_at) ORDER BY q.id)
            FROM setup_fleet_qualifications q
            JOIN setup_update_releases r ON r.id = q.release_id AND r.sha256 = q.sha256
            JOIN setup_update_assignments j ON j.id = q.evidence_assignment_id AND j.release_id = r.id
            WHERE j.status = 'applied' AND j.source_foundation_version = q.source_foundation
              AND q.qualified_at <= transaction_timestamp() AND q.expires_at >= transaction_timestamp()
              AND NOT EXISTS (SELECT 1 FROM setup_update_preparations p WHERE p.assignment_id = j.id)
        ), '[]'::jsonb),
        'enrollment_sources', coalesce((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.platform, e.version, e.release_id)
            FROM planning_enrollment e), '[]'::jsonb),
        'pending_enrollments', coalesce((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.platform, r.version, r.release_id, r.status)
            FROM planning_requests r), '[]'::jsonb)
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
