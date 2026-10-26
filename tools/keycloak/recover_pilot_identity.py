"""Plan identity recovery; explicit prepare restores ONLY an exclusive candidate.

Full-database recovery is required to preserve the original Keycloak UUID and
OTP bytes. Never write user/credential rows or reenrol OTP. There is no live
switch/JVM/API command until the isolated harness and evidence are reviewed.

Pinned primary references (Context7 quota unavailable):
https://www.postgresql.org/docs/16/sql-alterdatabase.html
https://www.postgresql.org/docs/16/app-pgrestore.html
https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/dbcommands.c
https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import uuid


BACKUP = "/var/backups/keycloak/20261026T215943Z.kK5AzR"
DUMP_SHA256 = "f7650e6ae9c6cdf73a47898bd78513ad9c2c9559f3bf9148dfa6dc2fbc40aa5c"
CONFIG_SHA256 = "f1d25d3bf3d519f365a04571f22a0120477da641b5d51841540113116a97d174"
ORIGINAL_SUBJECT_SHA256 = "5215ed1d332acab94349086da817ab8989122ba2d2df7cbb6f5130d2c18a73a6"
REIMPORTED_SUBJECT_SHA256 = "01fa0f3ef508cd8b885ec8d2c1bc8b9aeea09adee1bc7dbac94313fd4f38359c"
FEDERATION_SHA256 = "5f90e84c415788da43c1b74a356f70d4a7b0979cbe798a35c97c9a1db899be72"
PILOT_GUID = "ee51f8b3-a7a8-4a69-808f-45adc6b35139"
REALM_ID = "b3e36dfe-afda-48ea-a83a-bd2b28d924e5"
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# Read-only information_schema inventory of this exact26.8.1/PG16 deployment.
# Cardinality alone cannot prove coverage; a replaced credential table must fail.
TABLE_MANIFEST = tuple("""
admin_event_entity associated_policy auth_session authentication_execution
authentication_flow authenticator_config authenticator_config_entry broker_link
client client_attributes client_auth_flow_bindings client_initial_access
client_node_registrations client_scope client_scope_attributes client_scope_client
client_scope_role_mapping cluster_event component component_config composite_role
credential databasechangelog databasechangeloglock default_client_scope event_entity
fed_issued_ver_credential fed_user_attribute fed_user_consent fed_user_consent_cl_scope
fed_user_credential fed_user_group_membership fed_user_required_action fed_user_role_mapping
fed_user_ver_credential federated_identity federated_user group_attribute group_role_mapping
identity_provider identity_provider_config identity_provider_mapper idp_mapper_config
issued_ver_credential jgroups_ping keycloak_group keycloak_role login_failure migration_model
offline_client_session offline_user_session org org_domain org_identity_provider org_invitation
outbox_entry policy_config protocol_mapper protocol_mapper_config realm realm_attribute
realm_default_groups realm_enabled_event_types realm_events_listeners realm_localizations
realm_required_credential realm_smtp_config realm_supported_locales redirect_uris
required_action_config required_action_provider resource_attribute resource_policy resource_scope
resource_server resource_server_perm_ticket resource_server_policy resource_server_resource
resource_server_scope resource_uris revoked_token role_attribute root_auth_session scope_mapping
scope_policy server_config single_use_object user_attribute user_consent user_consent_client_scope
user_entity user_federation_config user_federation_mapper user_federation_mapper_config
user_federation_provider user_group_membership user_required_action user_role_mapping
user_ver_credential web_origins workflow_state
""".split())
REQUIRED_EVIDENCE = (
    "postgres16_disposable_rename_commit_and_rollback",
    "verified_dump_config_complete_marker_and_physical_root_private_paths",
    "current_forensic_full_backup_after_quiescence",
    "exact_config_and_distribution_identity",
    "all_101_tables_original_current_exact_reviewed_row_drift",
    "candidate_original_subject_otp_guid_and_schema_acl_ownership",
    "candidate_isolated_loopback_runtime_no_proxy_exposure",
    "candidate_all_realm_no_backchannel_admin_urls_or_custom_outbound_listeners",
    "candidate_retention_msad_no_cache_before_any_user_lookup",
    "candidate_audience_basic_scope_parity",
    "candidate_session_revocation",
    "candidate_no_online_or_offline_sessions_all_realms",
    "candidate_not_before_all_realms_after_any_restored_token_issue",
    "candidate_all_tables_exact_reviewed_api_repair_drift",
    "all_application_sso_flags_false_no_bindings_or_new_clients",
    "fresh_ad_enabled_guid_unchanged",
    "fresh_zero_connections_and_prepared_transactions_both_databases",
    "independent_source_and_evidence_approval",
)


class RecoveryRefused(ValueError):
    """Fixed diagnostics only: never include source data or DB stderr."""


def require(condition, code):
    if not condition:
        raise RecoveryRefused(code)


def is_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_snapshot(snapshot):
    require(isinstance(snapshot, dict), "SnapshotMalformed")
    require(snapshot.get("schema") == "keycloak_recovery_snapshot_v1", "SnapshotVersionMismatch")
    require(snapshot.get("owner") == "keycloak", "DatabaseOwnerMismatch")
    require(type(snapshot.get("server_version_num")) is int and
            160000 <= snapshot["server_version_num"] < 170000, "Postgres16Required")
    require(snapshot.get("port") == 5544, "DedicatedClusterRequired")
    require(type(snapshot.get("database_oid")) is int and snapshot["database_oid"] > 0,
            "DatabaseOidMissing")
    require(is_hash(snapshot.get("schema_sha256")), "SchemaDigestInvalid")
    tables = snapshot.get("tables")
    require(isinstance(tables, dict) and len(tables) == 101, "Complete101TableInventoryRequired")
    require(set(tables) == set(TABLE_MANIFEST), "PinnedTableManifestMismatch")
    require(isinstance(snapshot.get("actual_tables"), list) and
            all(isinstance(name, str) for name in snapshot["actual_tables"]) and
            sorted(snapshot["actual_tables"]) == sorted(TABLE_MANIFEST), "ActualTableManifestMismatch")
    require(snapshot.get("unexpected_functions") == 0 and snapshot.get("unexpected_triggers") == 0,
            "UnexpectedSchemaExecutable")
    sequence_state = snapshot.get("sequence_state")
    require(isinstance(sequence_state, dict) and all(
        isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name) and is_hash(value)
        for name, value in sequence_state.items()), "SequenceStateInvalid")
    total = 0
    for table, rows in tables.items():
        require(isinstance(table, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", table),
                "TableNameInvalid")
        require(isinstance(rows, list) and all(is_hash(row) for row in rows), "RowDigestInvalid")
        total += len(rows)
    require(total <= 100000, "InventoryBoundExceeded")


def compare_snapshots(before, after):
    """Exact row-digest multisets; no table-name exclusions, even audit/session tables.

    Hash full canonical row JSON privately, including credential/config secrets.
    Only SHA256 digests enter these inputs. Count duplicates; an unexpected user,
    client, key, role, config value or event cannot hide behind a table allowance.
    Schema digest must cover columns/types/defaults/indexes/constraints/ACLs and
    sequences; data digest collection must share a repeatable-read snapshot.
    """
    _validate_snapshot(before)
    _validate_snapshot(after)
    require(before["schema_sha256"] == after["schema_sha256"], "SchemaOrPermissionsDrift")
    require(set(before["tables"]) == set(after["tables"]), "TableSetDrift")
    changes = []
    for table in sorted(before["tables"]):
        old, new = Counter(before["tables"][table]), Counter(after["tables"][table])
        if old != new:
            changes.append({"table": table, "removed": sorted((old - new).elements()),
                            "added": sorted((new - old).elements())})
    require(set(before["sequence_state"]) == set(after["sequence_state"]), "SequenceSetDrift")
    for name in sorted(before["sequence_state"]):
        if before["sequence_state"][name] != after["sequence_state"][name]:
            changes.append({"sequence": name, "before_sha256": before["sequence_state"][name],
                            "after_sha256": after["sequence_state"][name]})
    return changes


def validate_reviewed_drift(before, after, reviewed_changes):
    require(isinstance(reviewed_changes, list), "ExactReviewedDriftRequired")
    require(compare_snapshots(before, after) == reviewed_changes, "UnreviewedDatabaseDrift")


def validate_outbound_safety(evidence):
    """Loopback/cache isolation alone does not prevent backchannel HTTP effects.

    Full restored ALL-realm inventory plus pinned distribution/provider closure
    must establish absence before logout/session DELETE APIs; no blanket bypass.
    """
    require(isinstance(evidence, dict), "OutboundEvidenceMissing")
    for key in ("admin_url_count", "backchannel_url_count", "identity_provider_count",
                "smtp_entry_count", "custom_provider_artifact_count"):
        require(type(evidence.get(key)) is int and evidence[key] == 0, "CandidateOutboundEffectPossible")
    require(evidence.get("event_listeners") == ["jboss-logging"], "CandidateCustomListenerPossible")


def inventory_sql():
    """Private collector SQL; raw secret columns never leave the server.

    pg_catalog shape/OID-independent definitions and ACLs are structural. Sequence
    current values have a separate digest, so API-driven sequence advancement is
    an explicit reviewed data change rather than invisible schema normalization.
    A later executor must collect actual table-name manifest independently first.
    """
    # jsonb_build_object supports at most100 arguments;101 tables must be split.
    chunks = []
    for offset in range(0, len(TABLE_MANIFEST), 40):
        part = TABLE_MANIFEST[offset:offset + 40]
        entries = ",\n".join(
            f"'{name}',(SELECT COALESCE(jsonb_agg(h ORDER BY h),'[]'::jsonb) FROM "
            f"(SELECT encode(sha256(convert_to(to_jsonb(row)::text,'UTF8')),'hex') AS h "
            f'FROM public."{name}" AS row) AS hashes)' for name in part)
        chunks.append("jsonb_build_object(" + entries + ")")
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='30s';
WITH structure AS (
 SELECT jsonb_build_object(
 'relations',(SELECT jsonb_agg(jsonb_build_object('name',c.relname,'kind',c.relkind,
    'owner',pg_get_userbyid(c.relowner),'acl',c.relacl::text) ORDER BY c.relname)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'columns',(SELECT jsonb_agg(jsonb_build_object('table',c.relname,'name',a.attname,
    'type',format_type(a.atttypid,a.atttypmod),'null',a.attnotnull,'identity',a.attidentity,
    'default',pg_get_expr(d.adbin,d.adrelid),'acl',a.attacl::text) ORDER BY c.relname,a.attnum)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
    LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
    WHERE n.nspname='public' AND c.relkind IN ('r','S')),
 'indexes',(SELECT jsonb_agg(pg_get_indexdef(c.oid) ORDER BY c.relname) FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='i'),
 'constraints',(SELECT jsonb_agg(jsonb_build_object('table',c.relname,'name',k.conname,
    'definition',pg_get_constraintdef(k.oid)) ORDER BY c.relname,k.conname)
    FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'public_schema_acl',(SELECT nspacl::text FROM pg_namespace WHERE nspname='public'),
 'database_acl',(SELECT datacl::text FROM pg_database WHERE datname=current_database()),
 'extensions',(SELECT jsonb_agg(jsonb_build_object('name',extname,'version',extversion) ORDER BY extname) FROM pg_extension),
 'sequences',(SELECT jsonb_agg(jsonb_build_object('name',sequencename,'owner',sequenceowner,
    'type',data_type,'start',start_value,'min',min_value,'max',max_value,'increment',increment_by,
    'cycle',cycle,'cache',cache_size) ORDER BY sequencename) FROM pg_sequences WHERE schemaname='public')
 ) AS data
)
SELECT jsonb_build_object(
 'schema','keycloak_recovery_snapshot_v1','database',current_database(),
 'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),
 'server_version_num',current_setting('server_version_num')::int,'port',current_setting('port')::int,
 'schema_sha256',(SELECT encode(sha256(convert_to(data::text,'UTF8')),'hex') FROM structure),
 'sequence_state',CASE WHEN EXISTS (SELECT 1 FROM pg_sequences WHERE schemaname='public')
    THEN NULL ELSE '{}'::jsonb END,
 'unexpected_functions',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'),
 'unexpected_triggers',(SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal),
 'actual_tables',(SELECT jsonb_agg(table_name ORDER BY table_name) FROM information_schema.tables
    WHERE table_schema='public' AND table_type='BASE TABLE'),
 'tables',""" + " || ".join(chunks) + ");\nCOMMIT;\n"


def candidate_configuration(source, candidate):
    """Derive private config only from exact reviewed production fields.

    Secret-bearing returned bytes must go root:keycloak0640 in the private
    candidate tree, never argv, output, receipts, test artifacts or exceptions.
    """
    _names(candidate)
    expected = {
        "db": "postgres", "db-url": "jdbc:postgresql://127.0.0.1:5544/keycloak",
        "db-username": "keycloak", "hostname": "https://sso.sosnadmin.local",
        "hostname-strict": "true", "http-enabled": "true", "http-host": "127.0.0.1",
        "http-port": "8088", "http-management-host": "127.0.0.1", "http-management-port": "9008",
        "proxy-headers": "xforwarded", "proxy-trusted-addresses": "127.0.0.1",
        "truststore-paths": "/etc/keycloak/trust", "health-enabled": "true",
        "metrics-enabled": "false", "cache": "local", "http-max-queued-requests": "100",
        "log-level": "INFO", "log-console-output": "default",
    }
    values = {}
    require(isinstance(source, str) and len(source) <= 65536, "ConfigurationMalformed")
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(separator and key not in values, "DuplicateOrMalformedConfiguration")
        values[key] = value
    require(set(values) == set(expected) | {"db-password"}, "UnexpectedConfigurationFields")
    require(all(values.get(key) == value for key, value in expected.items()), "LiveConfigurationDrift")
    require(re.fullmatch(r"[A-Za-z0-9_\-]{16,128}", values["db-password"]), "DatabaseCredentialEncodingInvalid")
    values.update({"db-url": "jdbc:postgresql://127.0.0.1:5544/" + candidate,
                   "http-port": "8089", "http-management-port": "9009",
                   "db-pool-initial-size": "1", "db-pool-min-size": "1", "db-pool-max-size": "5",
                   "log": "console", "http-access-log-enabled": "false"})
    del values["proxy-headers"]
    del values["proxy-trusted-addresses"]
    return "".join(key + "=" + value + "\n" for key, value in values.items())


def runtime_recipe(candidate):
    """No shared mutable live tree or inherited KC/JAVA/secret environment."""
    _names(candidate)
    private = "/var/lib/keycloak-recovery/" + candidate
    distribution = private + "/keycloak-26.8.1"
    return {"directory": private, "distribution": distribution,
            "cache": "local", "http": "127.0.0.1:8089", "management": "127.0.0.1:9009",
            "shared_mutable_paths": [],
            "argv": ["runuser", "-u", "keycloak", "--", "env", "-i",
                     "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + private,
                     "TMPDIR=" + private + "/tmp", "JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m",
                     "JAVA_OPTS_APPEND=-Djava.io.tmpdir=" + private + "/tmp",
                     distribution + "/bin/kc.sh", "--config-file=" + private + "/candidate.conf",
                     "start", "--optimized"]}


def validate_runtime_proof(proof):
    require(isinstance(proof, dict), "RuntimeProofMissing")
    _names(proof.get("candidate_database"))
    require(type(proof.get("pid")) is int and proof["pid"] > 1 and
            type(proof.get("canonical_pid")) is int and proof["canonical_pid"] > 1 and
            proof["pid"] != proof["canonical_pid"], "RuntimePidMismatch")
    require(proof.get("http_listener") == "127.0.0.1:8089" and
            proof.get("management_listener") == "127.0.0.1:9009" and
            proof.get("socket_pids") == [proof["pid"]], "RuntimeSocketIsolationMismatch")
    for key in ("uid_matches_keycloak", "configuration_sha256_matches",
                "private_distribution_sha256_matches", "private_data_tmp_logs",
                "jdbc_session_database_matches", "no_jgroups_sockets", "no_proxy_routes"):
        require(proof.get(key) is True, "RuntimeIsolationProofIncomplete")


def qualify_candidate(operations):
    """Canonical ordering; no operation here stops/promotes the live service.

    The concrete adapter must reject missing actual evidence at each step.
    A completed ordering is never itself an acceptance verdict. All candidate
    effects remain forensic if any step fails; always stop only its owned PID.
    """
    results = {}
    started = False
    try:
        for operation in (
            "verify_reviewed_restored_candidate_and_capacity",
            "start_private_candidate_runtime",
            "verify_pid_sockets_database_and_config",
            "apply_reviewed_retention_without_user_lookup",
            "verify_original_pilot_and_otp",
            "apply_reviewed_audience_and_basic_scope_repairs",
            "verify_all_realm_no_outbound_effects",
            "purge_restored_sessions_master_last",
            "verify_stale_cookie_and_token_rejected",
        ):
            # The start adapter owns cleanup even if start itself partially
            # succeeds then raises, so mark intent before entering it.
            if operation == "start_private_candidate_runtime":
                started = True
            results[operation] = operations.perform(operation)
    finally:
        if started:
            operations.perform("stop_owned_candidate_pid")
    results["persisted_sessions"] = operations.perform("verify_persisted_sessions_zero")
    results["final_inventory"] = operations.perform("collect_final_candidate_inventory")
    return {"status": "CandidateQualificationEvidenceRequired", "switch_ready": False,
            "operations": list(results), "live_service_changed": False}


def _run_private(argv, *, input_bytes=None, maximum_output=32 * 1024 * 1024, timeout=45):
    """No shell, inherited credentials, child stderr or unbounded stdout in memory."""
    require(sys.platform == "linux" and os.geteuid() == 0, "ApprovedLinuxRootRequired")
    try:
        host = subprocess.run(["hostname", "-I"], check=True, capture_output=True,
                              timeout=5, env={"PATH": SYSTEM_PATH})
        require(b"192.168.100.19" in host.stdout.split(), "ApprovedHostRequired")
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(argv, input=input_bytes, stdout=output, stderr=subprocess.DEVNULL,
                                    timeout=timeout, check=False, env={"PATH": SYSTEM_PATH, "LANG": "C.UTF-8"})
            require(result.returncode == 0, "PrivateCommandFailed")
            require(output.tell() <= maximum_output, "PrivateCommandOutputBoundExceeded")
            output.seek(0)
            return output.read()
    except (OSError, subprocess.SubprocessError):
        raise RecoveryRefused("PrivateCommandFailed") from None


def collect_inventory(database, *, runner=_run_private):
    """Read-only local peer collector; audit clone may never expose secret rows."""
    if database != "keycloak":
        _names(database)
    result = runner(
        ["runuser", "-u", "postgres", "--", "env", "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8",
         "PGOPTIONS=-c default_transaction_read_only=on", "PGCONNECT_TIMEOUT=5",
         "psql", "--no-psqlrc", "--no-password", "--quiet", "--tuples-only", "--no-align",
         "--port", "5544", "--dbname", database, "--set", "ON_ERROR_STOP=1"],
        input_bytes=inventory_sql().encode("utf-8"), maximum_output=32 * 1024 * 1024)
    try:
        snapshot = json.loads(result)
    except (ValueError, TypeError, UnicodeError):
        raise RecoveryRefused("InventoryResponseMalformed") from None
    _validate_snapshot(snapshot)
    require(snapshot.get("database") == database, "InventoryDatabaseMismatch")
    return snapshot


def purge_sessions(client, inventory):
    """Bounded canonical Admin APIs; never user/OTP SQL or user lookups.

    Requires actual fresh isolated runtime and outbound-absence proof before
    caller creates this client. Master logout is final; stale-token negative
    probes use a separate read-only public/unauthorized verification transport.
    """
    require(isinstance(inventory, dict) and inventory.get("realms") == ["master", "sosnadmin"],
            "UnexpectedRestoredRealms")
    cutoff = getattr(client, "admin_iat", None)
    old_max = inventory.get("maximum_restored_token_iat")
    require(type(cutoff) is int and type(old_max) is int and 0 <= old_max < cutoff,
            "FreshAdminMustPostdateRestoredTokens")
    sessions = inventory.get("offline_sessions")
    require(isinstance(sessions, list) and len(sessions) <= 100, "OfflineSessionBoundExceeded")
    seen = set()
    for item in sessions:
        require(isinstance(item, dict) and set(item) == {"realm", "id"} and
                item["realm"] in {"master", "sosnadmin"} and isinstance(item["id"], str),
                "OfflineSessionIdentityInvalid")
        try:
            canonical = str(uuid.UUID(item["id"]))
        except (ValueError, AttributeError):
            raise RecoveryRefused("OfflineSessionIdentityInvalid") from None
        require(canonical == item["id"] and (item["realm"], canonical) not in seen,
                "OfflineSessionIdentityInvalid")
        seen.add((item["realm"], canonical))
    # Transport must enforce one-shot exact payloads against this fixed plan.
    client.not_before_payloads = {"master": cutoff, "sosnadmin": cutoff}
    client.session_delete_paths = {
        "/admin/realms/" + realm + "/sessions/" + session + "?isOffline=true"
        for realm, session in seen}
    client.logout_paths = {"/admin/realms/" + realm + "/logout-all" for realm in ("master", "sosnadmin")}
    for realm in ("sosnadmin", "master"):
        prefix = "/admin/realms/" + realm
        for item in sorted((item for item in sessions if item["realm"] == realm), key=lambda item: item["id"]):
            client.request("DELETE", prefix + "/sessions/" + item["id"] + "?isOffline=true")
        if realm != "master":
            client.request("POST", prefix + "/logout-all")
        client.request("PUT", prefix, payload={"notBefore": cutoff})
        current = client.request("GET", prefix)
        require(isinstance(current, dict) and current.get("notBefore") == cutoff, "RealmNotBeforeNotVerified")
        if realm == "master":
            client.request("POST", prefix + "/logout-all")
    return {"status": "CandidateSessionApisCompletedEvidenceRequired",
            "offline_deleted": len(sessions), "master_logout_last": True,
            "not_before": cutoff, "persisted_zero_not_yet_proven": True}


def validate_capacity(evidence):
    fields = {"free_bytes", "available_memory_bytes", "current_database_bytes", "distribution_bytes", "dump_bytes"}
    require(isinstance(evidence, dict) and set(evidence) == fields and all(
        type(evidence[field]) is int and evidence[field] > 0 for field in fields), "CapacityEvidenceInvalid")
    required = max(4 * 1024**3, 4 * evidence["current_database_bytes"] +
                   2 * evidence["distribution_bytes"] + 2 * evidence["dump_bytes"] + 512 * 1024**2)
    require(evidence["free_bytes"] >= required and evidence["available_memory_bytes"] >= 3 * 1024**3,
            "CandidateCapacityInsufficient")
    return {"sufficient": True, "minimum_free_bytes": required}


def prepare_candidate(operations):
    results = {}
    for operation in ("verify_pinned_backup_config_and_capacity", "capture_current_forensic_backup",
                      "restore_fresh_owned_candidate", "capture_candidate_and_exact_unreviewed_drift"):
        results[operation] = operations.perform(operation)
    return {"status": "CandidateRestoredReviewRequired", "switch_ready": False,
            "live_service_changed": False, "operations": list(results)}


def _physical_root_path(path, *, mode=None):
    """No symlink/foreign-writable ancestor, including backup namespace parents."""
    require(path.is_absolute(), "AbsolutePhysicalPathRequired")
    try:
        for part in (list(reversed(path.parents)) + [path]):
            metadata = part.lstat()
            require(not stat.S_ISLNK(metadata.st_mode) and metadata.st_uid == 0 and
                    not metadata.st_mode & 0o022, "PhysicalRootPathRequired")
        if mode is not None:
            require(stat.S_IMODE(metadata.st_mode) == mode, "PrivatePathModeMismatch")
    except OSError:
        raise RecoveryRefused("PrivatePathUnavailable") from None


def _private_bytes(path, *, expected_sha256=None, mode=0o600, maximum=64 * 1024 * 1024):
    _physical_root_path(path, mode=mode)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1 and
                    stat.S_IMODE(metadata.st_mode) == mode and metadata.st_size <= maximum,
                    "PrivateFileMetadataMismatch")
            data = stream.read(maximum + 1)
        require(len(data) <= maximum, "PrivateFileBoundExceeded")
        if expected_sha256 is not None:
            require(hashlib.sha256(data).hexdigest() == expected_sha256, "PrivateFileDigestMismatch")
        return data
    except OSError:
        raise RecoveryRefused("PrivateFileUnavailable") from None


def _write_private(path, value):
    _physical_root_path(path.parent, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise RecoveryRefused("PrivateReceiptWriteFailed") from None


def _psql_argv(database, *, readonly=True):
    if database not in {"keycloak", "postgres"}:
        _names(database)
    argv = ["runuser", "-u", "postgres", "--", "env", "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8",
            "PGCONNECT_TIMEOUT=5"]
    if readonly:
        argv.append("PGOPTIONS=-c default_transaction_read_only=on")
    return argv + ["psql", "--no-psqlrc", "--no-password", "--quiet", "--tuples-only", "--no-align",
                   "--port", "5544", "--dbname", database, "--set", "ON_ERROR_STOP=1"]


class PrepareOperations:
    """Actual narrow restore adapter. Never starts/stops a JVM or touches live DB.

    A failed prepare leaves its unique candidate, forensic backup and receipts;
    retry creates a fresh name, never drops/reuses a failed or metadata DB.
    """
    BACKUP_SCRIPT_SHA256 = "77f003602b342302dd7a36a75ee94c7ca63249f1cc2a3f0c69b58d7be184f5b9"

    def __init__(self, *, runner=_run_private):
        self.runner = runner
        self.plan = build_plan()
        self.stage = None
        self.dump_data = None
        self.current = None
        self.forensic = None
        self.lock_fd = None

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def perform(self, operation):
        allowed = {"verify_pinned_backup_config_and_capacity": self.verify,
                   "capture_current_forensic_backup": self.backup,
                   "restore_fresh_owned_candidate": self.restore,
                   "capture_candidate_and_exact_unreviewed_drift": self.inventory}
        require(operation in allowed, "PrepareOperationProhibited")
        return allowed[operation]()

    def verify(self):
        # Root/host command gate runs before even a local path or DB mutation.
        self.runner(["true"], maximum_output=0)
        import fcntl
        try:
            self.lock_fd = os.open("/run/keycloak-identity-recovery.lock",
                                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            metadata = os.fstat(self.lock_fd)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1 and
                    stat.S_IMODE(metadata.st_mode) == 0o600, "RecoveryLockMetadataInvalid")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.close()
            raise RecoveryRefused("RecoveryAlreadyRunningOrLockUnavailable") from None
        backup = Path(BACKUP)
        _physical_root_path(backup, mode=0o700)
        _private_bytes(backup / "COMPLETE", maximum=1)
        self.dump_data = _private_bytes(backup / "keycloak.dump", expected_sha256=DUMP_SHA256)
        _private_bytes(backup / "config.tar.gz", expected_sha256=CONFIG_SHA256)
        require(_private_bytes(backup / "distribution.txt", maximum=256).decode().strip() ==
                "/opt/keycloak/keycloak-26.8.1", "BackupDistributionMismatch")
        self.configuration = _private_bytes(Path("/etc/keycloak/keycloak.conf"), mode=0o640, maximum=65536)
        # Parse before any mutation, but never save/print derived secret config.
        candidate_configuration(self.configuration.decode(), self.plan["candidate_database"])
        self.current = collect_inventory("keycloak", runner=self.runner)
        size = self.runner(_psql_argv("postgres"), input_bytes=(
            "SELECT pg_database_size('keycloak');").encode(), maximum_output=1024)
        try:
            database_size = int(size.strip())
            available_memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                                        if line.startswith('MemAvailable:'))) * 1024
            distribution = Path("/opt/keycloak/keycloak-26.8.1")
            _physical_root_path(distribution)
            files = [entry for entry in distribution.rglob('*') if entry.is_file() and not entry.is_symlink()]
            require(len(files) <= 10000, "DistributionInventoryBoundExceeded")
            distribution_size = sum(entry.stat().st_size for entry in files)
            volume = os.statvfs("/var/lib/postgresql/16/keycloak")
            capacity = {"free_bytes": volume.f_bavail * volume.f_frsize,
                        "available_memory_bytes": available_memory, "current_database_bytes": database_size,
                        "distribution_bytes": distribution_size, "dump_bytes": len(self.dump_data)}
        except (OSError, ValueError, StopIteration):
            raise RecoveryRefused("CapacityEvidenceUnavailable") from None
        self.capacity = validate_capacity(capacity)
        _private_bytes(Path("/usr/local/sbin/keycloak-backup"), mode=0o700,
                       expected_sha256=self.BACKUP_SCRIPT_SHA256)
        return {"verified": True, "candidate_capacity_sufficient": True}

    def backup(self):
        require(self.dump_data is not None and self.current is not None, "PrepareNotVerified")
        parent = Path("/var/backups/keycloak")
        before = set(parent.iterdir())
        self.runner(["/usr/local/sbin/keycloak-backup"], maximum_output=4096, timeout=120)
        added = set(parent.iterdir()) - before
        require(len(added) == 1, "ConcurrentOrMissingForensicBackup")
        self.forensic = added.pop()
        _physical_root_path(self.forensic, mode=0o700)
        _private_bytes(self.forensic / "COMPLETE", maximum=1)
        self.forensic_dump_sha256 = hashlib.sha256(_private_bytes(self.forensic / "keycloak.dump")).hexdigest()
        self.forensic_config_sha256 = hashlib.sha256(_private_bytes(self.forensic / "config.tar.gz")).hexdigest()
        # A separate root-owned namespace avoids all existing backup ownership.
        root = Path("/var/backups/keycloak-recovery")
        _physical_root_path(root.parent)
        if not root.exists() and not root.is_symlink():
            root.mkdir(mode=0o700)
        _physical_root_path(root, mode=0o700)
        self.stage = root / self.plan["candidate_database"]
        self.stage.mkdir(mode=0o700, exist_ok=False)
        _write_private(self.stage / "current-before.json", self.current)
        return {"verified": True, "forensic_backup_preserved": True}

    def restore(self):
        require(self.stage is not None and self.forensic is not None and self.dump_data is not None,
                "ForensicBackupRequired")
        candidate = self.plan["candidate_database"]
        exists = self.runner(_psql_argv("postgres"), input_bytes=(
            "SELECT count(*) FROM pg_database WHERE datname='" + candidate + "';").encode(), maximum_output=1024)
        require(exists.strip() == b"0", "CandidateDatabaseAlreadyExists")
        self.runner(_psql_argv("postgres", readonly=False),
                    input_bytes=self.plan["restore"]["create"].encode(), maximum_output=4096)
        self.runner(self.plan["restore"]["argv"], input_bytes=self.dump_data,
                    maximum_output=65536, timeout=180)
        self.dump_data = None
        return {"restored": True, "canonical_database_unchanged": True}

    def inventory(self):
        require(self.stage is not None and self.dump_data is None, "CandidateRestoreRequired")
        candidate = collect_inventory(self.plan["candidate_database"], runner=self.runner)
        # Structural/ACL drift is NEVER waived by review of data-row differences.
        drift = compare_snapshots(candidate, self.current)
        _write_private(self.stage / "candidate-restored.json", candidate)
        _write_private(self.stage / "unreviewed-original-current-drift.json", drift)
        _write_private(self.stage / "context.json", {
            "schema": "keycloak_identity_recovery_context_v1", "status": "RestoredReviewRequired",
            "candidate_database": self.plan["candidate_database"],
            "candidate_oid": candidate["database_oid"], "current_oid": self.current["database_oid"],
            "backup_dump_sha256": DUMP_SHA256, "backup_config_sha256": CONFIG_SHA256,
            "current_config_sha256": hashlib.sha256(self.configuration).hexdigest(),
            "forensic_directory": str(self.forensic), "forensic_dump_sha256": self.forensic_dump_sha256,
            "forensic_config_sha256": self.forensic_config_sha256,
            "structural_schema_sha256": candidate["schema_sha256"],
            "candidate_jvm_started": False, "api_writes": 0, "live_service_changed": False,
            "switch_ready": False,
        })
        return {"restored_review_required": True, "private_receipt_directory": str(self.stage)}


def validate_identity(backup, candidate):
    require(isinstance(backup, dict) and isinstance(candidate, dict), "IdentityEvidenceMalformed")
    expected = {"user_id_sha256": ORIGINAL_SUBJECT_SHA256,
                "created_timestamp": 1793048930752,
                "federation_link_sha256": FEDERATION_SHA256,
                "ldap_guid": PILOT_GUID, "realm_user_count": 1, "enabled": True}
    for evidence in (backup, candidate):
        require(all(evidence.get(key) == value for key, value in expected.items()),
                "OriginalPilotIdentityMismatch")
        credentials = evidence.get("credentials")
        require(isinstance(credentials, list) and len(credentials) == 1 and
                isinstance(credentials[0], dict) and
                credentials[0].get("type") == "otp" and
                credentials[0].get("created_date") == 1793051223562 and
                is_hash(credentials[0].get("row_sha256")), "OriginalOtpEvidenceMissing")
    require(backup["credentials"] == candidate["credentials"], "OriginalOtpBytesOrMetadataChanged")


def _names(candidate):
    require(isinstance(candidate, str) and
            re.fullmatch(r"keycloak_recovery_20261027_[0-9a-f]{8}", candidate) is not None,
            "ExclusiveCandidateNameRequired")
    suffix = candidate.removeprefix("keycloak_recovery_")
    return candidate, "keycloak_forensic_" + suffix, "keycloak_failed_" + suffix


def _guard_sql(first_name, first_oid, second_name, second_oid, absent_name):
    require(type(first_oid) is int and type(second_oid) is int and
            0 < first_oid < 2**32 and 0 < second_oid < 2**32 and first_oid != second_oid,
            "DistinctDatabaseOidsRequired")
    # Names are internal constants or validated by _names; no caller SQL input.
    return f"""DO $recovery$
BEGIN
 IF current_database() <> 'postgres' OR current_setting('port') <> '5544'
    OR current_setting('server_version_num')::int NOT BETWEEN 160000 AND 169999
    OR current_user <> 'postgres' THEN RAISE EXCEPTION 'RecoveryClusterMismatch'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='{first_name}' AND oid={first_oid}
                AND datdba=(SELECT oid FROM pg_roles WHERE rolname='keycloak'))
    OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='{second_name}' AND oid={second_oid}
                AND datdba=(SELECT oid FROM pg_roles WHERE rolname='keycloak'))
    OR EXISTS (SELECT 1 FROM pg_database WHERE datname='{absent_name}')
    THEN RAISE EXCEPTION 'RecoveryDatabaseIdentityMismatch'; END IF;
 IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datid IN ({first_oid},{second_oid}))
    OR EXISTS (SELECT 1 FROM pg_prepared_xacts WHERE database IN ('{first_name}','{second_name}'))
    THEN RAISE EXCEPTION 'RecoveryDatabaseBusy'; END IF;
END $recovery$;
"""


def switch_sql(candidate, current_oid, candidate_oid):
    candidate, forensic, _ = _names(candidate)
    return ("BEGIN;\nSET LOCAL lock_timeout='5s';\nSET LOCAL statement_timeout='15s';\n" +
            _guard_sql("keycloak", current_oid, candidate, candidate_oid, forensic) +
            'ALTER DATABASE "keycloak" ALLOW_CONNECTIONS false;\n' +
            f'ALTER DATABASE "{candidate}" ALLOW_CONNECTIONS false;\n' +
            f'ALTER DATABASE "keycloak" RENAME TO "{forensic}";\n' +
            f'ALTER DATABASE "{candidate}" RENAME TO "keycloak";\n' +
            'ALTER DATABASE "keycloak" ALLOW_CONNECTIONS true;\nCOMMIT;\n')


def rollback_sql(candidate, original_oid, candidate_oid):
    _, forensic, failed = _names(candidate)
    return ("BEGIN;\nSET LOCAL lock_timeout='5s';\nSET LOCAL statement_timeout='15s';\n" +
            _guard_sql("keycloak", candidate_oid, forensic, original_oid, failed) +
            'ALTER DATABASE "keycloak" ALLOW_CONNECTIONS false;\n' +
            f'ALTER DATABASE "keycloak" RENAME TO "{failed}";\n' +
            f'ALTER DATABASE "{forensic}" RENAME TO "keycloak";\n' +
            'ALTER DATABASE "keycloak" ALLOW_CONNECTIONS true;\nCOMMIT;\n')


def build_plan():
    candidate = "keycloak_recovery_20261027_" + secrets.token_hex(4)
    _, forensic, failed = _names(candidate)
    return {
        "schema": "keycloak_identity_recovery_plan_v1", "status": "PlanOnly",
        "apply_supported": False, "switch_ready": False,
        "target_host": "192.168.100.19", "keycloak_version": "26.8.1",
        "canonical_database": "keycloak", "port": 5544, "owner": "keycloak",
        "candidate_database": candidate, "forensic_database": forensic,
        "failed_candidate_database": failed, "audit_clone_reusable": False,
        "backup": {"directory": BACKUP, "dump_sha256": DUMP_SHA256,
                   "config_sha256": CONFIG_SHA256, "restore_config_archive": False},
        "restore": {"argv": ["runuser", "-u", "postgres", "--", "pg_restore", "--port", "5544",
                             "--dbname", candidate, "--no-owner", "--role=keycloak",
                             "--single-transaction", "--exit-on-error"],
                    "stdin_from_verified_dump": True,
                    "create": f'CREATE DATABASE "{candidate}" OWNER keycloak TEMPLATE template0;\n'
                              f'REVOKE ALL ON DATABASE "{candidate}" FROM PUBLIC;',
                    "overwrite_or_drop_existing": False},
        "required_evidence": list(REQUIRED_EVIDENCE),
        "sequence": [
            "Independent review of source, scratch PG16 proof, actual no-secret inventory collector and isolated candidate executor",
            "Verify original dump/config digests, COMPLETE, paths/permissions, disk capacity; capture current config/distribution/service identities",
            "Full current DB/config forensic backup; preserve all audit records and failed harness receipts",
            "Claim fresh candidate name/OID owned keycloak; restore verified dump via stdin, never reuse metadata audit DB",
            "Compare all101 table row multisets plus schema/ACLs; review exact old/current drift; refuse unknown users/clients/keys/roles/config changes",
            "Start isolated loopback candidate with separate cache/ports, no Nginx/public routing and correct dedicated candidate JDBC identity",
            "Before any pilot user lookup apply reviewed retention + MSAD always-read + NO_CACHE guard, audience/basic API repairs",
            "Before session APIs prove ALL-realm admin/backchannel URLs, IdPs, SMTP and custom outgoing providers absent; loopback alone is insufficient",
            "Through candidate Admin API purge offline sessions then online logout per non-master realm, raise notBefore after old/test token iat; fresh master admin NB<=its iat, master logout-all LAST; no more authenticated APIs",
            "Stop candidate and SQL-prove zero persisted online/offline/auth sessions, original UUID/OTP/GUID unchanged; nonzero auth-session rows HOLD for supported expiry/removal",
            "Stop isolated candidate; require fresh all-table exact reviewed API changes and current config/AD/client/session/app-flag evidence",
            "After explicit approval stop ONLY keycloak; fresh post-stop forensic snapshot; recheck exact current/candidate OIDs, owner, zero connections/prepared xacts",
            "One postgres-connected transaction renames original to forensic and candidate to canonical; keep forensic inaccessible, no backend kills",
            "Start ONLY keycloak; strict-TLS health, exact original subject/OTP metadata and repaired LDAP guard; normal canonical backup path remains keycloak",
            "Any switch/start/health failure: stop ONLY keycloak, classify exact OID/name state, transactional reverse renames; preserve failed candidate; health original",
        ],
        "rollback_warning": "Never rollback after unknown users/clients/legitimate writes without a new drift review; partial/ambiguous rename states require HOLD",
        "live_mutations_performed": False,
    }


def read_evidence(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 32 * 1024 * 1024,
            "EvidenceFileInvalid")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise RecoveryRefused("EvidenceFileUnreadable") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", nargs=3, type=Path, metavar=("BEFORE", "AFTER", "REVIEWED_DIFF"))
    parser.add_argument("--prepare-candidate", action="store_true",
                        help="After independent review only: forensic backup and fresh exclusive restore; stop before JVM/API/live service")
    args = parser.parse_args()
    try:
        require(not (args.compare and args.prepare_candidate), "ConflictingOperationModes")
        if args.prepare_candidate:
            operations = PrepareOperations()
            try:
                result = prepare_candidate(operations)
                result.update(candidate_database=operations.plan["candidate_database"],
                              private_receipt_directory=str(operations.stage))
                print(json.dumps(result))
            finally:
                operations.close()
        elif args.compare:
            before, after, reviewed = (read_evidence(path) for path in args.compare)
            validate_reviewed_drift(before, after, reviewed)
            # Do not echo digests, arbitrary input fields or sensitive row data.
            print(json.dumps({"status": "ExactReviewedDriftMatches", "switch_ready": False,
                              "live_mutations_performed": False}))
        else:
            print(json.dumps(build_plan(), indent=2))
    except RecoveryRefused as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
