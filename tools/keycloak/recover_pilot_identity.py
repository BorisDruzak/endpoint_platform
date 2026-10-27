"""Plan, restore and privately qualify the fixed synthetic pilot identity.

Full-database recovery is required to preserve the original Keycloak UUID and
OTP bytes. Never write user/credential rows or reenrol OTP. Explicit private
qualification is reviewed separately and cannot promote a candidate: there is
no canonical database/service switch command.

Pinned primary references (Context7 quota unavailable):
https://www.postgresql.org/docs/16/sql-alterdatabase.html
https://www.postgresql.org/docs/16/app-pgrestore.html
https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/dbcommands.c
https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import io
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import tempfile
import tarfile
import time
import urllib.error
import urllib.request
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
# Narayana7.3.4.Final CoreEnvironmentBean @FullPropertyName; native library-only
# proof is required before this private profile may be qualified.
# https://github.com/jbosstm/narayana/blob/7.3.4.Final/ArjunaCore/arjuna/classes/com/arjuna/ats/arjuna/common/CoreEnvironmentBean.java
PRIVATE_PROCESS_ID_PROPERTY = ('-Dcom.arjuna.ats.internal.arjuna.utils.processImplementation='
                               'com.arjuna.ats.internal.arjuna.utils.MBeanProcessId')
DISTRIBUTION_ARCHIVE = Path('/root/keycloak-input/keycloak-26.8.1.tar.gz')
DISTRIBUTION_ARCHIVE_SHA256 = '4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8'
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


class RecoveryCleanupFailure(RecoveryRefused):
    """Carry only sanitized primary/cleanup metadata across nested cleanup."""
    def __init__(self, code, primary, cleanup):
        if code not in {'PrivateBuildCleanupHold', 'PrivateRuntimeCleanupHold'}:
            raise RecoveryRefused('CleanupFailureCodeInvalid')
        super().__init__(code)
        self.primary_metadata = dict(primary.primary_metadata) if type(primary) is RecoveryCleanupFailure \
                                else _safe_error_metadata(primary)
        self.cleanup_metadata = _safe_error_metadata(cleanup)


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


def validate_outbound_metadata(evidence):
    """Loopback/cache isolation alone does not prevent backchannel HTTP effects.

    Full restored ALL-realm inventory plus pinned distribution/provider closure
    must establish absence before logout/session DELETE APIs; no blanket bypass.
    """
    require(isinstance(evidence, dict), "OutboundEvidenceMissing")
    for key in ("admin_url_count", "backchannel_url_count", "identity_provider_count", "smtp_entry_count"):
        require(type(evidence.get(key)) is int and evidence[key] == 0, "CandidateOutboundEffectPossible")
    require(evidence.get("event_listeners") == ["jboss-logging"], "CandidateCustomListenerPossible")
    require(type(evidence.get('storage_provider_count')) is int and evidence['storage_provider_count'] == 1 and
            evidence.get('ldap_configuration_safe') is True, 'CandidateLdapScopeOrScheduledSyncUnsafe')


def validate_outbound_safety(evidence):
    validate_outbound_metadata(evidence)
    require(type(evidence.get('custom_provider_artifact_count')) is int and
            evidence['custom_provider_artifact_count'] == 0, 'CustomProviderClosureRequired')


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


def candidate_configuration(source, candidate, *, browser_tls=False):
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
    require(type(browser_tls) is bool, "InvalidBrowserTlsProfile")
    if browser_tls:
        private = "/var/lib/keycloak-recovery-v8/" + candidate
        values.update({"hostname": "https://sso.sosnadmin.local:18449", "https-port": "8449",
                       "https-certificate-file": private + "/tls/fullchain.pem",
                       "https-certificate-key-file": private + "/tls/key.pem",
                       "http-management-scheme": "http"})
    return "".join(key + "=" + value + "\n" for key, value in values.items())


def runtime_recipe(candidate, *, browser_tls=False):
    """No shared mutable live tree or inherited KC/JAVA/secret environment."""
    _names(candidate)
    private = "/var/lib/keycloak-recovery-v8/" + candidate
    distribution = private + "/keycloak-26.8.1"
    result = {"directory": private, "distribution": distribution,
            "cache": "local", "http": "127.0.0.1:8089", "management": "127.0.0.1:9009",
            "shared_mutable_paths": [],
            "argv": ["runuser", "-u", "keycloak", "--", "env", "-i",
                     "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + private,
                     "TMPDIR=" + private + "/tmp", "JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m",
                     "JAVA_OPTS_APPEND=-Djava.io.tmpdir=" + private + "/tmp -Duser.home=" + private + "/work " + PRIVATE_PROCESS_ID_PROPERTY,
                     distribution + "/bin/kc.sh", "--config-file=" + private + "/candidate.conf",
                     "start", "--optimized"]}
    require(type(browser_tls) is bool, "InvalidBrowserTlsProfile")
    if browser_tls:
        result.update(https="127.0.0.1:8449", browser_origin="https://sso.sosnadmin.local:18449",
                      browser_network_permission="ExactCandidateOriginAndInterceptedCallbacksOnly")
    return result


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
            "prove_browser_cookie_before_purge",
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


def _owned_build_members(group, prefix):
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            if os.getpgid(pid) != group:
                continue
            if (entry / 'stat').read_text().rpartition(')')[2].split()[0] == 'Z':
                continue
            require(entry.stat().st_uid == 0 and prefix.encode() in (entry / 'cmdline').read_bytes(),
                    'PrivateBuildCleanupHold')
            members.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


def _stop_owned_build_group(process, prefix, forbidden, start):
    require(process.pid not in set(forbidden) | {os.getpgrp()}, 'PrivateBuildCleanupHold')
    members = _owned_build_members(process.pid, prefix)
    if not members:
        process.wait(timeout=5)
        return
    if process.poll() is None:
        try:
            require(start is not None and _pid_start(process.pid) == start and os.getpgid(process.pid) == process.pid,
                    'PrivateBuildCleanupHold')
        except (ProcessLookupError, FileNotFoundError):
            pass
    os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _owned_build_members(process.pid, prefix):
        time.sleep(0.1)
    if _owned_build_members(process.pid, prefix):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and _owned_build_members(process.pid, prefix):
        time.sleep(0.1)
    require(not _owned_build_members(process.pid, prefix), 'PrivateBuildCleanupHold')


def _run_owned_private_group(argv, *, input_bytes, output, timeout, cwd, environment, prefix, forbidden, process_receipt=None):
    require(re.fullmatch(r'/var/lib/keycloak-recovery-v8/keycloak_recovery_20261027_[0-9a-f]{8}', prefix),
            'PrivateBuildPrefixInvalid')
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                               stdout=output, stderr=subprocess.DEVNULL, cwd=cwd, env=environment,
                               start_new_session=True)
    start = None
    primary_error = None
    try:
        if process.poll() is None:
            start = _pid_start(process.pid)
        if process_receipt is not None:
            _write_private(process_receipt, {'pid': process.pid, 'pgid': process.pid, 'start_ticks': start,
                'private_prefix': prefix, 'forbidden_groups': sorted(forbidden),
                'argv_sha256': hashlib.sha256(json.dumps(argv, separators=(',', ':')).encode()).hexdigest()})
        process.communicate(input=input_bytes, timeout=timeout)
        return process
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            _stop_owned_build_group(process, prefix, forbidden, start)
        except BaseException as cleanup_error:
            raise RecoveryCleanupFailure('PrivateBuildCleanupHold',
                                         primary_error if primary_error is not None else cleanup_error,
                                         cleanup_error) from None


def _run_private(argv, *, input_bytes=None, maximum_output=32 * 1024 * 1024, timeout=45, cwd=None,
                 owned_group_prefix=None, forbidden_group_ids=(), process_receipt=None):
    """No shell, inherited credentials, child stderr or unbounded stdout in memory."""
    require(sys.platform == "linux" and os.geteuid() == 0, "ApprovedLinuxRootRequired")
    try:
        host = subprocess.run(["hostname", "-I"], check=True, capture_output=True,
                              timeout=5, env={"PATH": SYSTEM_PATH})
        require(b"192.168.100.19" in host.stdout.split(), "ApprovedHostRequired")
        with tempfile.TemporaryFile() as output:
            environment = {"PATH": SYSTEM_PATH, "LANG": "C.UTF-8"}
            if owned_group_prefix is not None:
                result = _run_owned_private_group(argv, input_bytes=input_bytes, output=output, timeout=timeout,
                    cwd=cwd, environment=environment, prefix=owned_group_prefix, forbidden=forbidden_group_ids,
                    process_receipt=process_receipt)
            else:
                result = subprocess.run(argv, input=input_bytes, stdout=output, stderr=subprocess.DEVNULL,
                                        timeout=timeout, check=False, cwd=cwd, env=environment)
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


class _CandidateNoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RecoveryRefused("CandidateRedirectProhibited")


def candidate_token_shape_metadata(token, *, now):
    """Unverified-claim diagnostic only; fixed booleans, never an auth decision.

    Keep all constructor/API/database guards independent of this witness. No
    token, SID, claim value, timestamp, payload or fingerprint is returned.
    """
    result = dict.fromkeys(('bounded_compact_token', 'claims_object', 'iat_positive_integer',
        'exp_after_iat', 'expected_master_issuer', 'expected_admin_cli', 'canonical_sid',
        'remaining_lifetime_at_least_45_seconds', 'signature_verified'), False)
    result['bounded_compact_token'] = bool(type(token) is str and len(token) <= 16384 and
        re.fullmatch(r'[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', token))
    if not result['bounded_compact_token']:
        return result
    try:
        payload = token.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        if type(claims) is not dict:
            return result
        result['claims_object'] = True
        issued, expires = claims.get('iat'), claims.get('exp')
        result['iat_positive_integer'] = type(issued) is int and issued > 0
        result['exp_after_iat'] = result['iat_positive_integer'] and type(expires) is int and expires > issued
        result['expected_master_issuer'] = claims.get('iss') == 'https://sso.sosnadmin.local:18449/realms/master'
        result['expected_admin_cli'] = claims.get('azp') == 'admin-cli'
        result['remaining_lifetime_at_least_45_seconds'] = bool(result['exp_after_iat'] and
            type(now) is int and expires - now >= 45)
        sid = claims.get('sid')
        result['canonical_sid'] = type(sid) is str and str(uuid.UUID(sid)) == sid
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError, RecursionError):
        pass
    return result


class CandidateSessionClient:
    """Exact one-shot session API scope, fresh PID/DB/socket proof each request.

    No password/user/client/credential methods. Caller supplies a fresh master
    token from the separately reviewed pilot helper after candidate isolation.
    This transport is used only by the explicit private qualification command.
    """
    def __init__(self, token, *, runtime_verifier, transport=None):
        require(callable(runtime_verifier), "RuntimeVerifierRequired")
        validate_runtime_proof(runtime_verifier())
        require(isinstance(token, str) and len(token) <= 16384 and
                re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", token),
                "CandidateTokenMalformed")
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            issued = claims["iat"]
            require(type(issued) is int and issued > 0, "CandidateTokenIatInvalid")
            expires = claims['exp']
            require(type(expires) is int and expires > issued and
                    claims.get('iss') == 'https://sso.sosnadmin.local:18449/realms/master' and
                    claims.get('azp') == 'admin-cli', 'CandidateTokenProvenanceInvalid')
            session_id = str(uuid.UUID(claims['sid']))
            require(session_id == claims['sid'], 'CandidateTokenSidInvalid')
        except RecoveryRefused:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise RecoveryRefused("CandidateTokenMalformed") from None
        self.token, self._admin_iat = token, issued
        self.expires_at, self.session_id = expires, session_id
        self.runtime_verifier = runtime_verifier
        self.not_before_payloads = {}
        self.session_delete_paths = set()
        self.logout_paths = set()
        self.requests = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _CandidateNoRedirects())
        self.transport = transport or self._send

    @property
    def admin_iat(self):
        return self._admin_iat

    def _send(self, request):
        try:
            with self.opener.open(request, timeout=10) as response:
                body = response.read(2 * 1024 * 1024 + 1)
                require(len(body) <= 2 * 1024 * 1024, "CandidateResponseBoundExceeded")
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            code = ('CandidateHTTP' + str(error.code) if type(error.code) is int and
                    100 <= error.code <= 599 else 'CandidateHTTPUnclassified')
            raise RecoveryRefused(code) from None
        except RecoveryRefused:
            raise
        except (urllib.error.URLError, TimeoutError, ValueError, UnicodeError):
            raise RecoveryRefused("CandidateRequestFailed") from None

    def request(self, method, path, *, payload=None):
        read = method == "GET" and payload is None and path in {
            "/admin/realms", "/admin/realms/master", "/admin/realms/sosnadmin"}
        realm = next((name for name in ("master", "sosnadmin") if path == "/admin/realms/" + name), None)
        before = (method == "PUT" and realm in self.not_before_payloads and
                  type(self.not_before_payloads[realm]) is int and self.not_before_payloads[realm] == self.admin_iat and
                  isinstance(payload, dict) and set(payload) == {'notBefore'} and
                  type(payload['notBefore']) is int and payload['notBefore'] == self.admin_iat and self.admin_iat > 0)
        delete = (method == "DELETE" and payload is None and path in self.session_delete_paths and
                  re.fullmatch(r"/admin/realms/(master|sosnadmin)/sessions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\?isOffline=true", path))
        logout = (method == "POST" and payload is None and path in self.logout_paths and
                  path in {"/admin/realms/master/logout-all", "/admin/realms/sosnadmin/logout-all"})
        require(read or before or delete or logout, "CandidateMutationProhibited")
        validate_runtime_proof(self.runtime_verifier())
        self.requests += 1
        require(self.requests <= 128, "CandidateRequestBudgetExceeded")
        # Consume BEFORE network: uncertain outcomes cannot be blindly replayed.
        if before:
            del self.not_before_payloads[realm]
        if delete:
            self.session_delete_paths.remove(path)
        if logout:
            self.logout_paths.remove(path)
        headers = {"Accept": "application/json", "Authorization": "Bearer " + self.token}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        request = urllib.request.Request("http://127.0.0.1:8089" + path, method=method, data=data, headers=headers)
        return self.transport(request)


def validate_distribution_manifest(manifest, *, live_source):
    require(isinstance(manifest, dict) and 1 <= len(manifest) <= 10000, "DistributionManifestInvalid")
    if live_source:
        require(manifest.get('data', {}).get('kind') == 'symlink' and
                manifest['data'].get('target') == '/var/lib/keycloak', 'LiveDataLinkContractMismatch')
    files = {}
    for relative, entry in manifest.items():
        require(isinstance(relative, str) and relative and not relative.startswith('/') and
                all(piece not in {'', '.', '..'} for piece in relative.split('/')) and isinstance(entry, dict),
                "DistributionPathInvalid")
        require(entry.get("uid") == 0, "DistributionForeignOwner")
        if entry.get("kind") == "symlink":
            require(live_source is True and relative == "data" and entry.get("target") == "/var/lib/keycloak",
                    "DistributionLinkEscape")
            continue
        require(entry.get("kind") in {"file", "directory"} and type(entry.get("mode")) is int and
                not entry["mode"] & 0o022, "DistributionWritableOrSpecial")
        if entry["kind"] == "file":
            require(is_hash(entry.get("sha256")), "DistributionFileDigestInvalid")
            require(not relative.startswith("providers/") or relative == "providers/README.md",
                    "CustomOutboundProviderProhibited")
            files[relative] = {"sha256": entry["sha256"], "mode": entry["mode"]}
    require("bin/kc.sh" in files, "DistributionLauncherMissing")
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {"sha256": digest, "binary_files": len(files), "custom_provider_artifact_count": 0}


def distribution_inventory(root, *, live_source):
    _physical_root_path(root)
    if live_source:
        # Fail BEFORE walking any unexpectedly physical live data directory.
        data_metadata = (root / 'data').lstat()
        require(stat.S_ISLNK(data_metadata.st_mode) and data_metadata.st_uid == 0 and
                os.readlink(root / 'data') == '/var/lib/keycloak', 'LiveDataLinkContractMismatch')
    manifest = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs + files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if relative == "data" and not live_source:
                # Physical private data is verified separately and never read
                # into the immutable distribution closure.
                require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
                        "PrivateDataMustBePhysical")
                dirs.remove("data")
                continue
            entry = {"uid": metadata.st_uid, "mode": stat.S_IMODE(metadata.st_mode)}
            if stat.S_ISLNK(metadata.st_mode):
                entry.update(kind="symlink", target=os.readlink(path))
                if name in dirs:
                    dirs.remove(name)
            elif stat.S_ISDIR(metadata.st_mode):
                entry["kind"] = "directory"
            elif stat.S_ISREG(metadata.st_mode):
                require(metadata.st_size <= 256 * 1024 * 1024, "DistributionFileBoundExceeded")
                entry.update(kind="file", sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                raise RecoveryRefused("DistributionSpecialFile")
            manifest[relative] = entry
            require(len(manifest) <= 10000, "DistributionInventoryBoundExceeded")
    return validate_distribution_manifest(manifest, live_source=live_source)


def validate_archive_members(members):
    require(isinstance(members, list) and 1 <= len(members) <= 20000, 'DistributionArchiveBoundExceeded')
    names, total, files = set(), 0, 0
    for member in members:
        path = PurePosixPath(member.name)
        require(not path.is_absolute() and path.parts and path.parts[0] == 'keycloak-26.8.1' and
                '..' not in path.parts and '\\' not in member.name and path.as_posix() not in names and
                (member.isfile() or member.isdir()) and type(member.size) is int and
                0 <= member.size <= 256 * 1024**2, 'UnsafeDistributionArchiveMember')
        names.add(path.as_posix())
        total += member.size
        files += int(member.isfile())
    require(total <= 1024**3 and files > 0, 'DistributionArchiveBoundExceeded')
    return {'files': files, 'uncompressed_bytes': total}


def private_build_recipe(candidate):
    _names(candidate)
    private = '/var/lib/keycloak-recovery-v8/' + candidate
    return {'archive_sha256': DISTRIBUTION_ARCHIVE_SHA256, 'network_namespace': True,
            'cwd': private + '/build-home',
            'argv': ['unshare', '--net', '--', 'env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8',
                     'HOME=' + private + '/build-home', 'TMPDIR=' + private + '/build-tmp',
                     'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx1024m',
                     'JAVA_OPTS_APPEND=-Djava.io.tmpdir=' + private + '/build-tmp -Duser.home=' + private + '/build-home',
                     private + '/keycloak-26.8.1/bin/kc.sh', 'build', '--db=postgres', '--health-enabled=true',
                     '--metrics-enabled=false', '--cache=local']}


def _pid_start(pid):
    try:
        fields = Path('/proc/' + str(pid) + '/stat').read_text().rpartition(')')[2].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        raise RecoveryRefused("ProcessIdentityUnavailable") from None


def _exact_loopback_port(endpoint, expected_port=None):
    """Strict ss numeric endpoint; mapped IPv6 may denote ONLY 127.0.0.1.

    No broad is_loopback test: ::1/other127/wildcards/names/zones are rejected.
    https://docs.python.org/3.12/library/ipaddress.html#ipaddress.IPv6Address.ipv4_mapped
    """
    if type(endpoint) is not str or len(endpoint) > 128 or \
       expected_port is not None and (type(expected_port) is not int or not 1 <= expected_port <= 65535):
        return None
    mapped = re.fullmatch(r'\[([0-9A-Fa-f:.]+)\]:([1-9][0-9]{0,4})', endpoint)
    if mapped:
        try:
            if ipaddress.IPv6Address(mapped[1]).ipv4_mapped != ipaddress.IPv4Address('127.0.0.1'):
                return None
        except ValueError:
            return None
        port = int(mapped[2])
    else:
        plain = re.fullmatch(r'127\.0\.0\.1:([1-9][0-9]{0,4})', endpoint)
        if plain is None:
            return None
        port = int(plain[1])
    return port if 1 <= port <= 65535 and (expected_port is None or port == expected_port) else None


def _socket_summary(lines):
    """Refusal evidence only: bounded numbers/fixed classes, never raw endpoints.

    These classifications grant no socket permission; the exact3TCP/zeroUDP
    policy is enforced separately and unchanged.
    """
    classes = dict.fromkeys(('ipv4_exact_loopback', 'ipv4_mapped_exact_loopback',
                             'other_loopback', 'wildcard', 'non_loopback', 'unparseable'), 0)
    ports = set()
    for line in lines:
        fields = line.split()
        endpoint = fields[3] if len(fields) >= 5 else ''
        host, separator, tail = endpoint.rpartition(':')
        if separator and re.fullmatch(r'[1-9][0-9]{0,4}', tail) and int(tail) <= 65535:
            ports.add(int(tail))
        label = 'unparseable'
        try:
            if host == '*':
                label = 'wildcard'
            else:
                if host.startswith('[') and host.endswith(']') and re.fullmatch(r'[0-9A-Fa-f:.]+', host[1:-1]):
                    address = ipaddress.IPv6Address(host[1:-1])
                else:
                    address = ipaddress.IPv4Address(host)
                mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
                if mapped == ipaddress.IPv4Address('127.0.0.1'):
                    label = 'ipv4_mapped_exact_loopback'
                elif address == ipaddress.IPv4Address('127.0.0.1'):
                    label = 'ipv4_exact_loopback'
                elif address.is_unspecified or mapped is not None and mapped.is_unspecified:
                    label = 'wildcard'
                elif address.is_loopback or mapped is not None and mapped.is_loopback:
                    label = 'other_loopback'
                else:
                    label = 'non_loopback'
        except ValueError:
            pass
        classes[label] += 1
    return {'count': len(lines), 'ports': sorted(ports)[:64], 'endpoint_classes': classes,
            'ports_truncated': len(ports) > 64}


def canonical_java_from_metadata(main_pid, uid, approved_exe, records):
    require(isinstance(records, list) and 1 <= len(records) <= 10000, 'CanonicalProcessMetadataInvalid')
    by_pid = {item['pid']: item for item in records}
    require(len(by_pid) == len(records) and main_pid in by_pid and by_pid[main_pid]['uid'] == uid,
            'CanonicalMainProcessMismatch')
    descendants = {main_pid}
    while True:
        expanded = descendants | {item['pid'] for item in records if item['ppid'] in descendants}
        if expanded == descendants:
            break
        descendants = expanded
    java = [item for item in records if item['pid'] in descendants and item.get('exe') == approved_exe]
    require(len(java) == 1 and java[0]['uid'] == uid and type(java[0]['start_ticks']) is int and
            java[0]['start_ticks'] > 0, 'CanonicalJavaDescendantNotUnique')
    return java[0]


def _canonical_java_reference(main_pid, uid):
    records = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rpartition(')')[2].split()
            records.append({'pid': int(entry.name), 'ppid': int(fields[1]),
                            'uid': entry.stat().st_uid, 'start_ticks': int(fields[19])})
        except (OSError, ValueError, IndexError):
            continue
    descendants = {main_pid}
    while True:
        expanded = descendants | {item['pid'] for item in records if item['ppid'] in descendants}
        if expanded == descendants:
            break
        descendants = expanded
    scoped = [item for item in records if item['pid'] in descendants]
    for item in scoped:
        try:
            item['exe'] = os.readlink('/proc/' + str(item['pid']) + '/exe')
        except OSError:
            item['exe'] = None
    approved = str(Path('/usr/bin/java').resolve())
    require(approved == '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', 'ApprovedJava21Required')
    _physical_root_path(Path(approved))
    return canonical_java_from_metadata(main_pid, uid, approved, scoped)


def _capture_canonical_reference(prepared, uid, *, runner):
    """Compare systemd exec events exactly, then bind separate proc identities.

    /proc start ticks describe process creation, while systemd's timestamp
    describes exec start. Comparing their difference against a tick tolerance
    cannot establish identity. Neither clock/event is converted here.
    """
    fields = {'MainPID', 'ExecMainStartTimestampMonotonic', 'ActiveState'}
    require(type(prepared) is dict and set(prepared) == fields and
            prepared.get('ActiveState') == 'active' and all(
                type(prepared.get(key)) is str and prepared[key].isdigit() and int(prepared[key]) > 0
                for key in ('MainPID', 'ExecMainStartTimestampMonotonic')), 'PreparedCanonicalServiceInvalid')
    def verify_service():
        output = runner(['systemctl', 'show', 'keycloak',
                         '--property=MainPID,ExecMainStartTimestampMonotonic,ActiveState'], maximum_output=65536)
        try:
            rows = [line.split('=', 1) for line in output.decode().splitlines()]
            require(len(rows) == len(fields) and all(len(row) == 2 for row in rows),
                    'CanonicalServiceMetadataInvalid')
            require(dict(rows) == prepared, 'CanonicalProcessChangedSincePrepare')
        except UnicodeError:
            raise RecoveryRefused('CanonicalServiceMetadataInvalid') from None
    verify_service()
    main_pid = int(prepared['MainPID'])
    main_start = _pid_start(main_pid)
    reference = _canonical_java_reference(main_pid, uid)
    verify_service()
    require(_pid_start(main_pid) == main_start and
            _pid_start(reference['pid']) == reference['start_ticks'], 'CanonicalProcessChangedDuringProbe')
    return main_pid, main_start, reference


def _write_group_binary(path, data, group):
    _physical_root_path(path.parent)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), 0, group)
            os.fchmod(stream.fileno(), 0o640)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise RecoveryRefused("PrivateRuntimeInputWriteFailed") from None


def _create_owned_directory(path, *, group, mode):
    """Exclusive root-owned inode; exact access is independent of umask077.

    Never chmod/chown an existing path. Parent/child descriptors do not follow
    links and the new child inode is checked before and after permission writes.
    """
    require(type(group) is int and group >= 0 and type(mode) is int and mode in {0o700, 0o750},
            'OwnedDirectoryParametersInvalid')
    _physical_root_path(path.parent)
    parent_fd, child_fd = None, None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent_fd = os.open(path.parent, flags)
        parent = os.fstat(parent_fd)
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022,
                'OwnedDirectoryParentInvalid')
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        child_fd = os.open(path.name, flags, dir_fd=parent_fd)
        before = os.fstat(child_fd)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and
                stat.S_IMODE(before.st_mode) == 0o700 and
                (before.st_dev, before.st_ino) == (named.st_dev, named.st_ino), 'OwnedDirectoryInodeInvalid')
        os.fchown(child_fd, 0, group)
        os.fchmod(child_fd, mode)
        after = os.fstat(child_fd)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISDIR(after.st_mode) and after.st_uid == 0 and after.st_gid == group and
                stat.S_IMODE(after.st_mode) == mode and
                (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino),
                'OwnedDirectoryMetadataInvalid')
        return path
    except OSError:
        raise RecoveryRefused('OwnedDirectoryCreationRefused') from None
    finally:
        if child_fd is not None:
            os.close(child_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _create_qualification_journal(evidence_root, candidate):
    _names(candidate)
    require(evidence_root == Path('/var/backups/keycloak-recovery') / candidate, 'OriginalEvidenceRootRequired')
    _physical_root_path(evidence_root, mode=0o700)
    nonce = secrets.token_hex(8)
    require(re.fullmatch(r'[0-9a-f]{16}', nonce), 'AttemptNonceInvalid')
    return _create_owned_directory(evidence_root.parent / (candidate + '-qualification-' + nonce), group=0, mode=0o700)


def _private_candidate_processes(candidate):
    _names(candidate)
    prefixes = [('/var/lib/' + name + '/' + candidate).encode()
                for name in ('keycloak-recovery', 'keycloak-recovery-v4', 'keycloak-recovery-v5', 'keycloak-recovery-v6', 'keycloak-recovery-v7', 'keycloak-recovery-v8')]
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            if any(prefix in (entry / 'cmdline').read_bytes() for prefix in prefixes):
                found.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return found


class PrivateCandidateRuntime:
    """Concrete private JVM lifecycle; never manages canonical service/DB names.

    All mutable paths/cache/ports are separate. The private qualification command
    uses this lifecycle only after independent review; no live tree is copied,
    no data link is followed and no database can be promoted by this class.
    """
    def __init__(self, candidate, *, runner=_run_private):
        import pwd
        self.runner = runner
        self.runner(['true'], maximum_output=0)
        _names(candidate)
        self.candidate = candidate
        self.evidence_root = Path('/var/backups/keycloak-recovery') / candidate
        self.receipts = None  # Assigned only to an exclusive qualification attempt.
        context = json.loads(_private_bytes(self.evidence_root / 'context.json').decode())
        prepare = json.loads(_private_bytes(self.evidence_root / 'prepare-result.json').decode())
        self.baseline = json.loads(_private_bytes(self.evidence_root / 'candidate-restored.json').decode())
        self.identity = json.loads(_private_bytes(self.evidence_root / 'identity-before.json').decode())
        require(context.get('candidate_database') == candidate and context.get('backup_dump_sha256') == DUMP_SHA256 and
                context.get('candidate_oid') == self.baseline.get('database_oid') == self.identity.get('candidate_oid'),
                'CandidateContextMismatch')
        self.candidate_oid = context['candidate_oid']
        fresh = collect_inventory(candidate, runner=runner)
        require(fresh['database_oid'] == self.candidate_oid, 'CandidateOidChanged')
        validate_reviewed_drift(self.baseline, fresh, [])
        validate_identity(self.identity, collect_identity(candidate, runner=runner))
        self.outbound = collect_outbound_safety(candidate, runner=runner)
        self.keycloak = pwd.getpwnam('keycloak')
        self.canonical_service_metadata = dict(prepare['services']['keycloak'])
        self.canonical_pid, self.canonical_main_start_ticks, reference = _capture_canonical_reference(
            self.canonical_service_metadata, self.keycloak.pw_uid, runner=runner)
        self.canonical_java_pid, self.canonical_exe = reference['pid'], reference['exe']
        self.canonical_java_start_ticks = reference['start_ticks']
        self.forbidden_group_ids = {os.getpgid(self.canonical_pid), os.getpgid(self.canonical_java_pid)}
        self.recipe = runtime_recipe(candidate, browser_tls=True)
        self.private = Path(self.recipe['directory'])
        self.previous_private = Path('/var/lib/keycloak-recovery') / candidate
        self.distribution = Path(self.recipe['distribution'])
        self.process = None
        self.output = None
        self.process_start = None
        self.expected_tree = None
        self.config_sha256 = None
        self.live_config_sha256 = context['current_config_sha256']
        self.java_pid = None
        self.java_start_ticks = None
        self.tls_verified = False

    def verify_pristine_attempt(self):
        require(not self.private.exists() and not self.private.is_symlink() and
                not self.private.parent.exists() and not self.private.parent.is_symlink() and
                not self.previous_private.exists() and not self.previous_private.is_symlink(),
                'NewPrivateWorkRootRequired')
        require(not _private_candidate_processes(self.candidate), 'ExistingPrivateCandidateProcessHold')
        fresh = collect_inventory(self.candidate, runner=self.runner)
        require(fresh['database_oid'] == self.candidate_oid, 'CandidateOidChanged')
        validate_reviewed_drift(self.baseline, fresh, [])
        validate_identity(self.identity, collect_identity(self.candidate, runner=self.runner))
        self.verify_canonical_reference()

    def verify_canonical_reference(self):
        pid, start, java = _capture_canonical_reference(
            self.canonical_service_metadata, self.keycloak.pw_uid, runner=self.runner)
        require(pid == self.canonical_pid and start == self.canonical_main_start_ticks and
                java['pid'] == self.canonical_java_pid and java['start_ticks'] == self.canonical_java_start_ticks and
                java['exe'] == self.canonical_exe and
                {os.getpgid(pid), os.getpgid(java['pid'])} == self.forbidden_group_ids,
                'CanonicalProcessIdentityChanged')

    def copy_and_configure(self):
        # Independent public release anchor, never trust arbitrary live-tree
        # hashes as provenance. No download or live /opt reads/builds.
        archive_mode = stat.S_IMODE(DISTRIBUTION_ARCHIVE.lstat().st_mode)
        require(archive_mode in {0o600, 0o644}, 'DistributionArchiveModeInvalid')
        archive_bytes = _private_bytes(DISTRIBUTION_ARCHIVE, mode=archive_mode,
                                       expected_sha256=DISTRIBUTION_ARCHIVE_SHA256, maximum=512 * 1024**2)
        common = self.private.parent
        _create_owned_directory(common, group=self.keycloak.pw_gid, mode=0o750)
        _create_owned_directory(self.private, group=self.keycloak.pw_gid, mode=0o750)
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as archive:
            members = archive.getmembers()
            archive_members = validate_archive_members(members)
            archive.extractall(self.private, members=members, filter='data')
        del archive_bytes
        # Same reviewed a+rX permission intent as initial stopped-distribution
        # repair. Never follow links; archive validator rejects all link types.
        for path in [self.distribution, *self.distribution.rglob('*')]:
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode), 'ExtractedDistributionSpecialFile')
            os.chown(path, 0, 0)
            original = stat.S_IMODE(metadata.st_mode) & 0o777 & ~0o022
            os.chmod(path, original | 0o444 | (0o111 if path.is_dir() or original & 0o111 else 0))
        self.data = self.distribution / 'data'
        self.work = self.private / 'work'
        self.tmp = self.private / 'tmp'
        for path in (self.data, self.work, self.tmp):
            if not path.exists():
                path.mkdir(mode=0o700)
            require(path.is_dir() and not path.is_symlink(), 'PrivateMutableDirectoryMismatch')
            os.chown(path, self.keycloak.pw_uid, self.keycloak.pw_gid)
            os.chmod(path, 0o700)
        for name in ('build-home', 'build-tmp'):
            (self.private / name).mkdir(mode=0o700)
        require(str(Path('/usr/bin/java').resolve()) == self.canonical_exe, 'PinnedJavaExecutableChanged')
        self.build_recipe = private_build_recipe(self.candidate)
        self.build_recipe_sha256 = hashlib.sha256(json.dumps(self.build_recipe, sort_keys=True,
                                                           separators=(',', ':')).encode()).hexdigest()
        self.runner(self.build_recipe['argv'], cwd=self.build_recipe['cwd'], maximum_output=1024 * 1024, timeout=180,
                    owned_group_prefix=str(self.private), forbidden_group_ids=self.forbidden_group_ids,
                    process_receipt=self.receipts / 'private-build-process.json')
        # Root's private umask may be077: generated optimized JARs still need
        # service-user read access, confined by the private parent750 boundary.
        for directory, dirs, files in os.walk(self.distribution, followlinks=False):
            if Path(directory) == self.distribution:
                dirs[:] = [name for name in dirs if name != 'data']
            for name in dirs + files:
                path = Path(directory) / name
                metadata = path.lstat()
                require(metadata.st_uid == 0 and (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)),
                        'PrivateBuiltDistributionOwnershipInvalid')
                original = stat.S_IMODE(metadata.st_mode) & 0o777 & ~0o022
                os.chmod(path, original | 0o444 | (0o111 if path.is_dir() or original & 0o111 else 0))
        for path in [self.data, *self.data.rglob('*')]:
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode), 'PrivateDataSpecialFile')
            os.chown(path, self.keycloak.pw_uid, self.keycloak.pw_gid)
            os.chmod(path, 0o700 if stat.S_ISDIR(metadata.st_mode) else 0o600)
        self.expected_tree = distribution_inventory(self.distribution, live_source=False)
        validate_outbound_safety(dict(self.outbound,
                                     custom_provider_artifact_count=self.expected_tree['custom_provider_artifact_count']))
        source_conf = _private_bytes(Path('/etc/keycloak/keycloak.conf'), mode=0o640, maximum=65536)
        require(hashlib.sha256(source_conf).hexdigest() == self.live_config_sha256, 'LiveConfigChangedSincePrepare')
        derived = candidate_configuration(source_conf.decode(), self.candidate, browser_tls=True).encode()
        self.config_sha256 = hashlib.sha256(derived).hexdigest()
        _write_group_binary(self.private / 'candidate.conf', derived, self.keycloak.pw_gid)
        tls = self.private / 'tls'
        _create_owned_directory(tls, group=self.keycloak.pw_gid, mode=0o750)
        certificate = Path('/etc/keycloak/tls/fullchain.pem')
        key = Path('/etc/keycloak/tls/key.pem')
        cert_data = _private_bytes(certificate, mode=0o644, maximum=1024 * 1024)
        key_data = _private_bytes(key, mode=0o600, maximum=65536)
        self.runner(['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', 'sso.sosnadmin.local',
                     '-CAfile', '/etc/keycloak/trust/ad-ca.pem', str(certificate)], maximum_output=65536)
        cert_public = self.runner(['openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout'], maximum_output=65536)
        key_public = self.runner(['openssl', 'pkey', '-in', str(key), '-pubout'], maximum_output=65536)
        require(cert_public == key_public, 'CandidateTlsCertificateKeyMismatch')
        _write_group_binary(tls / 'fullchain.pem', cert_data, self.keycloak.pw_gid)
        _write_group_binary(tls / 'key.pem', key_data, self.keycloak.pw_gid)
        _write_private(self.receipts / 'private-runtime-closure.json', {
            'candidate_database': self.candidate, 'candidate_oid': self.candidate_oid,
            'distribution': self.expected_tree, 'private_root': str(self.private),
            'archive_sha256': DISTRIBUTION_ARCHIVE_SHA256, 'archive_members': archive_members,
            'build_recipe_sha256': self.build_recipe_sha256, 'build_recipe': self.build_recipe,
            'all_realm_outbound_metadata': self.outbound,
            'config_sha256': self.config_sha256, 'certificate_sha256': hashlib.sha256(cert_data).hexdigest(),
            'canonical_main_pid': self.canonical_pid, 'canonical_main_start_ticks': self.canonical_main_start_ticks,
            'canonical_java_pid': self.canonical_java_pid, 'canonical_java_start_ticks': self.canonical_java_start_ticks,
            'forbidden_group_ids': sorted(self.forbidden_group_ids),
            'original_config_unchanged': True, 'shared_live_data_link_copied': False,
            'jvm_started': False, 'canonical_service_changed': False})

    def start(self):
        try:
            return self._start_owned()
        except BaseException as primary_error:
            try:
                self.stop()
            except BaseException as cleanup_error:
                raise RecoveryCleanupFailure('PrivateRuntimeCleanupHold', primary_error, cleanup_error) from None
            raise

    def _start_owned(self):
        self.verify_canonical_reference()
        require(self.process is None and self.expected_tree is not None and self.config_sha256 is not None,
                'PrivateRuntimeNotPrepared')
        for port in (8089, 9009, 8449):
            require(not self.runner(['ss', '-Hltn', 'sport', '=', ':' + str(port)], maximum_output=65536).strip(),
                    'PrivateRuntimePortOccupied')
        self.output = open(self.receipts / 'candidate-console.log', 'xb')
        os.chmod(self.receipts / 'candidate-console.log', 0o600)
        argv = list(self.recipe['argv'])
        argv[argv.index('HOME=' + str(self.private))] = 'HOME=' + str(self.work)
        self.process = subprocess.Popen(argv, cwd=self.work, stdout=self.output, stderr=self.output,
                                        start_new_session=True, env={'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'})
        self.process_start = _pid_start(self.process.pid)
        deadline = time.monotonic() + 120
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _CandidateNoRedirects())
        while time.monotonic() < deadline:
            require(self.process.poll() is None, 'PrivateRuntimeExitedBeforeReady')
            try:
                with opener.open('http://127.0.0.1:9009/health/ready', timeout=2) as response:
                    if response.status == 200 and json.loads(response.read(65536)).get('status') == 'UP':
                        break
            except (urllib.error.URLError, TimeoutError, ValueError, UnicodeError):
                pass
            time.sleep(1)
        else:
            raise RecoveryRefused('PrivateRuntimeReadinessTimeout')
        # Verify existing CA and hostname against the actual candidate endpoint,
        # without disabling chain/hostname verification or using a new CA.
        self.runner(['openssl', 's_client', '-connect', '127.0.0.1:8449', '-servername', 'sso.sosnadmin.local',
                     '-verify_hostname', 'sso.sosnadmin.local', '-verify_return_error',
                     '-CAfile', '/etc/keycloak/trust/ad-ca.pem', '-brief'], input_bytes=b'', maximum_output=65536)
        self.tls_verified = True
        return self.proof()

    def _owned_group(self):
        protected_pids = {self.canonical_pid, getattr(self, 'canonical_java_pid', None)}
        protected_groups = getattr(self, 'forbidden_group_ids', {self.canonical_pid})
        require(self.process.pid not in protected_pids | protected_groups, 'CanonicalPidSignalProhibited')
        members = []
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                if os.getpgid(pid) != self.process.pid:
                    continue
                metadata = entry.stat()
                if (entry / 'stat').read_text().rpartition(')')[2].split()[0] == 'Z':
                    continue  # A dead zombie cannot own sockets or execute code.
                command = (entry / 'cmdline').read_bytes()
                require(metadata.st_uid in {0, self.keycloak.pw_uid} and
                        str(self.private).encode() in command and pid not in protected_pids,
                        'PrivateProcessGroupUnexpectedMember')
                members.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
        return members

    def stop(self):
        if self.process is None:
            return {'owned_candidate_stopped': True, 'never_started': True}
        if self.process.poll() is None:
            require(_pid_start(self.process.pid) == self.process_start, 'PrivateProcessPidReused')
        members = self._owned_group()
        if members:
            os.killpg(self.process.pid, signal.SIGTERM)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and self._owned_group():
                time.sleep(0.2)
            if self._owned_group():
                os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=10)
            require(not self._owned_group(), 'PrivateRuntimeFailedToStop')
        if self.output is not None:
            self.output.close()
        return {'owned_candidate_stopped': True, 'canonical_pid_signaled': False}

    def proof(self):
        require(self.process is not None and self.process.poll() is None and
                _pid_start(self.process.pid) == self.process_start, 'PrivateRuntimeProcessMissing')
        lines = self.runner(['ss', '-Hltnp'], maximum_output=1024 * 1024).decode().splitlines()
        listeners, pids = {}, set()
        for port in (8089, 9009, 8449):
            matching = [line for line in lines if len(line.split()) >= 5 and line.split()[3].endswith(':' + str(port))]
            require(len(matching) == 1 and _exact_loopback_port(matching[0].split()[3], port) == port,
                    'PrivateRuntimeListenerNotLoopback')
            found = re.findall(r'pid=(\d+)', matching[0])
            require(len(set(found)) == 1, 'PrivateRuntimeSocketOwnerAmbiguous')
            pids.update(int(pid) for pid in found)
            listeners[port] = '127.0.0.1:' + str(port)
        require(len(pids) == 1, 'PrivateRuntimeSocketPidMismatch')
        java_pid = next(iter(pids))
        require(java_pid in self._owned_group() and java_pid != self.canonical_pid and
                Path('/proc/' + str(java_pid)).stat().st_uid == self.keycloak.pw_uid and
                os.readlink('/proc/' + str(java_pid) + '/exe') == self.canonical_exe,
                'PrivateRuntimeJavaIdentityMismatch')
        if self.java_pid is not None:
            require(java_pid == self.java_pid and _pid_start(java_pid) == self.java_start_ticks,
                    'PrivateRuntimeJavaPidChanged')
        java_marker = 'pid=' + str(java_pid) + ','
        tcp_lines = [line for line in lines if java_marker in line]
        udp_snapshot = self.runner(['ss', '-Hlunp'], maximum_output=1024 * 1024).decode().splitlines()
        udp_lines = [line for line in udp_snapshot if java_marker in line]
        if len(tcp_lines) != 3 or udp_lines:
            tcp, udp = _socket_summary(tcp_lines), _socket_summary(udp_lines)
            _write_private(self.receipts / 'private-runtime-network-refusal.json', {
                'schema': 'keycloak_private_socket_refusal_v1',
                'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'pid': java_pid, 'start_ticks': _pid_start(java_pid),
                'tcp_listener_count': tcp['count'], 'udp_listener_count': udp['count'],
                'tcp_ports': tcp['ports'], 'udp_ports': udp['ports'],
                'tcp_endpoint_classes': tcp['endpoint_classes'], 'udp_endpoint_classes': udp['endpoint_classes'],
                'port_lists_truncated': tcp['ports_truncated'] or udp['ports_truncated']})
        require(len(tcp_lines) == 3, 'PrivateRuntimeUnexpectedTcpListener')
        require(not udp_lines, 'PrivateRuntimeUnexpectedUdpSocket')
        connections = self.runner(['ss', '-Hntp'], maximum_output=1024 * 1024).decode().splitlines()
        java_pg_ports = set()
        for line in connections:
            fields = line.split()
            if java_marker not in line or len(fields) < 5 or _exact_loopback_port(fields[4], 5544) != 5544:
                continue
            local_port = _exact_loopback_port(fields[3])
            require(local_port is not None, 'PrivateRuntimeJdbcSourceNotLoopback')
            java_pg_ports.add(local_port)
        sql = "SELECT jsonb_build_object('oid',(SELECT oid::bigint FROM pg_database WHERE datname='" + self.candidate + "'),'owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='" + self.candidate + "'),'ports',(SELECT COALESCE(jsonb_agg(client_port),'[]'::jsonb) FROM pg_stat_activity WHERE datname='" + self.candidate + "' AND usename='keycloak' AND client_addr='127.0.0.1'));"
        database = json.loads(self.runner(_psql_argv('postgres'), input_bytes=sql.encode(), maximum_output=65536))
        database_ports = database.get('ports') if isinstance(database, dict) else None
        require(database_ports and set(database_ports) == java_pg_ports and database.get('oid') == self.candidate_oid and
                database.get('owner') == 'keycloak', 'PrivateRuntimeJdbcDatabaseMismatch')
        for path in (self.data, self.work, self.tmp):
            metadata = path.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == self.keycloak.pw_uid and
                    stat.S_IMODE(metadata.st_mode) == 0o700, 'PrivateMutableDirectoryMismatch')
        _physical_root_path(self.private / 'candidate.conf', mode=0o640)
        _physical_root_path(self.receipts / 'candidate-console.log', mode=0o600)
        require(hashlib.sha256((self.private / 'candidate.conf').read_bytes()).hexdigest() == self.config_sha256,
                'PrivateRuntimeConfigurationChanged')
        require(distribution_inventory(self.distribution, live_source=False) == self.expected_tree,
                'PrivateRuntimeDistributionChanged')
        require(collect_outbound_safety(self.candidate, runner=self.runner) == self.outbound,
                'PrivateRuntimeOutboundMetadataChanged')
        nginx = self.runner(['nginx', '-T'], maximum_output=4 * 1024 * 1024)
        require(not re.search(rb'[:\s](8089|9009|8449)\b|proxy_pass\s+[^;]*\$', nginx),
                'PrivateRuntimeProxyExposurePossible')
        require(self.tls_verified is True, 'PrivateRuntimeTlsProofMissing')
        self.java_pid, self.java_start_ticks = java_pid, _pid_start(java_pid)
        proof = {'schema': 'keycloak_private_runtime_proof_v1',
                 'candidate_database': self.candidate, 'candidate_oid': self.candidate_oid,
                 'pid': java_pid, 'canonical_pid': self.canonical_pid, 'uid_matches_keycloak': True,
                 'pgid': os.getpgid(java_pid), 'start_ticks': self.java_start_ticks, 'uid': self.keycloak.pw_uid,
                 'http_listener': listeners[8089], 'management_listener': listeners[9009],
                 'https_listener': listeners[8449], 'socket_pids': [java_pid],
                 'jdbc_database': self.candidate, 'jdbc_database_oid': database['oid'],
                 'jdbc_database_owner': database['owner'], 'jdbc_port': 5544, 'jdbc_client_ports': sorted(java_pg_ports),
                 'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 'config_sha256': self.config_sha256, 'archive_sha256': DISTRIBUTION_ARCHIVE_SHA256,
                 'build_recipe_sha256': self.build_recipe_sha256, 'distribution_sha256': self.expected_tree['sha256'],
                 'configuration_sha256_matches': True, 'private_distribution_sha256_matches': True,
                 'private_data_tmp_logs': True, 'jdbc_session_database_matches': True,
                 'no_jgroups_sockets': True, 'no_proxy_routes': True, 'browser_tls_guarded': True,
                 'tls_chain_verified': True, 'tls_hostname_verified': True, 'archive_anchor_verified': True,
                 'no_live_data_link': True, 'observed_utc_ms': int(time.time() * 1000)}
        validate_runtime_proof(proof)
        return proof


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
    before = inventory.get('realm_not_before')
    require(isinstance(before, dict) and set(before) == {'master', 'sosnadmin'} and
            all(type(value) is int and 0 <= value <= cutoff for value in before.values()),
            'ExistingRealmRevocationWouldBeLowered')
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
        client.request("PUT", prefix, payload={"notBefore": cutoff})
        current = client.request("GET", prefix)
        require(isinstance(current, dict) and current.get("notBefore") == cutoff, "RealmNotBeforeNotVerified")
        # ResourceAdminManager.logoutAll raises NB to currentTime as well. Keep
        # it last for EACH realm so this explicit cutoff can never lower that.
        client.request("POST", prefix + "/logout-all")
    return {"status": "CandidateSessionApisCompletedEvidenceRequired",
            "offline_deleted": len(sessions), "master_logout_last": True,
            "requested_not_before": cutoff, "persisted_zero_not_yet_proven": True}


def identity_sql():
    """Synthetic pilot metadata; hash OTP full row on server, never emit secrets."""
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='10s';
WITH pilot AS (
 SELECT * FROM user_entity WHERE realm_id='""" + REALM_ID + """'
 AND username='ssopilot-20261027'
)
SELECT jsonb_build_object(
 'realm_user_count',(SELECT count(*) FROM user_entity WHERE realm_id='""" + REALM_ID + """'),
 'pilot_count',(SELECT count(*) FROM pilot),
 'user_id_sha256',(SELECT encode(sha256(convert_to(id,'UTF8')),'hex') FROM pilot),
 'created_timestamp',(SELECT created_timestamp FROM pilot),
 'enabled',(SELECT enabled FROM pilot),
 'federation_link_sha256',(SELECT encode(sha256(convert_to(federation_link,'UTF8')),'hex') FROM pilot),
 'ldap_id_count',(SELECT count(*) FROM user_attribute a JOIN pilot p ON p.id=a.user_id WHERE a.name='LDAP_ID'),
 'ldap_guid',CASE WHEN (SELECT count(*) FROM user_attribute a JOIN pilot p ON p.id=a.user_id
   WHERE a.name='LDAP_ID')=1 AND (SELECT count(*) FROM user_attribute a JOIN pilot p ON p.id=a.user_id
   WHERE a.name='LDAP_ID' AND lower(a.value)='""" + PILOT_GUID + """')=1
   THEN '""" + PILOT_GUID + """' ELSE NULL END,
 'credentials',(SELECT COALESCE(jsonb_agg(jsonb_build_object('type',type,'created_date',created_date,
   'row_sha256',encode(sha256(convert_to(to_jsonb(credential_row)::text,'UTF8')),'hex')) ORDER BY id),'[]'::jsonb)
   FROM credential AS credential_row WHERE user_id=(SELECT id FROM pilot))
);
COMMIT;
"""


def collect_identity(database, *, runner=_run_private):
    _names(database)
    response = runner(_psql_argv(database), input_bytes=identity_sql().encode(), maximum_output=65536)
    try:
        result = json.loads(response)
    except (ValueError, TypeError, UnicodeError):
        raise RecoveryRefused("IdentityResponseMalformed") from None
    require(isinstance(result, dict) and result.get("pilot_count") == 1, "OriginalPilotCountMismatch")
    validate_identity(result, result)
    return result


def outbound_safety_sql():
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='10s';
SELECT jsonb_build_object(
 'realms',(SELECT jsonb_agg(name ORDER BY name) FROM realm),
 'admin_url_count',(SELECT count(*) FROM client WHERE nullif(trim(management_url),'') IS NOT NULL),
 'backchannel_url_count',(SELECT count(*) FROM client_attributes WHERE lower(name) LIKE '%backchannel%'
   AND lower(name) LIKE '%url%' AND nullif(trim(value),'') IS NOT NULL),
 'event_listeners',(SELECT jsonb_agg(DISTINCT value ORDER BY value) FROM realm_events_listeners),
 'identity_provider_count',(SELECT count(*) FROM identity_provider),
 'smtp_entry_count',(SELECT count(*) FROM realm_smtp_config),
 'storage_provider_count',(SELECT count(*) FROM component WHERE provider_type='org.keycloak.storage.UserStorageProvider'),
 'ldap_configuration_safe',EXISTS(SELECT 1 FROM component WHERE id='HqtFYF0QRMy-SARJtaSFzw'
   AND parent_id='b3e36dfe-afda-48ea-a83a-bd2b28d924e5' AND provider_id='ldap'
   AND provider_type='org.keycloak.storage.UserStorageProvider') AND NOT EXISTS(
   SELECT 1 FROM (VALUES ('connectionUrl','ldaps://AD-MAIN.sosnadmin.local:636'),
     ('usersDn','CN=ssopilot-20261027,OU=TEST,DC=sosnadmin,DC=local'),('searchScope','0'),
     ('editMode','READ_ONLY'),('cachePolicy','NO_CACHE'),('syncRegistrations','false'),
     ('fullSyncPeriod','-1'),('changedSyncPeriod','-1'),('useTruststoreSpi','always'),('connectionPooling','false'))
   AS expected(name,value) WHERE (SELECT count(*) FROM component_config c
     WHERE c.component_id='HqtFYF0QRMy-SARJtaSFzw' AND c.name=expected.name)<>1
   OR NOT EXISTS(SELECT 1 FROM component_config c WHERE c.component_id='HqtFYF0QRMy-SARJtaSFzw'
     AND c.name=expected.name AND c.value=expected.value))
);
COMMIT;
"""


def collect_outbound_safety(database, *, runner=_run_private):
    _names(database)
    response = runner(_psql_argv(database), input_bytes=outbound_safety_sql().encode(), maximum_output=65536)
    try:
        result = json.loads(response)
    except (ValueError, TypeError, UnicodeError):
        raise RecoveryRefused('OutboundResponseMalformed') from None
    require(isinstance(result, dict) and result.get('realms') == ['master', 'sosnadmin'], 'UnexpectedRestoredRealms')
    # This proves SQL metadata only. Binary provider absence remains a separate
    # required check from distribution_inventory, never manufactured here.
    validate_outbound_metadata(result)
    return result


def session_inventory_sql(fresh_sid):
    try:
        require(isinstance(fresh_sid, str) and str(uuid.UUID(fresh_sid)) == fresh_sid, 'FreshMasterSidInvalid')
    except (ValueError, AttributeError):
        raise RecoveryRefused('FreshMasterSidInvalid') from None
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='10s';
SELECT jsonb_build_object(
 'realms',(SELECT jsonb_agg(name ORDER BY name) FROM realm),
 'fresh_master_session_count',(SELECT count(*) FROM offline_user_session s JOIN realm r ON r.id=s.realm_id
   JOIN user_entity u ON u.id=s.user_id WHERE s.user_session_id='""" + fresh_sid + """'
   AND s.offline_flag='0' AND r.name='master' AND u.username='sso-bootstrap'),
 'unexpected_offline_flags',(SELECT count(*) FROM offline_user_session WHERE offline_flag NOT IN ('0','1')),
 'maximum_restored_token_iat',(SELECT COALESCE(max(GREATEST(created_on,last_session_refresh)),0)
   FROM offline_user_session WHERE user_session_id<>'""" + fresh_sid + """'),
 'offline_sessions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('realm',r.name,'id',s.user_session_id)
   ORDER BY r.name,s.user_session_id),'[]'::jsonb) FROM offline_user_session s JOIN realm r ON r.id=s.realm_id WHERE s.offline_flag='1'),
 'realm_not_before',(SELECT jsonb_object_agg(name,not_before) FROM realm)
);
COMMIT;
"""


def collect_session_inventory(database, fresh_sid, *, runner=_run_private):
    _names(database)
    response = runner(_psql_argv(database), input_bytes=session_inventory_sql(fresh_sid).encode(), maximum_output=65536)
    try:
        result = json.loads(response)
    except (ValueError, TypeError, UnicodeError):
        raise RecoveryRefused('SessionInventoryMalformed') from None
    require(isinstance(result, dict) and result.get('fresh_master_session_count') == 1 and
            result.get('unexpected_offline_flags') == 0, 'FreshMasterSessionOrFlagNotVerified')
    return result


def poststop_sessions_sql():
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT jsonb_build_object('offline_user_session',(SELECT count(*) FROM offline_user_session),
 'offline_client_session',(SELECT count(*) FROM offline_client_session),
 'auth_session',(SELECT count(*) FROM auth_session),'root_auth_session',(SELECT count(*) FROM root_auth_session),
 'realm_not_before',(SELECT jsonb_object_agg(name,not_before) FROM realm));
COMMIT;
"""


def validate_poststop_sessions(result, cutoff):
    require(isinstance(result, dict) and type(cutoff) is int and cutoff > 0, 'PoststopSessionProofInvalid')
    for name in ('offline_user_session', 'offline_client_session', 'auth_session', 'root_auth_session'):
        require(type(result.get(name)) is int and result[name] == 0, 'PersistentSessionsRemainHold')
    realms = result.get('realm_not_before')
    require(isinstance(realms, dict) and set(realms) == {'master', 'sosnadmin'} and
            all(type(value) is int and value >= cutoff for value in realms.values()), 'RealmRevocationCutoffNotPreserved')


def _exact_keys(value, names):
    require(type(value) is dict and set(value) == set(names), 'PrivateRpcShapeInvalid')


def _read_rpc_json(deadline):
    """One bounded line; partial input cannot escape the monotonic deadline."""
    data = bytearray()
    descriptor = sys.stdin.fileno()
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0 and select.select([descriptor], [], [], remaining)[0], 'PrivateRpcReplyTimeout')
        chunk = os.read(descriptor, min(4096, 65537 - len(data)))
        require(chunk, 'PrivateRpcReplyMissing')
        data.extend(chunk)
        require(len(data) <= 65536, 'PrivateRpcReplyBoundExceeded')
        require(time.monotonic() <= deadline, 'PrivateRpcReplyTimeout')
        if b'\n' in data:
            require(data.endswith(b'\n') and data.count(b'\n') == 1, 'PrivateRpcDuplicateLine')
            break
    def unique_keys(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs), 'PrivateRpcDuplicateKey')
        return value
    try:
        result = json.loads(data, object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError):
        raise RecoveryRefused('PrivateRpcReplyMalformed') from None
    require(type(result) is dict, 'PrivateRpcShapeInvalid')
    return result


class ServerBrowserProofGate:
    def __init__(self, binding):
        self.binding_sha256 = hashlib.sha256(json.dumps(binding, separators=(',', ':')).encode('ascii')).hexdigest()
        self.context_id, self.cookie_sha256, self.phase = None, None, 'new'

    def started(self, proof):
        _exact_keys(proof, ('stage', 'context_id', 'binding_sha256', 'all_callbacks_intercepted',
                            'strict_tls', 'http_default_deny', 'websocket_default_deny'))
        require(self.phase == 'new' and proof['stage'] == 'browser_ready' and
                proof['binding_sha256'] == self.binding_sha256, 'BrowserReadyBindingMismatch')
        try:
            require(str(uuid.UUID(proof['context_id'])) == proof['context_id'], 'BrowserContextInvalid')
        except (ValueError, TypeError, AttributeError):
            raise RecoveryRefused('BrowserContextInvalid') from None
        require(all(proof[key] is True for key in ('all_callbacks_intercepted', 'strict_tls',
                                                  'http_default_deny', 'websocket_default_deny')), 'BrowserPolicyNotProven')
        self.context_id, self.phase = proof['context_id'], 'started'

    def _callback(self, proof, first):
        _exact_keys(proof, ('stage', 'context_id', 'code_present', 'state_matches', 'callback_matches', 'error_present',
                            'password_prompts', 'otp_prompts', 'cookie_fingerprint_sha256', 'identity_cookie_present',
                            'cookies_secure', 'cookie_count', 'cookie_before_sha256', 'blocked_egress'))
        require(proof['stage'] == 'callback' and proof['context_id'] == self.context_id and
                all(proof[key] is True for key in ('code_present', 'state_matches', 'callback_matches',
                                                  'identity_cookie_present', 'cookies_secure')) and
                proof['error_present'] is False, 'BrowserCallbackNotProven')
        require(type(proof['password_prompts']) is int and proof['password_prompts'] == int(first) and
                type(proof['otp_prompts']) is int and proof['otp_prompts'] == 0 and
                type(proof['blocked_egress']) is int and proof['blocked_egress'] == 0 and
                type(proof['cookie_count']) is int and 1 <= proof['cookie_count'] <= 64 and
                is_hash(proof['cookie_fingerprint_sha256']) and is_hash(proof['cookie_before_sha256']),
                'BrowserCredentialOrCookieProvenanceInvalid')

    def positive(self, initial, sso):
        require(self.phase == 'started', 'BrowserPositiveOutOfOrder')
        self._callback(initial, True)
        self._callback(sso, False)
        require(sso['cookie_before_sha256'] == initial['cookie_fingerprint_sha256'], 'BrowserPositiveCookieChanged')
        self.cookie_sha256, self.phase = sso['cookie_fingerprint_sha256'], 'positive'

    def negative(self, proof):
        require(self.phase == 'positive', 'BrowserNegativeOutOfOrder')
        _exact_keys(proof, ('stage', 'context_id', 'cookie_before_sha256', 'password_prompts',
                            'otp_prompts', 'callback_absent', 'blocked_egress'))
        require(proof['stage'] == 'password_required' and proof['context_id'] == self.context_id and
                proof['cookie_before_sha256'] == self.cookie_sha256 and proof['callback_absent'] is True and
                all(type(proof[key]) is int and proof[key] == 0 for key in ('password_prompts', 'otp_prompts', 'blocked_egress')),
                'StaleBrowserCookieNotRejected')
        self.phase = 'negative'

    def closed(self, proof):
        require(self.phase == 'negative' and type(proof) is dict and proof == {'stage': 'closed'}, 'BrowserCloseNotProven')
        self.phase = 'closed'


SAFE_REFUSAL_CODES = frozenset({
    'OwnedDirectoryParametersInvalid', 'OwnedDirectoryParentInvalid', 'OwnedDirectoryInodeInvalid',
    'OwnedDirectoryMetadataInvalid', 'OwnedDirectoryCreationRefused', 'PrivatePathModeMismatch',
    'PhysicalRootPathRequired', 'PrivatePathUnavailable', 'PrivateCommandFailed', 'PrivateBuildCleanupHold',
    'PrivateRuntimeCleanupHold',
    'NewPrivateWorkRootRequired', 'ExistingPrivateCandidateProcessHold', 'UnreviewedDatabaseDrift', 'CandidateOidChanged',
    'OriginalPilotIdentityMismatch', 'OriginalOtpBytesOrMetadataChanged', 'PrivateRuntimePortOccupied',
    'PrivateRuntimeExitedBeforeReady', 'PrivateRuntimeReadinessTimeout', 'PrivateRuntimeFailedToStop',
    'CandidateTlsCertificateKeyMismatch', 'PrivateRuntimeJdbcDatabaseMismatch', 'PrivateRuntimeConfigurationChanged',
    'QualificationInterrupted', 'PrivateRpcReplyMissing', 'PrivateRpcReplyTimeout', 'PrivateRpcReplyBoundExceeded',
    'PrivateRpcReplyMalformed', 'PrivateRpcReplyOutOfOrder', 'PrivateRpcShapeInvalid', 'PrivateRpcDuplicateLine',
    'PrivateRpcDuplicateKey', 'PrivateRpcChallengeInvalidOrReplayed', 'PrivateRpcEventAlreadyConsumed',
    'PrivateRpcOperationInvalid', 'FreshMasterTokenLifetimeTooShort', 'MasterTokenRevocationOrLifetimeNotProven',
    'PersistentSessionsRemainHold', 'CanonicalProcessIdentityChanged', 'CanonicalProcessChangedSincePrepare',
    # Fixed literal diagnostics reachable across startup/proof and its trusted runner.
    'AbsolutePhysicalPathRequired', 'ActualTableManifestMismatch', 'ApprovedHostRequired',
    'ApprovedJava21Required', 'ApprovedLinuxRootRequired', 'CandidateCustomListenerPossible',
    'CandidateLdapScopeOrScheduledSyncUnsafe', 'CandidateOutboundEffectPossible', 'CanonicalJavaDescendantNotUnique',
    'CanonicalMainProcessMismatch', 'CanonicalPidSignalProhibited', 'CanonicalProcessChangedDuringProbe',
    'CanonicalProcessMetadataInvalid', 'CanonicalServiceMetadataInvalid', 'CleanupFailureCodeInvalid',
    'Complete101TableInventoryRequired', 'CustomOutboundProviderProhibited', 'DatabaseOidMissing',
    'DatabaseOwnerMismatch', 'DedicatedClusterRequired', 'DistributionFileBoundExceeded',
    'DistributionFileDigestInvalid', 'DistributionForeignOwner', 'DistributionInventoryBoundExceeded',
    'DistributionLauncherMissing', 'DistributionLinkEscape', 'DistributionManifestInvalid',
    'DistributionPathInvalid', 'DistributionSpecialFile', 'DistributionWritableOrSpecial',
    'ExactReviewedDriftRequired', 'ExclusiveCandidateNameRequired', 'IdentityEvidenceMalformed',
    'IdentityResponseMalformed', 'InventoryBoundExceeded', 'InventoryDatabaseMismatch',
    'InventoryResponseMalformed', 'LiveDataLinkContractMismatch', 'OriginalOtpEvidenceMissing',
    'OriginalPilotCountMismatch', 'OutboundEvidenceMissing', 'OutboundResponseMalformed',
    'PinnedTableManifestMismatch', 'Postgres16Required', 'PreparedCanonicalServiceInvalid',
    'PrivateBuildPrefixInvalid', 'PrivateCommandOutputBoundExceeded', 'PrivateDataMustBePhysical',
    'PrivateMutableDirectoryMismatch', 'PrivateProcessGroupUnexpectedMember', 'PrivateProcessPidReused',
    'PrivateReceiptWriteFailed', 'PrivateRuntimeDistributionChanged', 'PrivateRuntimeJavaIdentityMismatch',
    'PrivateRuntimeJavaPidChanged', 'PrivateRuntimeListenerNotLoopback', 'PrivateRuntimeNotPrepared',
    'PrivateRuntimeJdbcSourceNotLoopback',
    'PrivateRuntimeOutboundMetadataChanged', 'PrivateRuntimeProcessMissing', 'PrivateRuntimeProxyExposurePossible',
    'PrivateRuntimeSocketOwnerAmbiguous', 'PrivateRuntimeSocketPidMismatch', 'PrivateRuntimeTlsProofMissing',
    'PrivateRuntimeUnexpectedClusterSocket', 'ProcessIdentityUnavailable', 'RowDigestInvalid',
    'PrivateRuntimeUnexpectedTcpListener', 'PrivateRuntimeUnexpectedUdpSocket',
    'RuntimeIsolationProofIncomplete', 'RuntimePidMismatch', 'RuntimeProofMissing',
    'RuntimeSocketIsolationMismatch', 'SchemaDigestInvalid', 'SchemaOrPermissionsDrift',
    'SequenceSetDrift', 'SequenceStateInvalid', 'SnapshotMalformed',
    'SnapshotVersionMismatch', 'TableNameInvalid', 'TableSetDrift',
    'UnexpectedRestoredRealms', 'UnexpectedSchemaExecutable',
    # Closed fixed purge/token/session diagnostics; never forward raw exception data.
    'BrowserPositiveRequiredBeforePurge', 'CandidateMutationProhibited',
    'CandidateRedirectProhibited', 'CandidateRequestBudgetExceeded', 'CandidateRequestFailed',
    'CandidateResponseBoundExceeded', 'CandidateTokenIatInvalid', 'CandidateTokenMalformed',
    'CandidateTokenProvenanceInvalid', 'CandidateTokenSidInvalid', 'CandidateHTTPUnclassified',
    'ExistingRealmRevocationWouldBeLowered', 'FreshAdminMustPostdateRestoredTokens',
    'FreshMasterSessionOrFlagNotVerified', 'FreshMasterSidInvalid', 'FreshMasterTokenNotVerified',
    'MasterTokenRejectionUnclassified', 'OfflineSessionBoundExceeded', 'OfflineSessionIdentityInvalid',
    'PoststopSessionProofInvalid', 'PurgeBindingMismatch', 'RealmNotBeforeNotVerified',
    'RealmRevocationCutoffNotPreserved', 'RuntimeVerifierRequired', 'SessionInventoryMalformed',
}) | frozenset('CandidateHTTP' + str(status) for status in range(100, 600))

SAFE_PURGE_SUBPHASES = frozenset({'PermitPurge', 'FreshMasterLogin', 'TokenShapeReceipt',
    'SessionClientConstruction', 'TokenLifetime', 'RealmApi', 'SessionInventory',
    'SessionProvenanceReceipt', 'SessionApis', 'TokenRevocation', 'TokenRevocationReceipt'})


def _safe_error_metadata(error):
    safe_classes = {RecoveryRefused, KeyboardInterrupt, OSError, FileNotFoundError, FileExistsError,
                    PermissionError, TimeoutError, ValueError, TypeError, AttributeError, BrokenPipeError,
                    subprocess.TimeoutExpired}
    refusal = None
    if type(error) in {RecoveryRefused, RecoveryCleanupFailure}:
        refusal = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str and \
                  error.args[0] in SAFE_REFUSAL_CODES else 'UnclassifiedRefusal'
    return {'exception_class': 'RecoveryRefused' if type(error) is RecoveryCleanupFailure else
            type(error).__name__ if type(error) in safe_classes else 'UnexpectedError',
            'refusal_code': refusal}


EXECUTOR_ROOT = Path('/root/keycloak-identity-recovery-20261027-executor-v8')
PILOT_HELPER_SHA256 = '7df5688f2c4de83cec4047c1788e56a8ccf1b84bd7297102545bea7bfa0a1cd8'


class QualificationOperations:
    """One private qualification; zero promotion capability, exact memory RPC."""
    def __init__(self, candidate, helper, helper_sha256):
        require(Path(__file__) == EXECUTOR_ROOT / 'recover_pilot_identity.py' and
                helper == EXECUTOR_ROOT / 'pilot_acceptance.py' and helper_sha256 == PILOT_HELPER_SHA256,
                'ReviewedExecutorPathRequired')
        _physical_root_path(EXECUTOR_ROOT, mode=0o700)
        _private_bytes(Path(__file__), mode=0o600, maximum=1024 * 1024)
        helper_source = _private_bytes(helper, expected_sha256=PILOT_HELPER_SHA256, maximum=1024 * 1024)
        self.runtime = PrivateCandidateRuntime(candidate)
        self.canonical_start = _pid_start(self.runtime.canonical_pid)
        self.phase, self.failure_context = 'constructed', None
        self.cleanup_phase, self.cleanup_failure = 'NotAttempted', None
        self.source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        spec = importlib.util.spec_from_file_location('reviewed_private_keycloak_pilot', helper)
        self.pilot = importlib.util.module_from_spec(spec)
        # Compile exact verified bytes, avoiding any path reread/import race.
        exec(compile(helper_source, str(helper), 'exec'), self.pilot.__dict__)
        self.pilot.BASE = 'http://127.0.0.1:8089'
        environment = self.pilot.read_private_environment()
        self.environment = {name: environment[name] for name in
                            ('SSO_BOOTSTRAP_PASSWORD', 'SSO_LDAP_BIND_DN', 'SSO_LDAP_BIND_PASSWORD')}
        environment.clear()
        self.browser, self.master, self.token_proof, self.purge_result = None, None, None, None
        self.rpc_challenge_nonces, self.rpc_challenged_events = set(), set()
        self.runtime.verify_pristine_attempt()
        self.receipts = _create_qualification_journal(self.runtime.evidence_root, candidate)
        self.runtime.receipts = self.receipts
        _write_private(self.receipts / 'qualification-begin.json', {
            'source_sha256': self.source_sha256, 'candidate_database': candidate,
            'candidate_oid': self.runtime.candidate_oid, 'original_current_drift_reviewed': False,
            'original_evidence_root': str(self.runtime.evidence_root),
            'canonical_writes_performed': False, 'switch_ready': False})

    def perform(self, operation):
        methods = {'verify_reviewed_restored_candidate_and_capacity': self.verify,
                   'start_private_candidate_runtime': self.start,
                   'verify_pid_sockets_database_and_config': self.runtime.proof,
                   'apply_reviewed_retention_without_user_lookup': self.retention,
                   'verify_original_pilot_and_otp': self.identity,
                   'apply_reviewed_audience_and_basic_scope_repairs': self.scopes,
                   'verify_all_realm_no_outbound_effects': self.outbound,
                   'prove_browser_cookie_before_purge': self.positive,
                   'purge_restored_sessions_master_last': self.purge,
                   'verify_stale_cookie_and_token_rejected': self.negative,
                   'stop_owned_candidate_pid': self.runtime.stop,
                   'verify_persisted_sessions_zero': self.poststop,
                   'collect_final_candidate_inventory': self.final_inventory}
        require(operation in methods, 'PrivateQualificationOperationProhibited')
        if operation == 'stop_owned_candidate_pid':
            self.cleanup_phase = 'StoppingOwnedCandidate'
            try:
                result = methods[operation]()
            except BaseException as error:
                self.cleanup_phase, self.cleanup_failure = 'CleanupUnconfirmed', _safe_error_metadata(error)
                raise
            self.cleanup_phase = 'OwnedCandidateStopConfirmed'
            return result
        self.phase = operation
        try:
            return methods[operation]()
        except BaseException as error:
            if self.failure_context is None:
                self.failure_context = dict(phase=operation, **(error.primary_metadata
                    if type(error) is RecoveryCleanupFailure else _safe_error_metadata(error)))
                if operation == 'purge_restored_sessions_master_last':
                    subphase = getattr(self, 'purge_subphase', None)
                    self.failure_context['purge_subphase'] = (subphase if type(subphase) is str and
                        subphase in SAFE_PURGE_SUBPHASES else 'UnclassifiedPurgeSubphase')
            if type(error) is RecoveryCleanupFailure:
                self.cleanup_phase, self.cleanup_failure = 'CleanupUnconfirmed', dict(error.cleanup_metadata)
            raise

    def _client(self):
        runtime, pilot = self.runtime, self.pilot
        class ProofBoundClient(pilot.LocalAdminClient):
            def request(self, *args, **kwargs):
                runtime.proof()
                return super().request(*args, **kwargs)
        client = ProofBoundClient(request_budget=48)
        client.login(self.environment['SSO_BOOTSTRAP_PASSWORD'])
        return client

    def _rpc(self, operation, expected_reply, **fields):
        sensitive = {'browser_start': 'browser_start_result', 'browser_positive': 'browser_positive_result',
                     'purge_held': 'permit_purge', 'browser_negative': 'browser_negative_result'}
        require((operation in sensitive and sensitive[operation] == expected_reply) or
                (operation, expected_reply) == ('browser_close', 'browser_close_result'), 'PrivateRpcOperationInvalid')
        deadline = time.monotonic() + 180
        request = dict(op=operation, **fields)
        if operation in sensitive:
            require(operation not in self.rpc_challenged_events, 'PrivateRpcEventAlreadyConsumed')
            self.rpc_challenged_events.add(operation)
            request['runtime_proof'] = self.runtime.proof()
        print(json.dumps(request, separators=(',', ':')), flush=True)
        if operation in sensitive:
            challenge = _read_rpc_json(deadline)
            _exact_keys(challenge, ('op', 'event_op', 'nonce'))
            nonce = challenge['nonce']
            require(challenge['op'] == 'runtime_proof_challenge' and challenge['event_op'] == operation and
                    type(nonce) is str and re.fullmatch(r'[0-9a-f]{64}', nonce) and
                    nonce not in self.rpc_challenge_nonces, 'PrivateRpcChallengeInvalidOrReplayed')
            # Consume before collection/output: uncertain outcomes cannot retry.
            self.rpc_challenge_nonces.add(nonce)
            fresh = self.runtime.proof()  # Causally AFTER the parent's nonce.
            require(time.monotonic() <= deadline, 'PrivateRpcReplyTimeout')
            print(json.dumps({'op': 'runtime_proof_response', 'event_op': operation,
                              'nonce': nonce, 'runtime_proof': fresh}, separators=(',', ':')), flush=True)
        result = _read_rpc_json(deadline)
        require(result.get('op') == expected_reply, 'PrivateRpcReplyOutOfOrder')
        self.runtime.proof()  # Actual OS/JDBC/TLS binding revalidated on EVERY return.
        require(time.monotonic() <= deadline, 'PrivateRpcReplyTimeout')
        return result

    def verify(self):
        # No public-vs-original data approval is fabricated here. This operation
        # stays private and ends HOLD with both original/final drifts UNREVIEWED.
        current = self.runtime.runner(_psql_argv('postgres'), input_bytes=b"SELECT oid::bigint FROM pg_database WHERE datname='keycloak';", maximum_output=1024)
        context = json.loads(_private_bytes(self.runtime.evidence_root / 'context.json').decode())
        require(int(current.strip()) == context['current_oid'], 'CanonicalDatabaseChanged')
        memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                          if line.startswith('MemAvailable:'))) * 1024
        volumes = [os.statvfs('/var/lib'), os.statvfs('/var/lib/postgresql/16/keycloak')]
        database_bytes = self.runtime.runner(_psql_argv('postgres'), input_bytes=(
            "SELECT pg_database_size('keycloak')+pg_database_size('" + self.runtime.candidate + "');").encode(), maximum_output=1024)
        validate_capacity({'free_bytes': min(v.f_bavail * v.f_frsize for v in volumes),
                           'available_memory_bytes': memory, 'current_database_bytes': int(database_bytes.strip()),
                           'distribution_bytes': 1024**3, 'dump_bytes': (Path(BACKUP) / 'keycloak.dump').stat().st_size})
        return {'private_only': True, 'original_current_drift_reviewed': False}

    def start(self):
        self.runtime.copy_and_configure()
        proof = self.runtime.start()
        _write_private(self.receipts / 'private-runtime-started.json', proof)
        return {'private_runtime_started': True}

    def retention(self):
        result = self.pilot.preserve_ldap_identities(self._client(), apply=True,
            receipt_path=self.receipts / 'candidate-retention-before.json')
        require(result.get('status') == 'LdapIdentityRetentionVerified', 'RetentionNotVerified')
        return result

    def identity(self):
        result = collect_identity(self.runtime.candidate)
        validate_identity(self.runtime.identity, result)
        _write_private(self.receipts / 'identity-after-retention.json', result)
        return {'original_identity_and_otp_unchanged': True}

    def scopes(self):
        audience = self.pilot.add_self_audiences(self._client(), self.environment, PILOT_GUID, apply=True,
            receipt_path=self.receipts / 'candidate-audience-before.json')
        basic = self.pilot.add_basic_scope(self._client(), self.environment, PILOT_GUID, apply=True,
            receipt_path=self.receipts / 'candidate-basic-before.json')
        require(audience.get('status') == 'SelfAudienceMappersVerified' and basic.get('status') == 'BasicClientScopesVerified',
                'CandidateScopeParityNotVerified')
        validate_identity(self.runtime.identity, collect_identity(self.runtime.candidate))
        return {'audience_basic_parity_verified': True}

    def outbound(self):
        metadata = collect_outbound_safety(self.runtime.candidate)
        require(metadata == self.runtime.outbound, 'CandidateOutboundMetadataChanged')
        validate_outbound_safety(dict(metadata, custom_provider_artifact_count=
                                     self.runtime.expected_tree['custom_provider_artifact_count']))
        return {'all_realm_outbound_metadata_and_binary_closure_verified': True}

    def positive(self):
        proof = self.runtime.proof()
        binding = {key: proof[key] for key in ('candidate_database', 'candidate_oid', 'pid', 'config_sha256', 'source_sha256')}
        self.browser = ServerBrowserProofGate(binding)
        reply = self._rpc('browser_start', 'browser_start_result', binding=binding)
        _exact_keys(reply, ('op', 'proof'))
        self.browser.started(reply['proof'])
        reply = self._rpc('browser_positive', 'browser_positive_result')
        _exact_keys(reply, ('op', 'initial', 'sso'))
        self.browser.positive(reply['initial'], reply['sso'])
        _write_private(self.receipts / 'browser-positive.json', {'initial': reply['initial'], 'sso': reply['sso']})
        return {'same_context_browser_cookie_valid_before': True}

    def purge(self):
        self.purge_subphase = 'PermitPurge'
        require(self.browser.phase == 'positive', 'BrowserPositiveRequiredBeforePurge')
        reply = self._rpc('purge_held', 'permit_purge', binding_sha256=self.browser.binding_sha256)
        _exact_keys(reply, ('op', 'binding_sha256'))
        require(reply['binding_sha256'] == self.browser.binding_sha256, 'PurgeBindingMismatch')
        time.sleep(1.1)  # The final admin token strictly postdates every prior test/session iat.
        self.purge_subphase = 'FreshMasterLogin'
        client = self._client()
        self.purge_subphase = 'TokenShapeReceipt'
        _write_private(self.receipts / 'purge-token-shape.json',
                       candidate_token_shape_metadata(client.token, now=int(time.time())))
        self.purge_subphase = 'SessionClientConstruction'
        self.master = CandidateSessionClient(client.token, runtime_verifier=self.runtime.proof)
        self.purge_subphase = 'TokenLifetime'
        require(self.master.expires_at - int(time.time()) >= 45, 'FreshMasterTokenLifetimeTooShort')
        self.purge_subphase = 'RealmApi'
        realms = self.master.request('GET', '/admin/realms')
        require(isinstance(realms, list) and sorted(item.get('realm') for item in realms) == ['master', 'sosnadmin'],
                'FreshMasterTokenNotVerified')
        started = time.monotonic()
        self.purge_subphase = 'SessionInventory'
        inventory = collect_session_inventory(self.runtime.candidate, self.master.session_id)
        self.purge_subphase = 'SessionProvenanceReceipt'
        _write_private(self.receipts / 'session-provenance-before.json', {
            'fresh_master_sid_sha256': hashlib.sha256(self.master.session_id.encode()).hexdigest(),
            'fresh_master_iat': self.master.admin_iat, 'fresh_master_expires_at': self.master.expires_at,
            'maximum_other_token_iat': inventory['maximum_restored_token_iat'],
            'offline_session_count': len(inventory['offline_sessions']),
            'token_valid_before_http': 200, 'realm_not_before': inventory['realm_not_before']})
        self.purge_subphase = 'SessionApis'
        self.purge_result = purge_sessions(self.master, inventory)
        self.purge_subphase = 'TokenRevocation'
        rejected = False
        try:
            self.master.request('GET', '/admin/realms')
        except RecoveryRefused as error:
            require(str(error) == 'CandidateHTTP401', 'MasterTokenRejectionUnclassified')
            rejected = True
        require(rejected and time.monotonic() - started <= 30 and int(time.time()) < self.master.expires_at - 5,
                'MasterTokenRevocationOrLifetimeNotProven')
        self.token_proof = {'valid_before_http': 200, 'revoked_after_http': 401,
                            'same_token_cryptographically_unexpired': True, 'elapsed_below_30_seconds': True}
        self.purge_subphase = 'TokenRevocationReceipt'
        _write_private(self.receipts / 'master-token-revocation.json', self.token_proof)
        self.master.token = ''
        return self.token_proof

    def negative(self):
        require(self.token_proof is not None, 'MasterTokenProofRequired')
        reply = self._rpc('browser_negative', 'browser_negative_result', context_id=self.browser.context_id,
                          expected_cookie_fingerprint_sha256=self.browser.cookie_sha256)
        _exact_keys(reply, ('op', 'proof'))
        self.browser.negative(reply['proof'])
        _write_private(self.receipts / 'browser-negative.json', reply['proof'])
        reply = self._rpc('browser_close', 'browser_close_result')
        _exact_keys(reply, ('op', 'proof'))
        self.browser.closed(reply['proof'])
        return {'same_context_stale_cookie_requires_password': True}

    def poststop(self):
        require(self.browser.phase == 'closed' and self.token_proof is not None, 'PrivateNegativeProofIncomplete')
        response = self.runtime.runner(_psql_argv(self.runtime.candidate), input_bytes=poststop_sessions_sql().encode(), maximum_output=65536)
        result = json.loads(response)
        validate_poststop_sessions(result, self.master.admin_iat)
        validate_identity(self.runtime.identity, collect_identity(self.runtime.candidate))
        _write_private(self.receipts / 'poststop-sessions.json', result)
        return {'persistent_sessions_zero': True, 'original_identity_and_otp_unchanged': True}

    def final_inventory(self):
        final = collect_inventory(self.runtime.candidate)
        drift = compare_snapshots(self.runtime.baseline, final)
        require(final['database_oid'] == self.runtime.candidate_oid, 'FinalCandidateOidChanged')
        _write_private(self.receipts / 'candidate-final.json', final)
        _write_private(self.receipts / 'unreviewed-final-drift.json', drift)
        self.verify()
        self.runtime.verify_canonical_reference()
        require(_pid_start(self.runtime.canonical_pid) == self.canonical_start, 'CanonicalServiceProcessChanged')
        self.result = {'schema': 'keycloak_private_qualification_result_v1', 'status': 'QualifiedUnreviewedDriftHold',
            'candidate_database': self.runtime.candidate, 'candidate_oid': self.runtime.candidate_oid,
            'source_sha256': self.source_sha256, 'private_receipt_directory': str(self.receipts),
            'original_identity_and_otp_unchanged': True, 'browser_cookie_valid_before_stale_after': True,
            'master_token_valid_before_revoked_unexpired': True, 'persistent_sessions_zero': True,
            'owned_candidate_stopped': True, 'canonical_oid_unchanged': True, 'canonical_service_process_unchanged': True,
            'canonical_writes_performed': False, 'original_current_drift_reviewed': False,
            'final_drift_reviewed': False, 'switch_ready': False}
        _write_private(self.receipts / 'private-qualification-result.json', self.result)
        return {'private_qualification_complete': True, 'switch_ready': False}


def run_private_qualification(candidate, helper, helper_sha256):
    """Bounded source-only CLI until review/approval; no public switch path."""
    operations, lock_fd, failure = None, None, None
    handlers = {}
    def interrupted(signum, frame):
        # Repeated cancellation must not interrupt owned-group cleanup and
        # accidentally turn uncertain termination into a confirmed failure.
        for number in handlers:
            signal.signal(number, signal.SIG_IGN)
        raise RecoveryRefused('QualificationInterrupted')
    try:
        _run_private(['true'], maximum_output=0)
        import fcntl
        lock_fd = os.open('/run/keycloak-identity-recovery.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        metadata = os.fstat(lock_fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1 and
                stat.S_IMODE(metadata.st_mode) == 0o600, 'RecoveryLockMetadataInvalid')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ('SIGTERM', 'SIGHUP', 'SIGINT'):
            number = getattr(signal, name)
            handlers[number] = signal.signal(number, interrupted)
        os.umask(0o077)
        operations = QualificationOperations(candidate, helper, helper_sha256)
        qualify_candidate(operations)
        print(json.dumps({'op': 'qualification_complete', 'result': operations.result}, separators=(',', ':')), flush=True)
        return 0
    except BaseException as error:
        failure = 'PRIVATE_CANDIDATE_CLEANUP_HOLD' if (isinstance(error, RecoveryCleanupFailure) or isinstance(error, RecoveryRefused) and
                  str(error) == 'PrivateBuildCleanupHold') else 'PRIVATE_QUALIFICATION_ABORTED' if (isinstance(error, KeyboardInterrupt) or
                    isinstance(error, RecoveryRefused) and str(error) in
                    {'QualificationInterrupted', 'PrivateRpcReplyMissing', 'PrivateRpcReplyTimeout'}) else 'PRIVATE_QUALIFICATION_FAILED'
        if operations is not None:
            primary = operations.failure_context or dict(phase=operations.phase, **_safe_error_metadata(error))
            try:
                operations.runtime.stop()
                operations.cleanup_phase = 'OwnedCandidateStopConfirmed'
            except BaseException as cleanup_error:
                failure = 'PRIVATE_CANDIDATE_CLEANUP_HOLD'
                operations.cleanup_phase, operations.cleanup_failure = 'CleanupUnconfirmed', _safe_error_metadata(cleanup_error)
            if operations.cleanup_failure is not None:
                failure = 'PRIVATE_CANDIDATE_CLEANUP_HOLD'
            try:
                _write_private(operations.receipts / 'qualification-failure.json', {
                    'status': 'FailedHold', 'error_code': failure, **primary,
                    'cleanup_phase': operations.cleanup_phase, 'cleanup_failure': operations.cleanup_failure,
                    'canonical_writes_performed': False, 'switch_ready': False})
            except BaseException:
                pass
        try:
            print(json.dumps({'op': 'qualification_failed', 'error_code': failure}), flush=True)
        except (OSError, ValueError):
            pass
        return 1
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if lock_fd is not None:
            os.close(lock_fd)


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
                "ldap_guid": PILOT_GUID, "ldap_id_count": 1, "realm_user_count": 1, "enabled": True}
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
    parser.add_argument('--qualify-private-candidate')
    parser.add_argument('--pilot-helper', type=Path)
    parser.add_argument('--pilot-helper-sha256')
    args = parser.parse_args()
    try:
        require(sum(bool(mode) for mode in (args.compare, args.prepare_candidate, args.qualify_private_candidate)) <= 1,
                "ConflictingOperationModes")
        if args.qualify_private_candidate:
            require(args.pilot_helper is not None and args.pilot_helper_sha256 is not None, 'PilotHelperClosureRequired')
            raise SystemExit(run_private_qualification(args.qualify_private_candidate, args.pilot_helper, args.pilot_helper_sha256))
        elif args.prepare_candidate:
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
