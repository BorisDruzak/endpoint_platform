"""Recovery plan must reject unsafe/incomplete evidence before any mutation."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def module():
    spec = importlib.util.spec_from_file_location(
        "identity_recovery", ROOT / "tools/keycloak/recover_pilot_identity.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def snapshot():
    return {"schema": "keycloak_recovery_snapshot_v1", "database": "keycloak",
            "database_oid": 12345, "owner": "keycloak", "server_version_num": 160014,
            "port": 5544, "schema_sha256": digest("schema"), "sequence_state": {},
            "actual_tables": list(module().TABLE_MANIFEST),
            "unexpected_functions": 0, "unexpected_triggers": 0,
            "tables": {name: [digest(f"row{i}")] for i, name in enumerate(module().TABLE_MANIFEST)}}


def test_default_plan_cannot_execute_and_holds_for_unproven_recovery():
    plan = module().build_plan()
    assert plan["status"] == "PlanOnly"
    assert plan["apply_supported"] is False
    assert plan["switch_ready"] is False
    assert "candidate_session_revocation" in plan["required_evidence"]
    assert plan["audit_clone_reusable"] is False
    assert "keycloak_identity_audit_sso20261027" not in plan["candidate_database"]


def test_full_multiset_comparison_requires_exact_reviewed_changes_not_table_exemptions():
    m = module()
    old = snapshot()
    current = copy.deepcopy(old)
    name = m.TABLE_MANIFEST[2]
    current["tables"][name] = [digest("new"), digest("new")]
    diff = m.compare_snapshots(old, current)
    assert diff == [{"table": name, "removed": [digest("row2")],
                     "added": [digest("new"), digest("new")]}]
    m.validate_reviewed_drift(old, current, diff)
    for invalid in ([], [{"table": name}], [{"table": name, "removed": [], "added": []}]):
        with pytest.raises(m.RecoveryRefused):
            m.validate_reviewed_drift(old, current, invalid)


@pytest.mark.parametrize("change", ["owner", "version", "port", "schema", "missing", "extra", "hash"])
def test_snapshots_fail_closed_for_wrong_ownership_schema_and_incomplete_table_coverage(change):
    m = module()
    old, current = snapshot(), snapshot()
    if change == "owner":
        current["owner"] = "postgres"
    elif change == "version":
        current["server_version_num"] = 170001
    elif change == "port":
        current["port"] = 5432
    elif change == "schema":
        current["schema_sha256"] = digest("different")
    elif change == "missing":
        del current["tables"][m.TABLE_MANIFEST[0]]
    elif change == "extra":
        current["tables"]["unexpected"] = []
    else:
        current["tables"][m.TABLE_MANIFEST[0]] = ["secret-not-a-hash"]
    with pytest.raises(m.RecoveryRefused):
        m.compare_snapshots(old, current)


def test_switch_sql_is_transactional_oid_guarded_and_never_kills_or_drops():
    m = module()
    sql = m.switch_sql("keycloak_recovery_20261027_abcdef12", 12345, 23456)
    assert sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;")
    assert 'ALTER DATABASE "keycloak" RENAME TO "keycloak_forensic_20261027_abcdef12"' in sql
    assert 'ALTER DATABASE "keycloak_recovery_20261027_abcdef12" RENAME TO "keycloak"' in sql
    assert "12345" in sql and "23456" in sql and "pg_prepared_xacts" in sql
    assert "pg_terminate_backend" not in sql and "DROP DATABASE" not in sql
    assert "ALLOW_CONNECTIONS false" in sql
    rollback = m.rollback_sql("keycloak_recovery_20261027_abcdef12", 12345, 23456)
    assert 'ALTER DATABASE "keycloak" RENAME TO "keycloak_failed_20261027_abcdef12"' in rollback
    assert 'ALTER DATABASE "keycloak_forensic_20261027_abcdef12" RENAME TO "keycloak"' in rollback
    assert "DROP DATABASE" not in rollback


@pytest.mark.parametrize("name", ["keycloak", "keycloak_identity_audit_sso20261027", "x;DROP DATABASE keycloak", "keycloak_recovery_20261027_abcdef12\n"])
def test_sql_rejects_nonexclusive_names(name):
    m = module()
    with pytest.raises(m.RecoveryRefused):
        m.switch_sql(name, 123, 456)


def test_identity_gate_requires_original_exact_otp_and_provider_guid_and_no_other_users():
    m = module()
    evidence = {
        "user_id_sha256": m.ORIGINAL_SUBJECT_SHA256,
        "created_timestamp": 1793048930752,
        "federation_link_sha256": m.FEDERATION_SHA256,
        "ldap_guid": m.PILOT_GUID,
        "credentials": [{"type": "otp", "created_date": 1793051223562,
                         "row_sha256": digest("otp-exact-original-row")}],
        "realm_user_count": 1, "enabled": True,
    }
    m.validate_identity(evidence, evidence)
    for key, value in [("user_id_sha256", m.REIMPORTED_SUBJECT_SHA256),
                       ("ldap_guid", "00000000-0000-0000-0000-000000000000"),
                       ("realm_user_count", 2), ("credentials", [])]:
        bad = copy.deepcopy(evidence)
        bad[key] = value
        with pytest.raises(m.RecoveryRefused):
            m.validate_identity(evidence, bad)
    bad = copy.deepcopy(evidence)
    bad["credentials"][0]["row_sha256"] = digest("changed-secret-or-metadata")
    with pytest.raises(m.RecoveryRefused):
        m.validate_identity(evidence, bad)


def test_output_never_accepts_raw_secrets_as_snapshot_values():
    m = module()
    bad = snapshot()
    bad["tables"][m.TABLE_MANIFEST[0]] = [{"secret_data": "must-never-escape"}]
    with pytest.raises(m.RecoveryRefused) as caught:
        m.compare_snapshots(snapshot(), bad)
    assert "must-never-escape" not in str(caught.value)


def test_restore_plan_never_overwrites_original_or_audit_clone_and_preserves_acls():
    plan = module().build_plan()
    command = plan["restore"]["argv"]
    assert "--no-owner" in command and "--role=keycloak" in command
    assert "--single-transaction" in command and "--exit-on-error" in command
    assert "--clean" not in command and "--create" not in command and "--no-acl" not in command
    assert command[command.index("--dbname") + 1] == plan["candidate_database"]
    assert plan["restore"]["stdin_from_verified_dump"] is True
    assert "REVOKE ALL" in plan["restore"]["create"]


def test_source_has_no_live_mutation_entrypoint():
    import ast
    source = (ROOT / "tools/keycloak/recover_pilot_identity.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {node.name for node in ast.walk(tree) if isinstance(node, ast.alias)}
    assert "psycopg" not in imports
    assert "--apply" not in source
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    assert "qualify_candidate" not in ast.unparse(main)


@pytest.mark.parametrize("credentials", [["raw-secret"], [None], [{}]])
def test_malformed_credential_evidence_fails_with_fixed_diagnostic(credentials):
    m = module()
    evidence = {"user_id_sha256": m.ORIGINAL_SUBJECT_SHA256,
                "created_timestamp": 1793048930752,
                "federation_link_sha256": m.FEDERATION_SHA256,
                "ldap_guid": m.PILOT_GUID, "realm_user_count": 1,
                "enabled": True, "credentials": credentials}
    with pytest.raises(m.RecoveryRefused) as caught:
        m.validate_identity(evidence, evidence)
    assert str(caught.value) == "OriginalOtpEvidenceMissing"


def test_same_size_wrong_table_manifest_refused_even_in_both_inputs():
    m = module()
    before = snapshot()
    before["tables"]["unknown_instead_of_credential"] = before["tables"].pop("credential")
    with pytest.raises(m.RecoveryRefused, match="PinnedTableManifestMismatch"):
        m.compare_snapshots(before, before)


def test_purge_outbound_effects_require_all_realm_absence_proof():
    m = module()
    safe = {"admin_url_count": 0, "backchannel_url_count": 0,
            "event_listeners": ["jboss-logging"], "identity_provider_count": 0,
            "smtp_entry_count": 0, "custom_provider_artifact_count": 0}
    m.validate_outbound_safety(safe)
    for key in safe:
        bad = copy.deepcopy(safe)
        bad[key] = ["custom-http-webhook"] if key == "event_listeners" else 1
        with pytest.raises(m.RecoveryRefused):
            m.validate_outbound_safety(bad)


def test_private_inventory_sql_hashes_server_side_in_one_readonly_snapshot_and_pins_names():
    m = module()
    sql = m.inventory_sql()
    assert sql.startswith("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;")
    assert sql.count("COMMIT;") == 1
    for name in m.TABLE_MANIFEST:
        assert f'FROM public."{name}" AS row' in sql
    assert "sha256(convert_to(to_jsonb(row)::text,'UTF8'))" in sql
    assert "schema_sha256" in sql and "sequence_state" in sql
    assert "SELECT oid::bigint FROM pg_database" in sql
    assert "pg_get_indexdef" in sql and "pg_get_constraintdef" in sql
    assert "relacl" in sql and "pg_get_userbyid" in sql
    # The aggregate contains row digests, never raw credential fields.
    assert "secret_data" not in sql and "credential_data" not in sql
    assert "DELETE " not in sql and "UPDATE " not in sql


def test_private_config_copy_changes_only_isolation_fields_and_keeps_secret_off_argv():
    m = module()
    source = (ROOT / "deploy/keycloak/keycloak.conf").read_text(encoding="utf-8")
    source += "\ndb-password=sentinel-secret-not-argv\n"
    result = m.candidate_configuration(source, "keycloak_recovery_20261027_abcdef12")
    values = dict(line.split("=", 1) for line in result.splitlines() if line and not line.startswith("#"))
    assert values["db-password"] == "sentinel-secret-not-argv"
    assert values["db-url"].endswith("/keycloak_recovery_20261027_abcdef12")
    assert values["http-host"] == values["http-management-host"] == "127.0.0.1"
    assert values["http-port"] == "8089" and values["http-management-port"] == "9009"
    assert values["cache"] == "local"
    assert values["log"] == "console" and values["http-access-log-enabled"] == "false"
    assert "proxy-headers" not in values and "proxy-trusted-addresses" not in values
    for extra in ("db-url=jdbc:postgresql://remote:5544/keycloak\n", "cache=ispn\n", "unknown-config=1\n"):
        with pytest.raises(m.RecoveryRefused):
            m.candidate_configuration(source + extra, "keycloak_recovery_20261027_abcdef12")


def test_collector_rejects_hidden_tables_functions_and_triggers():
    m = module()
    for key, value in [("actual_tables", list(m.TABLE_MANIFEST) + ["hidden"]),
                       ("unexpected_functions", 1), ("unexpected_triggers", 1)]:
        bad = snapshot()
        bad[key] = value
        with pytest.raises(m.RecoveryRefused):
            m.compare_snapshots(bad, bad)


def test_sequence_value_change_is_explicit_drift_not_schema_fingerprint():
    m = module()
    before, after = snapshot(), snapshot()
    before["sequence_state"] = {"sequence_test": digest("1,true")}
    after["sequence_state"] = {"sequence_test": digest("2,true")}
    assert m.compare_snapshots(before, after) == [{"sequence": "sequence_test",
        "before_sha256": digest("1,true"), "after_sha256": digest("2,true")}]


def test_isolated_launch_recipe_has_separate_tree_environment_ports_and_no_secret_arguments():
    m = module()
    recipe = m.runtime_recipe("keycloak_recovery_20261027_abcdef12")
    command = recipe["argv"]
    assert command[:5] == ["runuser", "-u", "keycloak", "--", "env"]
    assert "-i" in command
    assert command[-2:] == ["start", "--optimized"]
    assert command[-3].startswith("--config-file=/var/lib/keycloak-recovery/")
    assert command[-4].startswith("/var/lib/keycloak-recovery/")
    assert not any("/opt/keycloak" in arg for arg in command)
    assert any("JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m" == arg for arg in command)
    assert recipe["http"] == "127.0.0.1:8089" and recipe["management"] == "127.0.0.1:9009"
    assert recipe["shared_mutable_paths"] == [] and recipe["cache"] == "local"


def test_candidate_api_rejects_unproven_pid_database_or_external_socket_before_token_request():
    m = module()
    good = {"candidate_database": "keycloak_recovery_20261027_abcdef12", "pid": 1234,
            "canonical_pid": 9876, "uid_matches_keycloak": True,
            "http_listener": "127.0.0.1:8089", "management_listener": "127.0.0.1:9009",
            "socket_pids": [1234], "configuration_sha256_matches": True,
            "private_distribution_sha256_matches": True, "private_data_tmp_logs": True,
            "jdbc_session_database_matches": True, "no_jgroups_sockets": True,
            "no_proxy_routes": True}
    m.validate_runtime_proof(good)
    for key, value in [("pid", 9876), ("http_listener", "0.0.0.0:8089"),
                       ("jdbc_session_database_matches", False), ("private_data_tmp_logs", False),
                       ("socket_pids", [9876])]:
        bad = copy.deepcopy(good)
        bad[key] = value
        with pytest.raises(m.RecoveryRefused):
            m.validate_runtime_proof(bad)


def test_qualification_orchestrator_repairs_retention_before_any_pilot_lookup_and_stops_owned_runtime():
    m = module()
    class Ops:
        def __init__(self): self.calls = []
        def perform(self, operation):
            self.calls.append(operation)
            return {"status": "verified"}
    ops = Ops()
    result = m.qualify_candidate(ops)
    assert result["status"] == "CandidateQualificationEvidenceRequired"
    assert result["switch_ready"] is False
    assert ops.calls.index("apply_reviewed_retention_without_user_lookup") < ops.calls.index("verify_original_pilot_and_otp")
    assert ops.calls.index("verify_all_realm_no_outbound_effects") < ops.calls.index("purge_restored_sessions_master_last")
    assert ops.calls.index("stop_owned_candidate_pid") < ops.calls.index("verify_persisted_sessions_zero")
    assert "switch_database_names" not in ops.calls and "stop_keycloak_service" not in ops.calls
    assert ops.calls.count("stop_owned_candidate_pid") == 1


def test_qualification_failure_always_stops_only_owned_candidate_and_never_promotes():
    m = module()
    class Ops:
        def __init__(self): self.calls = []
        def perform(self, operation):
            self.calls.append(operation)
            if operation == "apply_reviewed_retention_without_user_lookup":
                raise m.RecoveryRefused("InjectedRetentionFailure")
            return {"status": "verified"}
    ops = Ops()
    with pytest.raises(m.RecoveryRefused, match="InjectedRetentionFailure"):
        m.qualify_candidate(ops)
    assert ops.calls[-1] == "stop_owned_candidate_pid"
    assert "verify_original_pilot_and_otp" not in ops.calls


def test_collector_transport_uses_readonly_postgres_peer_fixed_cluster_and_no_secret_output():
    m = module()
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return json.dumps(snapshot()).encode()
    result = m.collect_inventory("keycloak", runner=run)
    assert result["owner"] == "keycloak"
    argv, kwargs = calls[0]
    assert argv[:5] == ["runuser", "-u", "postgres", "--", "env"]
    assert "PGOPTIONS=-c default_transaction_read_only=on" in argv
    assert argv[argv.index("--port") + 1] == "5544"
    assert "--no-password" in argv and "--no-psqlrc" in argv
    assert kwargs["input_bytes"].startswith(b"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;")
    assert kwargs["maximum_output"] == 32 * 1024 * 1024
    with pytest.raises(m.RecoveryRefused):
        m.collect_inventory("keycloak_identity_audit_sso20261027", runner=run)
    assert len(calls) == 1


def test_collector_discards_raw_psql_error_and_any_unexpected_secret_data():
    m = module()
    def bad_runner(*args, **kwargs):
        return b'{"password":"must-never-print"}'
    with pytest.raises(m.RecoveryRefused) as caught:
        m.collect_inventory("keycloak", runner=bad_runner)
    assert "must-never-print" not in str(caught.value)


def test_privileged_runner_resolves_debian_runuser_without_inheriting_operator_path():
    m = module()
    assert "/usr/sbin" in m.SYSTEM_PATH.split(":")
    assert "/sbin" in m.SYSTEM_PATH.split(":")


def test_session_purge_is_bounded_offline_first_and_master_last_without_user_queries():
    m = module()
    class Client:
        admin_iat = 100
        def __init__(self): self.calls = []
        def request(self, method, path, *, payload=None):
            self.calls.append((method, path, payload))
            return {"notBefore": 100}
    client = Client()
    inventory = {"realms": ["master", "sosnadmin"], "maximum_restored_token_iat": 50,
                 "offline_sessions": [{"realm": "master", "id": "00000000-0000-0000-0000-000000000001"},
                                      {"realm": "sosnadmin", "id": "00000000-0000-0000-0000-000000000002"}]}
    result = m.purge_sessions(client, inventory)
    assert result["offline_deleted"] == 2 and result["master_logout_last"] is True
    assert client.calls[0][0] == "DELETE"
    assert client.calls[-1] == ("POST", "/admin/realms/master/logout-all", None)
    assert all("/users" not in path for _, path, _ in client.calls)
    master_start = next(i for i, (_, path, _) in enumerate(client.calls) if path.startswith("/admin/realms/master"))
    assert all(not path.startswith("/admin/realms/sosnadmin") for _, path, _ in client.calls[master_start:])
    assert client.not_before_payloads == {"master": 100, "sosnadmin": 100}


@pytest.mark.parametrize("unsafe", ["newer-token", "unknown-realm", "path-injection", "too-many"])
def test_session_purge_refuses_unsafe_inventory_before_any_api_write(unsafe):
    m = module()
    class Client:
        admin_iat = 100
        def request(self, *args, **kwargs): raise AssertionError("No API call permitted")
    inventory = {"realms": ["master", "sosnadmin"], "maximum_restored_token_iat": 50, "offline_sessions": []}
    if unsafe == "newer-token": inventory["maximum_restored_token_iat"] = 100
    elif unsafe == "unknown-realm": inventory["realms"].append("unexpected")
    elif unsafe == "path-injection": inventory["offline_sessions"] = [{"realm": "master", "id": "../users/admin"}]
    else: inventory["offline_sessions"] = [{"realm": "master", "id": "00000000-0000-0000-0000-000000000001"}] * 101
    with pytest.raises(m.RecoveryRefused):
        m.purge_sessions(Client(), inventory)


def test_prepare_capacity_guard_includes_private_distribution_and_forensic_growth():
    m = module()
    good = {"free_bytes": 10 * 1024**3, "available_memory_bytes": 5 * 1024**3,
            "current_database_bytes": 15 * 1024**2, "distribution_bytes": 184 * 1024**2,
            "dump_bytes": 450 * 1024}
    assert m.validate_capacity(good)["sufficient"] is True
    for key, value in [("free_bytes", 3 * 1024**3), ("available_memory_bytes", 2 * 1024**3),
                       ("current_database_bytes", 10 * 1024**3), ("dump_bytes", -1)]:
        bad = dict(good, **{key: value})
        with pytest.raises(m.RecoveryRefused):
            m.validate_capacity(bad)


def test_prepare_stops_before_jvm_and_current_service_even_on_success():
    m = module()
    class Ops:
        def __init__(self): self.calls = []
        def perform(self, name): self.calls.append(name); return {"verified": True}
    ops = Ops()
    result = m.prepare_candidate(ops)
    assert result["status"] == "CandidateRestoredReviewRequired"
    assert result["switch_ready"] is False
    assert ops.calls.index("verify_pinned_backup_config_and_capacity") < ops.calls.index("restore_fresh_owned_candidate")
    assert ops.calls.index("capture_current_forensic_backup") < ops.calls.index("restore_fresh_owned_candidate")
    assert not any("start" in name or "stop" in name or "switch" in name for name in ops.calls)


def test_actual_restore_adapter_uses_verified_stdin_only_and_never_canonical_or_audit_destination(tmp_path):
    m = module()
    calls = []
    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return b"0\n" if len(calls) == 1 else b""
    ops = m.PrepareOperations(runner=runner)
    ops.stage = tmp_path
    ops.forensic = tmp_path
    ops.dump_data = b"verified-original-dump-test-only"
    result = ops.restore()
    assert result["canonical_database_unchanged"] is True
    assert ops.dump_data is None
    assert len(calls) == 3
    assert calls[-1][1]["input_bytes"] == b"verified-original-dump-test-only"
    destination = calls[-1][0][calls[-1][0].index("--dbname") + 1]
    assert destination.startswith("keycloak_recovery_20261027_")
    assert destination not in {"keycloak", "keycloak_identity_audit_sso20261027"}
    assert "REVOKE ALL" in calls[1][1]["input_bytes"].decode()
    assert all("DROP DATABASE" not in str(kwargs) and "pg_terminate_backend" not in str(kwargs) for _, kwargs in calls)


def test_actual_restore_adapter_refuses_existing_database_without_write_or_cleanup(tmp_path):
    m = module()
    calls = []
    def runner(argv, **kwargs): calls.append(argv); return b"1\n"
    ops = m.PrepareOperations(runner=runner)
    ops.stage = tmp_path
    ops.forensic = tmp_path
    ops.dump_data = b"verified-original-dump-test-only"
    with pytest.raises(m.RecoveryRefused, match="CandidateDatabaseAlreadyExists"):
        ops.restore()
    assert len(calls) == 1
