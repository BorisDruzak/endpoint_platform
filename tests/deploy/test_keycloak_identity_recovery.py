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
        "ldap_id_count": 1,
        "credentials": [{"type": "otp", "created_date": 1793051223562,
                         "row_sha256": digest("otp-exact-original-row")}],
        "realm_user_count": 1, "enabled": True,
    }
    m.validate_identity(evidence, evidence)
    for key, value in [("user_id_sha256", m.REIMPORTED_SUBJECT_SHA256),
                       ("ldap_guid", "00000000-0000-0000-0000-000000000000"),
                       ("ldap_id_count", 2),
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
                "ldap_guid": m.PILOT_GUID, "ldap_id_count": 1, "realm_user_count": 1,
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
            "smtp_entry_count": 0, "custom_provider_artifact_count": 0,
            "storage_provider_count":1,"ldap_configuration_safe":True}
    m.validate_outbound_safety(safe)
    for key in safe:
        bad = copy.deepcopy(safe)
        bad[key] = (["custom-http-webhook"] if key == "event_listeners" else
                    2 if key=='storage_provider_count' else False if key=='ldap_configuration_safe' else 1)
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
    assert command[-3].startswith("--config-file=/var/lib/keycloak-recovery-v7/")
    assert command[-4].startswith("/var/lib/keycloak-recovery-v7/")
    assert not any("/opt/keycloak" in arg for arg in command)
    assert any("JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m" == arg for arg in command)
    assert any('-Duser.home=/var/lib/keycloak-recovery-v7/keycloak_recovery_20261027_abcdef12/work' in arg for arg in command)
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


def test_browser_tls_profile_is_fixed_private_and_never_uses_a_validation_bypass():
    m = module()
    source = (ROOT / "deploy/keycloak/keycloak.conf").read_text(encoding="utf-8") + "\ndb-password=sentinel-secret-not-argv\n"
    candidate = "keycloak_recovery_20261027_abcdef12"
    result = m.candidate_configuration(source, candidate, browser_tls=True)
    values = dict(line.split("=", 1) for line in result.splitlines() if line)
    assert values["hostname"] == "https://sso.sosnadmin.local:18449"
    assert values["https-port"] == "8449" and values["http-management-scheme"] == "http"
    assert values["https-certificate-key-file"] == "/var/lib/keycloak-recovery-v7/" + candidate + "/tls/key.pem"
    assert values["https-certificate-file"] == "/var/lib/keycloak-recovery-v7/" + candidate + "/tls/fullchain.pem"
    assert values["http-host"] == "127.0.0.1"
    recipe = m.runtime_recipe(candidate, browser_tls=True)
    assert recipe["https"] == "127.0.0.1:8449"
    assert recipe["browser_origin"] == "https://sso.sosnadmin.local:18449"
    assert recipe["browser_network_permission"] == "ExactCandidateOriginAndInterceptedCallbacksOnly"


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
                 "realm_not_before":{"master":0,"sosnadmin":0},
                 "offline_sessions": [{"realm": "master", "id": "00000000-0000-0000-0000-000000000001"},
                                      {"realm": "sosnadmin", "id": "00000000-0000-0000-0000-000000000002"}]}
    result = m.purge_sessions(client, inventory)
    assert result["offline_deleted"] == 2 and result["master_logout_last"] is True
    assert client.calls[0][0] == "DELETE"
    assert client.calls[-1] == ("POST", "/admin/realms/master/logout-all", None)
    nonmaster = "/admin/realms/sosnadmin"
    # logout-all itself raises NB to currentTime; never PUT a lower cutoff after.
    assert client.calls.index(("PUT", nonmaster, {"notBefore": 100})) < client.calls.index(("POST", nonmaster + "/logout-all", None))
    assert all("/users" not in path for _, path, _ in client.calls)
    master_start = next(i for i, (_, path, _) in enumerate(client.calls) if path.startswith("/admin/realms/master"))
    assert all(not path.startswith("/admin/realms/sosnadmin") for _, path, _ in client.calls[master_start:])
    assert client.not_before_payloads == {"master": 100, "sosnadmin": 100}


def test_identity_sql_emits_only_expected_metadata_and_server_side_otp_digest():
    m = module()
    sql = m.identity_sql()
    assert sql.startswith("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;")
    assert "ssopilot-20261027" in sql and m.REALM_ID in sql
    assert "to_jsonb(credential_row)::text" in sql
    assert "sha256" in sql and "credentials" in sql
    assert "secret_data" not in sql and "credential_data" not in sql
    assert "LDAP_ID" in sql and m.PILOT_GUID in sql
    assert "'ldap_id_count'" in sql


@pytest.mark.parametrize("unsafe", ["newer-token", "unknown-realm", "path-injection", "too-many"])
def test_session_purge_refuses_unsafe_inventory_before_any_api_write(unsafe):
    m = module()
    class Client:
        admin_iat = 100
        def request(self, *args, **kwargs): raise AssertionError("No API call permitted")
    inventory = {"realms": ["master", "sosnadmin"], "maximum_restored_token_iat": 50, "offline_sessions": [],
                 "realm_not_before":{"master":0,"sosnadmin":0}}
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


def session_client_fixture():
    import base64
    payload = base64.urlsafe_b64encode(json.dumps({"iat": 100,"exp":400,
        "sid":"00000000-0000-0000-0000-000000000099",
        "iss":"https://sso.sosnadmin.local:18449/realms/master","azp":"admin-cli"}).encode()).decode().rstrip("=")
    proof = {"candidate_database": "keycloak_recovery_20261027_abcdef12", "pid": 1234,
             "canonical_pid": 9876, "uid_matches_keycloak": True,
             "http_listener": "127.0.0.1:8089", "management_listener": "127.0.0.1:9009",
             "socket_pids": [1234], "configuration_sha256_matches": True,
             "private_distribution_sha256_matches": True, "private_data_tmp_logs": True,
             "jdbc_session_database_matches": True, "no_jgroups_sockets": True, "no_proxy_routes": True}
    return "header." + payload + ".signature", proof


def test_candidate_session_transport_pins_receiver_and_consumes_exact_write_once():
    m = module()
    token, proof = session_client_fixture()
    calls, checks = [], []
    def verifier(): checks.append(1); return proof
    def transport(request): calls.append(request); return {"notBefore": 100}
    client = m.CandidateSessionClient(token, runtime_verifier=verifier, transport=transport)
    client.not_before_payloads = {"sosnadmin": 100}
    client.request("PUT", "/admin/realms/sosnadmin", payload={"notBefore": 100})
    assert len(calls) == 1 and len(checks) >= 2
    assert calls[0].full_url == "http://127.0.0.1:8089/admin/realms/sosnadmin"
    assert calls[0].get_header("Authorization") == "Bearer " + token
    assert json.loads(calls[0].data) == {"notBefore": 100}
    for method, path, payload in [("PUT", "/admin/realms/sosnadmin", {"notBefore": 100}),
                                   ("GET", "/admin/realms/sosnadmin/users", None),
                                   ("POST", "/admin/realms/master/logout-all", None),
                                   ("PUT", "/admin/realms/master", {"notBefore": 100, "enabled": False})]:
        with pytest.raises(m.RecoveryRefused): client.request(method, path, payload=payload)
    assert len(calls) == 1


def test_candidate_session_transport_rechecks_live_pid_before_every_request():
    m = module()
    token, proof = session_client_fixture()
    calls = []
    client = m.CandidateSessionClient(token, runtime_verifier=lambda: proof,
                                      transport=lambda request: calls.append(request))
    proof["socket_pids"] = [9876]
    with pytest.raises(m.RecoveryRefused):
        client.request("GET", "/admin/realms/master")
    assert calls == []


def test_candidate_session_transport_cannot_expand_writes_by_guard_set_poisoning():
    m = module()
    token, proof = session_client_fixture()
    calls = []
    client = m.CandidateSessionClient(token, runtime_verifier=lambda: proof,
                                      transport=lambda request: calls.append(request))
    dangerous = "/admin/realms/sosnadmin/users/00000000-0000-0000-0000-000000000001"
    client.session_delete_paths = {dangerous}
    client.logout_paths = {dangerous}
    for method in ["DELETE", "POST"]:
        with pytest.raises(m.RecoveryRefused): client.request(method, dangerous)
    assert calls == []


@pytest.mark.parametrize("cutoff", [0, -1, 101, True, 100.0])
def test_candidate_session_transport_not_before_is_immutable_token_iat(cutoff):
    m = module()
    token, proof = session_client_fixture()
    calls = []
    client = m.CandidateSessionClient(token, runtime_verifier=lambda: proof,
                                      transport=lambda request: calls.append(request))
    client.not_before_payloads = {"master": cutoff}
    with pytest.raises(m.RecoveryRefused): client.request("PUT", "/admin/realms/master", payload={"notBefore": cutoff})
    assert calls == []


def test_distribution_closure_rejects_live_data_escape_and_custom_plugins():
    m = module()
    manifest = {"bin/kc.sh": {"kind": "file", "sha256": digest("script"), "mode": 0o755, "uid": 0},
                "lib/runtime.jar": {"kind": "file", "sha256": digest("jar"), "mode": 0o644, "uid": 0},
                "data": {"kind": "symlink", "target": "/var/lib/keycloak", "uid": 0}}
    assert m.validate_distribution_manifest(manifest, live_source=True)["binary_files"] == 2
    for change in ("symlink", "plugin", "writable", "foreign"):
        bad = copy.deepcopy(manifest)
        if change == "symlink": bad["lib/escape"] = {"kind": "symlink", "target": "/etc", "uid": 0}
        elif change == "plugin": bad["providers/webhook.jar"] = {"kind": "file", "sha256": digest("custom"), "mode": 0o644, "uid": 0}
        elif change == "writable": bad["bin/kc.sh"]["mode"] = 0o777
        else: bad["lib/runtime.jar"]["uid"] = 1000
        with pytest.raises(m.RecoveryRefused): m.validate_distribution_manifest(bad, live_source=True)
    with pytest.raises(m.RecoveryRefused): m.validate_distribution_manifest(manifest, live_source=False)
    missing_data = copy.deepcopy(manifest)
    del missing_data["data"]
    with pytest.raises(m.RecoveryRefused): m.validate_distribution_manifest(missing_data, live_source=True)


def test_private_runtime_stop_never_targets_canonical_pid_or_uses_service_manager():
    m = module()
    runtime = m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    runtime.process = None
    assert runtime.stop() == {"owned_candidate_stopped": True, "never_started": True}
    source = (ROOT / "tools/keycloak/recover_pilot_identity.py").read_text(encoding="utf-8")
    import ast
    tree = ast.parse(source)
    runtime_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PrivateCandidateRuntime")
    assert "systemctl" not in ast.unparse(runtime_class)
    assert "pkill" not in ast.unparse(runtime_class)
    assert "pg_terminate_backend" not in ast.unparse(runtime_class)


@pytest.mark.parametrize("failure", ["canonical-pid", "pid-reuse", "foreign-pgid-member"])
def test_actual_runtime_stop_guard_rejects_signal_for_uncertain_process(failure, monkeypatch):
    from types import SimpleNamespace
    m = module()
    runtime = m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    runtime.process = SimpleNamespace(pid=40, poll=lambda:None)
    runtime.process_start = 123
    runtime.canonical_pid = 40 if failure == "canonical-pid" else 90
    runtime.private = Path('/var/lib/keycloak-recovery-v7/keycloak_recovery_20261027_abcdef12')
    runtime.keycloak = SimpleNamespace(pw_uid=1000)
    runtime.output = None
    monkeypatch.setattr(m, '_pid_start', lambda pid:999 if failure == 'pid-reuse' else 123)
    class Node:
        name='55'
        def stat(self): return SimpleNamespace(st_uid=1000)
        def __truediv__(self, name): return self
        def read_text(self): return '55 (unrelated) S ' + '1 ' * 30
        def read_bytes(self): return b'/usr/bin/unrelated'
    monkeypatch.setattr(m, 'Path', lambda value:SimpleNamespace(iterdir=lambda:[Node()]))
    monkeypatch.setattr(m.os, 'getpgid', lambda pid:40, raising=False)
    signals=[]
    monkeypatch.setattr(m.os, 'killpg', lambda *args:signals.append(args), raising=False)
    with pytest.raises(m.RecoveryRefused): runtime.stop()
    assert signals == []


def test_actual_runtime_partial_start_failure_cleans_only_owned_runtime(monkeypatch):
    m = module()
    runtime = m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    calls=[]
    def partial(): calls.append('own-process-started'); raise m.RecoveryRefused('InjectedReadinessFailure')
    monkeypatch.setattr(runtime,'_start_owned',partial,raising=False)
    monkeypatch.setattr(runtime,'stop',lambda:calls.append('own-stop'))
    with pytest.raises(m.RecoveryRefused,match='InjectedReadinessFailure'): runtime.start()
    assert calls == ['own-process-started','own-stop']


def test_outbound_metadata_sql_is_all_realms_and_never_emits_url_values():
    m = module()
    sql = m.outbound_safety_sql()
    assert sql.startswith("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;")
    assert "management_url" in sql and "backchannel" in sql
    assert "realm_events_listeners" in sql and "realm_smtp_config" in sql
    assert "identity_provider" in sql and "max_diff_lifespan" not in sql
    assert "'admin_url_count'" in sql and "'backchannel_url_count'" in sql


def test_fresh_private_distribution_is_anchored_to_independent_release_archive():
    m = module()
    release = json.loads((ROOT/'deploy/keycloak/release.json').read_text())
    assert m.DISTRIBUTION_ARCHIVE_SHA256 == release['sha256']
    assert m.DISTRIBUTION_ARCHIVE == Path('/root/keycloak-input/keycloak-26.8.1.tar.gz')
    import ast
    tree = ast.parse((ROOT/'tools/keycloak/recover_pilot_identity.py').read_text())
    klass = next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='PrivateCandidateRuntime')
    preparation = next(node for node in klass.body if isinstance(node,ast.FunctionDef) and node.name=='copy_and_configure')
    text = ast.unparse(preparation)
    assert 'DISTRIBUTION_ARCHIVE_SHA256' in text and 'extractall' in text
    assert 'copytree' not in text and '/opt/keycloak' not in text


def test_private_archive_rejects_paths_links_devices_and_decompression_bombs():
    import tarfile
    m = module()
    good=tarfile.TarInfo('keycloak-26.8.1/bin/kc.sh');good.size=10
    assert m.validate_archive_members([good])['files']==1
    for name,kind,size in [('keycloak-26.8.1/../../escape',tarfile.REGTYPE,1),
                           ('/absolute',tarfile.REGTYPE,1),('wrong-version/bin/kc.sh',tarfile.REGTYPE,1),
                           ('keycloak-26.8.1/data',tarfile.SYMTYPE,1),
                           ('keycloak-26.8.1/hard',tarfile.LNKTYPE,1),
                           ('keycloak-26.8.1/device',tarfile.CHRTYPE,1),
                           ('keycloak-26.8.1/bomb',tarfile.REGTYPE,2*1024**3)]:
        entry=tarfile.TarInfo(name);entry.type=kind;entry.size=size
        with pytest.raises(m.RecoveryRefused):m.validate_archive_members([entry])


def test_private_build_has_no_network_shared_home_or_inherited_environment():
    m = module()
    recipe=m.private_build_recipe('keycloak_recovery_20261027_abcdef12')
    assert recipe['argv'][:5]==['unshare','--net','--','env','-i']
    assert recipe['argv'][-5:]==['build','--db=postgres','--health-enabled=true','--metrics-enabled=false','--cache=local']
    assert all('/opt/keycloak' not in arg for arg in recipe['argv'])
    assert any(arg.startswith('HOME=/var/lib/keycloak-recovery-v7/') for arg in recipe['argv'])
    assert any(arg.startswith('JAVA_OPTS_KC_HEAP=-Xms128m -Xmx1024m') for arg in recipe['argv'])


def test_session_provenance_excludes_only_fresh_master_sid_and_emits_no_tokens():
    m = module()
    sid='00000000-0000-0000-0000-000000000099'
    sql=m.session_inventory_sql(sid)
    assert sql.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;')
    assert "offline_flag='1'" in sql and "user_session_id<>'"+sid+"'" in sql
    assert 'fresh_master_session_count' in sql and 'maximum_restored_token_iat' in sql
    assert 'last_session_refresh' in sql and 'created_on' in sql
    assert 'data' not in sql.replace('database','')
    with pytest.raises(m.RecoveryRefused):m.session_inventory_sql("../users/arbitrary")


def test_poststop_proof_rejects_any_persistent_auth_or_online_offline_session():
    m = module()
    good={'offline_user_session':0,'offline_client_session':0,'auth_session':0,'root_auth_session':0,
          'realm_not_before':{'master':100,'sosnadmin':101}}
    m.validate_poststop_sessions(good,100)
    for table in ['offline_user_session','offline_client_session','auth_session','root_auth_session']:
        bad=dict(good,**{table:1})
        with pytest.raises(m.RecoveryRefused):m.validate_poststop_sessions(bad,100)
    with pytest.raises(m.RecoveryRefused):m.validate_poststop_sessions(dict(good,realm_not_before={'master':99,'sosnadmin':100}),100)


def test_server_browser_provenance_gate_requires_same_context_and_cookie_without_otp():
    m=module(); binding={'candidate_database':'keycloak_recovery_20261027_abcdef12','candidate_oid':20856,
        'pid':1234,'config_sha256':digest('conf'),'source_sha256':digest('source')}
    gate=m.ServerBrowserProofGate(binding)
    ready={'stage':'browser_ready','context_id':'00000000-0000-0000-0000-000000000001',
           'binding_sha256':gate.binding_sha256,'all_callbacks_intercepted':True,'strict_tls':True,
           'http_default_deny':True,'websocket_default_deny':True}
    gate.started(ready)
    def proof(first,before,after):return {'stage':'callback','context_id':ready['context_id'],
        'code_present':True,'state_matches':True,'callback_matches':True,'error_present':False,
        'password_prompts':int(first),'otp_prompts':0,'cookie_fingerprint_sha256':after,
        'identity_cookie_present':True,'cookies_secure':True,'cookie_count':2,
        'cookie_before_sha256':before,'blocked_egress':0}
    initial=proof(True,digest('empty'),digest('initial'));sso=proof(False,digest('initial'),digest('sso'))
    bad=copy.deepcopy(sso);bad['cookie_before_sha256']=digest('other')
    with pytest.raises(m.RecoveryRefused):gate.positive(initial,bad)
    gate.positive(initial,sso)
    negative={'stage':'password_required','context_id':ready['context_id'],'cookie_before_sha256':digest('sso'),
        'password_prompts':0,'otp_prompts':0,'callback_absent':True,'blocked_egress':0}
    bad=dict(negative,otp_prompts=1)
    with pytest.raises(m.RecoveryRefused):gate.negative(bad)
    gate.negative(negative)
    gate.closed({'stage':'closed'})
    assert gate.phase=='closed'


def test_canonical_java_reference_follows_wrapper_ancestry_not_systemd_main_exe():
    m=module();exe='/usr/lib/jvm/java-21-openjdk-amd64/bin/java'
    records=[{'pid':10,'ppid':1,'uid':988,'exe':'/usr/bin/dash','start_ticks':100},
             {'pid':11,'ppid':10,'uid':988,'exe':exe,'start_ticks':101}]
    assert m.canonical_java_from_metadata(10,988,exe,records)==records[1]
    for failure in ['zero','multiple','foreign-uid','non-descendant']:
        bad=copy.deepcopy(records)
        if failure=='zero':bad.pop()
        elif failure=='multiple':bad.append(dict(records[1],pid=12))
        elif failure=='foreign-uid':bad[1]['uid']=999
        else:bad[1]['ppid']=999
        with pytest.raises(m.RecoveryRefused):m.canonical_java_from_metadata(10,988,exe,bad)


def test_owned_stop_forbids_canonical_java_pid_and_both_canonical_groups(monkeypatch):
    from types import SimpleNamespace
    m=module();runtime=m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    runtime.process=SimpleNamespace(pid=40,poll=lambda:None);runtime.process_start=123
    runtime.canonical_pid=90;runtime.canonical_java_pid=91;runtime.forbidden_group_ids={40,91}
    monkeypatch.setattr(m,'_pid_start',lambda pid:123)
    signals=[];monkeypatch.setattr(m.os,'killpg',lambda *args:signals.append(args),raising=False)
    with pytest.raises(m.RecoveryRefused):runtime.stop()
    assert signals==[]


@pytest.mark.parametrize('scenario',['timeout','wrapper-exited-child-alive'])
def test_private_build_cleanup_owns_group_even_when_shell_has_exited(scenario,monkeypatch):
    import io
    m=module();state={'alive':True,'members':True};signals=[]
    class Process:
        pid=40;returncode=None
        def poll(self):return None if state['alive'] else self.returncode
        def communicate(self,input=None,timeout=None):
            if scenario=='timeout':raise m.subprocess.TimeoutExpired('private-build',timeout)
            state['alive']=False;self.returncode=1
        def wait(self,timeout=None):state['alive']=False;self.returncode=-15;return self.returncode
    process=Process()
    monkeypatch.setattr(m.subprocess,'Popen',lambda *args,**kwargs:process)
    monkeypatch.setattr(m,'_pid_start',lambda pid:123)
    monkeypatch.setattr(m,'_owned_build_members',lambda group,prefix:[41] if state['members'] else [],raising=False)
    monkeypatch.setattr(m.os,'getpgrp',lambda:99,raising=False)
    monkeypatch.setattr(m.os,'getpgid',lambda pid:40,raising=False)
    def signal_group(group,number):signals.append((group,number));state['members']=False
    monkeypatch.setattr(m.os,'killpg',signal_group,raising=False)
    invoke=lambda:m._run_owned_private_group(['private-build'],input_bytes=None,output=io.BytesIO(),timeout=1,
        cwd=None,environment={},prefix='/var/lib/keycloak-recovery-v7/keycloak_recovery_20261027_abcdef12',forbidden={90,91})
    if scenario=='timeout':
        with pytest.raises(m.subprocess.TimeoutExpired):invoke()
    else:invoke()
    assert signals==[(40,m.signal.SIGTERM)] and not state['members']


def test_canonical_capture_compares_identical_systemd_events_without_proc_clock_tolerance(monkeypatch):
    m=module()
    prepared={'MainPID':'312382','ExecMainStartTimestampMonotonic':'656005833129','ActiveState':'active'}
    java={'pid':312467,'ppid':312382,'uid':999,'start_ticks':65600589,
          'exe':'/usr/lib/jvm/java-21-openjdk-amd64/bin/java'}
    calls=[]
    def runner(argv,**kwargs):
        calls.append(argv)
        return ''.join(key+'='+value+'\n' for key,value in prepared.items()).encode()
    monkeypatch.setattr(m,'_pid_start',lambda pid:65600582 if pid==312382 else 65600589)
    monkeypatch.setattr(m,'_canonical_java_reference',lambda pid,uid:java)
    # Actual native case: proc creation precedes systemd exec-start by13.129ms.
    assert abs(65600582*10000-int(prepared['ExecMainStartTimestampMonotonic']))==13129
    main_pid,start_ticks,actual_java=m._capture_canonical_reference(prepared,999,runner=runner)
    assert (main_pid,start_ticks,actual_java)==(312382,65600582,java)
    assert len(calls)==2 and all(call[:3]==['systemctl','show','keycloak'] for call in calls)


@pytest.mark.parametrize('change',['first-pid','first-timestamp','first-active','second-pid','second-timestamp','second-active','main-tick','java-tick'])
def test_canonical_capture_refuses_metadata_or_proc_identity_change(change,monkeypatch):
    m=module()
    prepared={'MainPID':'312382','ExecMainStartTimestampMonotonic':'656005833129','ActiveState':'active'}
    java={'pid':312467,'ppid':312382,'uid':999,'start_ticks':65600589,
          'exe':'/usr/lib/jvm/java-21-openjdk-amd64/bin/java'}
    reads=[];tick_reads=[]
    def runner(argv,**kwargs):
        data=dict(prepared);reads.append(1)
        if (change.startswith('first') and len(reads)==1) or (change.startswith('second') and len(reads)==2):
            if change.endswith('pid'):data['MainPID']='312383'
            elif change.endswith('active'):data['ActiveState']='inactive'
            else:data['ExecMainStartTimestampMonotonic']='656005833130'
        return ''.join(key+'='+value+'\n' for key,value in data.items()).encode()
    def ticks(pid):
        tick_reads.append(pid)
        if pid==312467:return 65600590 if change=='java-tick' else 65600589
        return 65600583 if change=='main-tick' and len(tick_reads)>1 else 65600582
    monkeypatch.setattr(m,'_pid_start',ticks)
    monkeypatch.setattr(m,'_canonical_java_reference',lambda pid,uid:java)
    with pytest.raises(m.RecoveryRefused):m._capture_canonical_reference(prepared,999,runner=runner)


@pytest.mark.parametrize('change',['none','main-start','java-start','group'])
def test_canonical_runtime_recheck_preserves_exact_captured_identities(change,monkeypatch):
    from types import SimpleNamespace
    m=module();runtime=m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    runtime.canonical_pid=10;runtime.canonical_main_start_ticks=100
    runtime.canonical_java_pid=11;runtime.canonical_java_start_ticks=101
    runtime.canonical_exe='/usr/lib/jvm/java-21-openjdk-amd64/bin/java'
    runtime.forbidden_group_ids={10};runtime.canonical_service_metadata={}
    runtime.keycloak=SimpleNamespace(pw_uid=999);runtime.runner=lambda *args,**kwargs:None
    java={'pid':11,'start_ticks':102 if change=='java-start' else 101,'exe':runtime.canonical_exe}
    monkeypatch.setattr(m,'_capture_canonical_reference',lambda *args,**kwargs:(10,101 if change=='main-start' else 100,java))
    monkeypatch.setattr(m.os,'getpgid',lambda pid:99 if change=='group' else 10,raising=False)
    if change=='none':assert runtime.verify_canonical_reference() is None
    else:
        with pytest.raises(m.RecoveryRefused):runtime.verify_canonical_reference()


def rpc_operations_fixture(m):
    from types import SimpleNamespace
    operations=m.QualificationOperations.__new__(m.QualificationOperations)
    trace=[]
    def proof():trace.append('proof');return {'proof_generation':trace.count('proof')}
    operations.runtime=SimpleNamespace(proof=proof)
    operations.rpc_challenge_nonces=set();operations.rpc_challenged_events=set()
    return operations,trace


@pytest.mark.parametrize('event,reply',[('browser_start','browser_start_result'),('browser_positive','browser_positive_result'),
                                      ('purge_held','permit_purge'),('browser_negative','browser_negative_result')])
def test_sensitive_rpc_recomputes_proof_only_after_exact_challenge(event,reply,monkeypatch,capsys):
    m=module();ops,trace=rpc_operations_fixture(m)
    challenge={'op':'runtime_proof_challenge','event_op':event,'nonce':'a'*64}
    replies=iter([challenge,{'op':reply}])
    def read(deadline):trace.append('read');return next(replies)
    monkeypatch.setattr(m,'_read_rpc_json',read,raising=False)
    result=ops._rpc(event,reply)
    lines=[json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line['op'] for line in lines]==[event,'runtime_proof_response']
    assert lines[0]['runtime_proof']['proof_generation']==1
    assert lines[1]=={'op':'runtime_proof_response','event_op':event,'nonce':'a'*64,
                      'runtime_proof':{'proof_generation':2}}
    assert trace==['proof','read','proof','read','proof'] and result['op']==reply
    assert ops.rpc_challenge_nonces=={'a'*64}


@pytest.mark.parametrize('bad',['wrong-event','wrong-op','short-nonce','uppercase-nonce','extra-key','replayed-nonce','duplicate-challenge'])
def test_sensitive_rpc_refuses_invalid_or_replayed_challenges(bad,monkeypatch,capsys):
    m=module();ops,trace=rpc_operations_fixture(m)
    challenge={'op':'runtime_proof_challenge','event_op':'browser_negative','nonce':'a'*64}
    if bad=='wrong-event':challenge['event_op']='browser_positive'
    elif bad=='wrong-op':challenge['op']='browser_negative_result'
    elif bad=='short-nonce':challenge['nonce']='a'*63
    elif bad=='uppercase-nonce':challenge['nonce']='A'*64
    elif bad=='extra-key':challenge['token']='forbidden'
    elif bad=='replayed-nonce':ops.rpc_challenge_nonces.add('a'*64)
    replies=iter([challenge,dict(challenge)])
    monkeypatch.setattr(m,'_read_rpc_json',lambda deadline:next(replies),raising=False)
    with pytest.raises(m.RecoveryRefused):ops._rpc('browser_negative','browser_negative_result')
    lines=[json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(lines)==(2 if bad=='duplicate-challenge' else 1)


def test_sensitive_rpc_consumes_event_before_uncertain_challenge_outcome(monkeypatch,capsys):
    m=module();ops,trace=rpc_operations_fixture(m)
    monkeypatch.setattr(m,'_read_rpc_json',lambda deadline:{'op':'runtime_proof_challenge','event_op':'purge_held','nonce':'b'*64},raising=False)
    with pytest.raises(m.RecoveryRefused):ops._rpc('purge_held','permit_purge')
    before=capsys.readouterr().out
    with pytest.raises(m.RecoveryRefused):ops._rpc('purge_held','permit_purge')
    assert capsys.readouterr().out=='' and before


@pytest.mark.parametrize('failure',['expired-before-read','partial-line-deadline','oversized','duplicate-line','duplicate-key'])
def test_rpc_reader_bounds_partial_lines_deadlines_and_duplicate_messages(failure,monkeypatch):
    from types import SimpleNamespace
    m=module();monkeypatch.setattr(m.sys,'stdin',SimpleNamespace(fileno=lambda:42))
    chunks={'partial-line-deadline':[b'{'], 'oversized':[b'x'*65537],
            'duplicate-line':[b'{}\n{}\n'],'duplicate-key':[b'{"op":"a","op":"b"}\n']}.get(failure,[])
    moments=iter([0,0,2]) if failure=='partial-line-deadline' else None
    monkeypatch.setattr(m.time,'monotonic',lambda:next(moments,2) if moments is not None else 2 if failure=='expired-before-read' else 0)
    monkeypatch.setattr(m.select,'select',lambda *args:([42],[],[]))
    monkeypatch.setattr(m.os,'read',lambda fd,count:chunks.pop(0))
    with pytest.raises(m.RecoveryRefused):m._read_rpc_json(1)


def test_rpc_reader_accepts_one_fragmented_strict_json_line(monkeypatch):
    from types import SimpleNamespace
    m=module();chunks=iter([b'{"op":',b'"expected"}',b'\n'])
    monkeypatch.setattr(m.sys,'stdin',SimpleNamespace(fileno=lambda:42))
    monkeypatch.setattr(m.time,'monotonic',lambda:0)
    monkeypatch.setattr(m.select,'select',lambda *args:([42],[],[]))
    monkeypatch.setattr(m.os,'read',lambda *args:next(chunks))
    assert m._read_rpc_json(1)=={'op':'expected'}


@pytest.mark.parametrize('phase',['proof-recomputation','normal-reply'])
def test_sensitive_rpc_never_resets_deadline_after_challenge(phase,monkeypatch,capsys):
    from types import SimpleNamespace
    m=module();ops,trace=rpc_operations_fixture(m);clock=[0]
    def proof():
        trace.append('proof')
        if phase=='proof-recomputation' and trace.count('proof')==2:clock[0]=181
        return {'generation':trace.count('proof')}
    ops.runtime=SimpleNamespace(proof=proof)
    def read(deadline):
        assert deadline==180
        if trace.count('proof')==1:return {'op':'runtime_proof_challenge','event_op':'browser_start','nonce':'a'*64}
        clock[0]=181
        return {'op':'browser_start_result'}
    monkeypatch.setattr(m.time,'monotonic',lambda:clock[0])
    monkeypatch.setattr(m,'_read_rpc_json',read)
    with pytest.raises(m.RecoveryRefused,match='PrivateRpcReplyTimeout'):ops._rpc('browser_start','browser_start_result')
    lines=capsys.readouterr().out.splitlines()
    assert len(lines)==(1 if phase=='proof-recomputation' else 2)


@pytest.mark.parametrize('site',['common','private','tls'])
def test_owned_directory_sets_exact_group_mode_despite_umask077(site,monkeypatch):
    import stat
    from types import SimpleNamespace
    m=module();state={'mode':0o700,'gid':0};calls=[]
    path=Path('/protected')/site
    def metadata(child=True):return SimpleNamespace(st_mode=stat.S_IFDIR|(state['mode'] if child else 0o700),
        st_uid=0,st_gid=state['gid'] if child else 0,st_dev=1,st_ino=2 if child else 1)
    monkeypatch.setattr(m,'_physical_root_path',lambda *args,**kwargs:None)
    monkeypatch.setattr(m.os,'O_DIRECTORY',0x10000,raising=False);monkeypatch.setattr(m.os,'O_NOFOLLOW',0x20000,raising=False)
    monkeypatch.setattr(m.os,'open',lambda path,flags,**kwargs:11 if 'dir_fd' in kwargs else 10)
    monkeypatch.setattr(m.os,'fstat',lambda fd:metadata(fd==11))
    monkeypatch.setattr(m.os,'stat',lambda *args,**kwargs:metadata())
    def mkdir(name,mode,**kwargs):calls.append(('mkdir',name,mode));state['mode']=mode&~0o077
    monkeypatch.setattr(m.os,'mkdir',mkdir)
    def chown(fd,uid,gid):calls.append(('chown',fd,uid,gid));state['gid']=gid
    def chmod(fd,mode):calls.append(('chmod',fd,mode));state['mode']=mode
    monkeypatch.setattr(m.os,'fchown',chown,raising=False);monkeypatch.setattr(m.os,'fchmod',chmod,raising=False)
    monkeypatch.setattr(m.os,'close',lambda fd:None)
    assert m._create_owned_directory(path,group=988,mode=0o750)==path
    assert calls==[('mkdir',site,0o700),('chown',11,0,988),('chmod',11,0o750)]
    assert state=={'mode':0o750,'gid':988}


def test_owned_directory_refuses_preexisting_without_chown_or_chmod(monkeypatch):
    from types import SimpleNamespace
    import stat
    m=module();calls=[]
    monkeypatch.setattr(m,'_physical_root_path',lambda *args,**kwargs:None)
    monkeypatch.setattr(m.os,'O_DIRECTORY',0x10000,raising=False);monkeypatch.setattr(m.os,'O_NOFOLLOW',0x20000,raising=False)
    monkeypatch.setattr(m.os,'open',lambda *args,**kwargs:10)
    monkeypatch.setattr(m.os,'fstat',lambda fd:SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0))
    monkeypatch.setattr(m.os,'mkdir',lambda *args,**kwargs:(_ for _ in ()).throw(FileExistsError()))
    monkeypatch.setattr(m.os,'fchown',lambda *args:calls.append('chown'),raising=False)
    monkeypatch.setattr(m.os,'fchmod',lambda *args:calls.append('chmod'),raising=False)
    monkeypatch.setattr(m.os,'close',lambda fd:None)
    with pytest.raises(m.RecoveryRefused):m._create_owned_directory(Path('/protected/existing'),group=988,mode=0o750)
    assert calls==[]


@pytest.mark.skipif(__import__('sys').platform!='linux' or not hasattr(__import__('os'),'geteuid') or __import__('os').geteuid()!=0,
                    reason='Actual POSIX root-owned fd/umask proof requires separately authorized Linux execution')
def test_actual_posix_umask077_preserves_exact_three_directory_modes():
    import os,stat,tempfile
    m=module()
    with tempfile.TemporaryDirectory(prefix='keycloak-dir-mode-test-',dir='/root') as directory:
        old=os.umask(0o077)
        try:
            for site in ('common','private','tls'):
                path=Path(directory)/site;m._create_owned_directory(path,group=os.getegid(),mode=0o750)
                meta=path.stat();assert stat.S_IMODE(meta.st_mode)==0o750 and meta.st_uid==0 and meta.st_gid==os.getegid()
                path.rmdir()
        finally:os.umask(old)


def test_group_directory_policy_uses_one_exclusive_primitive_for_all_three_sites():
    import ast
    m=module();tree=ast.parse((ROOT/'tools/keycloak/recover_pilot_identity.py').read_text())
    klass=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='PrivateCandidateRuntime')
    method=next(n for n in klass.body if isinstance(n,ast.FunctionDef) and n.name=='copy_and_configure')
    targets=[ast.unparse(n.args[0]) for n in ast.walk(method) if isinstance(n,ast.Call) and
             isinstance(n.func,ast.Name) and n.func.id=='_create_owned_directory']
    assert sorted(targets)==['common','self.private','tls']


def test_attempt_journal_is_exclusive_sibling_of_immutable_stage1(monkeypatch):
    m=module();calls=[];candidate='keycloak_recovery_20261027_abcdef12'
    evidence=Path('/var/backups/keycloak-recovery')/candidate
    monkeypatch.setattr(m,'_physical_root_path',lambda *args,**kwargs:None)
    monkeypatch.setattr(m.secrets,'token_hex',lambda size:'a'*16)
    monkeypatch.setattr(m,'_create_owned_directory',lambda path,**kwargs:calls.append((path,kwargs)) or path,raising=False)
    result=m._create_qualification_journal(evidence,candidate)
    assert result==evidence.parent/(candidate+'-qualification-'+'a'*16)
    assert calls==[(result,{'group':0,'mode':0o700})] and result!=evidence


def test_primary_failure_is_retained_when_cleanup_changes_phase(monkeypatch):
    from types import SimpleNamespace
    m=module();ops=m.QualificationOperations.__new__(m.QualificationOperations)
    ops.phase='constructed';ops.failure_context=None;ops.cleanup_phase='NotAttempted';ops.cleanup_failure=None
    ops.verify=lambda:True
    ops.start=lambda:(_ for _ in ()).throw(m.RecoveryRefused('OwnedDirectoryCreationRefused'))
    ops.runtime=SimpleNamespace(stop=lambda:True,proof=lambda:True)
    for name in ('retention','identity','scopes','outbound','positive','purge','negative','poststop','final_inventory'):
        setattr(ops,name,lambda:True)
    with pytest.raises(m.RecoveryRefused):m.qualify_candidate(ops)
    assert ops.phase=='start_private_candidate_runtime'
    assert ops.failure_context=={'phase':'start_private_candidate_runtime','exception_class':'RecoveryRefused',
                                 'refusal_code':'OwnedDirectoryCreationRefused'}
    assert ops.cleanup_phase=='OwnedCandidateStopConfirmed'


def test_failure_diagnostics_never_emit_arbitrary_exception_args_or_refusal_strings():
    m=module();sentinel='secret-token-and-raw-response-must-not-escape'
    carrier=m.RecoveryCleanupFailure('PrivateBuildCleanupHold',ValueError(sentinel),ValueError(sentinel))
    carrier.args=(sentinel,)
    for error in [m.RecoveryRefused(sentinel),ValueError(sentinel),type('UnknownSecretError',(Exception,),{})(sentinel),carrier]:
        result=m._safe_error_metadata(error)
        assert sentinel not in json.dumps(result) and result['exception_class'] in {'RecoveryRefused','ValueError','UnexpectedError'}
        assert result['refusal_code'] in {None,'UnclassifiedRefusal'}


@pytest.mark.parametrize('change',['none','private','previous-private','common','process','row','oid','otp'])
def test_new_attempt_requires_pristine_database_otp_work_paths_and_no_private_process(change,monkeypatch):
    from types import SimpleNamespace
    m=module();runtime=m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    absent=lambda name:SimpleNamespace(exists=lambda:change==name,is_symlink=lambda:False)
    runtime.private=absent('private');runtime.private.parent=absent('common');runtime.previous_private=absent('previous-private')
    runtime.candidate='keycloak_recovery_20261027_abcdef12';runtime.baseline=snapshot();runtime.candidate_oid=12345
    runtime.identity={'user_id_sha256':m.ORIGINAL_SUBJECT_SHA256,'created_timestamp':1793048930752,
        'federation_link_sha256':m.FEDERATION_SHA256,'ldap_guid':m.PILOT_GUID,'ldap_id_count':1,
        'realm_user_count':1,'enabled':True,'credentials':[{'type':'otp','created_date':1793051223562,'row_sha256':digest('original')}]}
    runtime.runner=lambda *args,**kwargs:None;runtime.verify_canonical_reference=lambda:None
    fresh=copy.deepcopy(runtime.baseline);identity=copy.deepcopy(runtime.identity)
    if change=='row':fresh['tables']['server_config']=[digest('unreviewed')]
    if change=='oid':fresh['database_oid']=12346
    if change=='otp':identity['credentials'][0]['row_sha256']=digest('different')
    monkeypatch.setattr(m,'_private_candidate_processes',lambda candidate:[99] if change=='process' else [])
    monkeypatch.setattr(m,'collect_inventory',lambda *args,**kwargs:fresh)
    monkeypatch.setattr(m,'collect_identity',lambda *args,**kwargs:identity)
    if change=='none':assert runtime.verify_pristine_attempt() is None
    else:
        with pytest.raises(m.RecoveryRefused):runtime.verify_pristine_attempt()


def test_capacity_verifier_reads_immutable_stage1_context_not_attempt_journal(monkeypatch):
    from types import SimpleNamespace
    m=module();ops=m.QualificationOperations.__new__(m.QualificationOperations)
    root=Path('/var/backups/keycloak-recovery/keycloak_recovery_20261027_abcdef12')
    ops.runtime=SimpleNamespace(evidence_root=root,runner=lambda *args,**kwargs:b'12345')
    ops.receipts=root.parent/(root.name+'-qualification-'+'a'*16)
    class ContextReadReached(Exception):pass
    def read(path):assert path==root/'context.json';raise ContextReadReached
    monkeypatch.setattr(m,'_private_bytes',read)
    with pytest.raises(ContextReadReached):ops.verify()


@pytest.mark.parametrize('mismatch',['foreign-owner','symlink','before-inode','after-inode'])
def test_owned_directory_refuses_unexpected_inode_or_owner(mismatch,monkeypatch):
    import stat
    from types import SimpleNamespace
    m=module();calls=[];named_reads=[]
    def child(ino=2):return SimpleNamespace(st_mode=(stat.S_IFLNK if mismatch=='symlink' else stat.S_IFDIR)|0o700,
        st_uid=999 if mismatch=='foreign-owner' else 0,st_gid=0,st_dev=1,st_ino=ino)
    monkeypatch.setattr(m,'_physical_root_path',lambda *args,**kwargs:None)
    monkeypatch.setattr(m.os,'O_DIRECTORY',0x10000,raising=False);monkeypatch.setattr(m.os,'O_NOFOLLOW',0x20000,raising=False)
    monkeypatch.setattr(m.os,'open',lambda path,flags,**kwargs:11 if 'dir_fd' in kwargs else 10)
    monkeypatch.setattr(m.os,'fstat',lambda fd:child() if fd==11 else SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0))
    def named(*args,**kwargs):
        named_reads.append(1)
        return child(3 if mismatch=='before-inode' or mismatch=='after-inode' and len(named_reads)>1 else 2)
    monkeypatch.setattr(m.os,'stat',named);monkeypatch.setattr(m.os,'mkdir',lambda *args,**kwargs:None)
    monkeypatch.setattr(m.os,'fchown',lambda *args:calls.append('chown'),raising=False)
    monkeypatch.setattr(m.os,'fchmod',lambda *args:calls.append('chmod'),raising=False)
    monkeypatch.setattr(m.os,'close',lambda fd:None)
    with pytest.raises(m.RecoveryRefused):m._create_owned_directory(Path('/protected/new'),group=0,mode=0o700)
    assert calls==(['chown','chmod'] if mismatch=='after-inode' else [])


def test_cleanup_failure_preserves_primary_operation_and_excludes_raw_cleanup_args():
    from types import SimpleNamespace
    m=module();ops=m.QualificationOperations.__new__(m.QualificationOperations)
    ops.phase='constructed';ops.failure_context=None;ops.cleanup_phase='NotAttempted';ops.cleanup_failure=None
    ops.verify=lambda:True;ops.start=lambda:(_ for _ in ()).throw(m.RecoveryRefused('PrivateCommandFailed'))
    ops.runtime=SimpleNamespace(stop=lambda:(_ for _ in ()).throw(ValueError('never-emit-cleanup-raw-secret')),proof=lambda:True)
    for name in ('retention','identity','scopes','outbound','positive','purge','negative','poststop','final_inventory'):
        setattr(ops,name,lambda:True)
    with pytest.raises(ValueError):m.qualify_candidate(ops)
    assert ops.failure_context=={'phase':'start_private_candidate_runtime','exception_class':'RecoveryRefused',
                                 'refusal_code':'PrivateCommandFailed'}
    assert ops.cleanup_phase=='CleanupUnconfirmed' and ops.cleanup_failure=={'exception_class':'ValueError','refusal_code':None}
    assert 'never-emit' not in json.dumps([ops.failure_context,ops.cleanup_failure])


def test_actual_runtime_start_cleanup_failure_preserves_readiness_primary():
    m=module();runtime=m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    runtime._start_owned=lambda:(_ for _ in ()).throw(m.RecoveryRefused('PrivateRuntimeReadinessTimeout'))
    runtime.stop=lambda:(_ for _ in ()).throw(ValueError('raw-cleanup-secret'))
    ops=m.QualificationOperations.__new__(m.QualificationOperations)
    ops.phase='constructed';ops.failure_context=None;ops.cleanup_phase='NotAttempted';ops.cleanup_failure=None
    ops.verify=lambda:True;ops.start=runtime.start;ops.runtime=runtime;runtime.proof=lambda:True
    for name in ('retention','identity','scopes','outbound','positive','purge','negative','poststop','final_inventory'):
        setattr(ops,name,lambda:True)
    with pytest.raises(Exception):m.qualify_candidate(ops)
    assert ops.failure_context=={'phase':'start_private_candidate_runtime','exception_class':'RecoveryRefused',
                                 'refusal_code':'PrivateRuntimeReadinessTimeout'}
    assert ops.cleanup_phase=='CleanupUnconfirmed' and ops.cleanup_failure=={'exception_class':'ValueError','refusal_code':None}
    assert 'raw-cleanup-secret' not in json.dumps([ops.failure_context,ops.cleanup_failure])


def test_actual_owned_build_cleanup_failure_preserves_original_timeout_metadata(monkeypatch):
    import io
    from types import SimpleNamespace
    m=module()
    process=SimpleNamespace(pid=40,poll=lambda:None,
        communicate=lambda **kwargs:(_ for _ in ()).throw(m.subprocess.TimeoutExpired('raw-argv-secret',1)))
    monkeypatch.setattr(m.subprocess,'Popen',lambda *args,**kwargs:process)
    monkeypatch.setattr(m,'_pid_start',lambda pid:123)
    monkeypatch.setattr(m,'_stop_owned_build_group',lambda *args:(_ for _ in ()).throw(ValueError('raw-cleanup-secret')))
    with pytest.raises(m.RecoveryRefused) as caught:
        m._run_owned_private_group(['build'],input_bytes=None,output=io.BytesIO(),timeout=1,cwd=None,environment={},
            prefix='/var/lib/keycloak-recovery-v7/keycloak_recovery_20261027_abcdef12',forbidden={90})
    assert caught.value.primary_metadata=={'exception_class':'TimeoutExpired','refusal_code':None}
    assert caught.value.cleanup_metadata=={'exception_class':'ValueError','refusal_code':None}
    assert caught.value.args==('PrivateBuildCleanupHold',)
    assert 'raw-' not in json.dumps([caught.value.primary_metadata,caught.value.cleanup_metadata])


def reachable_startup_refusal_codes():
    """Static committed-code reachability plus explicit dynamic runner boundary."""
    import ast
    tree=ast.parse((ROOT/'tools/keycloak/recover_pilot_identity.py').read_text())
    functions={};classes={}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):functions[node.name]=(node,None)
        elif isinstance(node,ast.ClassDef):
            classes[node.name]=node
            for method in node.body:
                if isinstance(method,ast.FunctionDef):functions[node.name+'.'+method.name]=(method,node.name)
    pending=['PrivateCandidateRuntime._start_owned','PrivateCandidateRuntime.proof','PrivateCandidateRuntime.stop',
             'PrivateCandidateRuntime.verify_canonical_reference','PrivateCandidateRuntime.verify_pristine_attempt',
             'validate_runtime_proof','_pid_start','_run_private']
    visited=set();codes=set()
    while pending:
        key=pending.pop()
        if key in visited:continue
        visited.add(key);node,owner=functions[key]
        for call in (x for x in ast.walk(node) if isinstance(x,ast.Call)):
            if isinstance(call.func,ast.Name):
                name=call.func.id
                index=1 if name=='require' else 0 if name in {'RecoveryRefused','RecoveryCleanupFailure'} else None
                if index is not None and len(call.args)>index and isinstance(call.args[index],ast.Constant) and type(call.args[index].value) is str:
                    codes.add(call.args[index].value)
                if name in functions:pending.append(name)
                elif name in classes and name+'.__init__' in functions:pending.append(name+'.__init__')
            elif isinstance(call.func,ast.Attribute) and owner is not None and isinstance(call.func.value,ast.Name) and call.func.value.id=='self':
                target=owner+'.'+call.func.attr
                if target in functions:pending.append(target)
    return codes,visited


def test_every_fixed_reachable_startup_refusal_preserves_exact_safe_diagnostic():
    import re
    m=module();codes,visited=reachable_startup_refusal_codes()
    assert {'PrivateCandidateRuntime.proof','_capture_canonical_reference','_canonical_java_reference',
            '_pid_start','_owned_build_members','distribution_inventory','validate_outbound_metadata','_exact_loopback_port'}<=visited
    assert 'ProcessIdentityUnavailable' in codes
    assert all(re.fullmatch('[A-Z][A-Za-z0-9]{1,99}',code) for code in codes)
    assert codes<=m.SAFE_REFUSAL_CODES, 'Missing fixed safe diagnostic codes: '+','.join(sorted(codes-m.SAFE_REFUSAL_CODES))
    for code in sorted(codes):
        assert m._safe_error_metadata(m.RecoveryRefused(code))=={'exception_class':'RecoveryRefused','refusal_code':code}


@pytest.mark.parametrize('endpoint',['127.0.0.1:8089','[::ffff:127.0.0.1]:8089','[::ffff:7f00:1]:8089',
                                    '[0:0:0:0:0:ffff:7f00:1]:8089'])
def test_exact_fixed_loopback_endpoint_accepts_only_same_ip_semantics(endpoint):
    m=module();assert m._exact_loopback_port(endpoint,8089)==8089


@pytest.mark.parametrize('endpoint',['[::1]:8089','0.0.0.0:8089','*:8089','[::]:8089','127.0.0.2:8089',
    '[::ffff:127.0.0.2]:8089','[::ffff:0.0.0.0]:8089','192.0.2.1:8089','localhost:8089',
    '[::ffff:127.0.0.1%lo]:8089','::ffff:127.0.0.1:8089','[127.0.0.1]:8089','127.0.0.1:http',
    '127.0.0.1:0','127.0.0.1:65536','127.0.0.1:08089','127.0.0.1:8090','[::ffff:127.0.0.1]:8090',
    ' 127.0.0.1:8089','127.0.0.1:8089\n','[::ffff:127.0.0.1]:8089extra','127.000.0.1:8089'])
def test_exact_fixed_loopback_endpoint_refuses_other_addresses_or_ambiguous_grammar(endpoint):
    assert module()._exact_loopback_port(endpoint,8089) is None


def native_mapped_runtime_fixture(m,monkeypatch,tmp_path):
    import stat
    from types import SimpleNamespace
    runtime=m.PrivateCandidateRuntime.__new__(m.PrivateCandidateRuntime)
    runtime.candidate='keycloak_recovery_20261027_abcdef12';runtime.candidate_oid=20856
    runtime.process=SimpleNamespace(pid=40,poll=lambda:None);runtime.process_start=100;runtime.canonical_pid=90
    runtime.keycloak=SimpleNamespace(pw_uid=999);runtime.canonical_exe='/usr/lib/jvm/java-21-openjdk-amd64/bin/java'
    runtime.java_pid=None;runtime.java_start_ticks=None;runtime._owned_group=lambda:state['group_members']
    runtime.private=tmp_path;runtime.receipts=tmp_path/'receipts';runtime.distribution=tmp_path/'distribution'
    (tmp_path/'candidate.conf').write_bytes(b'configuration')
    runtime.config_sha256=hashlib.sha256(b'configuration').hexdigest();runtime.tls_verified=True
    for name in ('data','work','tmp'):setattr(runtime,name,SimpleNamespace(lstat=lambda:SimpleNamespace(st_mode=stat.S_IFDIR|state['mutable_mode'],st_uid=999)))
    runtime.expected_tree={'sha256':digest('tree'),'binary_files':505,'custom_provider_artifact_count':0}
    runtime.outbound={'safe':True};runtime.build_recipe_sha256=digest('recipe')
    # Exact safe host token was observed on canonical Java listeners and BOTH
    # JDBC sides. Private ports/PIDs and source ephemeral ports are fixtures.
    listeners=[f'LISTEN 0 4096 [::ffff:127.0.0.1]:{port} *:* users:(("java",pid=41,fd=10))' for port in (8089,9009,8449)]
    connections=[f'ESTAB 0 0 [::ffff:127.0.0.1]:{port} [::ffff:127.0.0.1]:5544 users:(("java",pid=41,fd=11))' for port in (50001,50002)]
    state={'listeners':listeners,'connections':connections,'db_ports':[50001,50002],'udp':b'',
           'java_uid':999,'group_members':[40,41],'exe':runtime.canonical_exe,'mutable_mode':0o700,
           'nginx':b'http { server { listen 443; } }','tree':runtime.expected_tree,'outbound':runtime.outbound,'writes':[],'ss_calls':[]}
    def runner(argv,**kwargs):
        if argv[0]=='ss':state['ss_calls'].append(list(argv))
        if argv==['ss','-Hltnp']:return '\n'.join(state['listeners']).encode()
        if argv==['ss','-Hlunp']:return state['udp']
        if argv==['ss','-Hntp']:return '\n'.join(state['connections']).encode()
        if argv==['nginx','-T']:return state['nginx']
        assert '--dbname' in argv
        return json.dumps({'oid':20856,'owner':'keycloak','ports':state['db_ports']}).encode()
    runtime.runner=runner
    actual_path=m.Path
    monkeypatch.setattr(m,'Path',lambda value:SimpleNamespace(stat=lambda:SimpleNamespace(st_uid=state['java_uid']))
                        if str(value).startswith('/proc/') else actual_path(value))
    monkeypatch.setattr(m,'_physical_root_path',lambda *args,**kwargs:None)
    monkeypatch.setattr(m,'_pid_start',lambda pid:100 if pid==40 else 200)
    monkeypatch.setattr(m.os,'readlink',lambda path:state['exe'])
    monkeypatch.setattr(m.os,'getpgid',lambda pid:40,raising=False)
    monkeypatch.setattr(m,'distribution_inventory',lambda *args,**kwargs:state['tree'])
    monkeypatch.setattr(m,'collect_outbound_safety',lambda *args,**kwargs:state['outbound'])
    monkeypatch.setattr(m,'_write_private',lambda path,value:state['writes'].append((path,value)))
    return runtime,state


@pytest.mark.parametrize('format',['mapped','plain','mapped-hex'])
def test_full_runtime_proof_accepts_observed_native_mapped_grammar_and_keeps_canonical35fields(format,monkeypatch,tmp_path):
    m=module();runtime,state=native_mapped_runtime_fixture(m,monkeypatch,tmp_path)
    if format!='mapped':
        token='127.0.0.1' if format=='plain' else '[::ffff:7f00:1]'
        for key in ('listeners','connections'):state[key]=[line.replace('[::ffff:127.0.0.1]',token) for line in state[key]]
    proof=runtime.proof()
    assert len(proof)==35 and proof['http_listener']=='127.0.0.1:8089'
    assert proof['management_listener']=='127.0.0.1:9009' and proof['https_listener']=='127.0.0.1:8449'
    assert proof['jdbc_client_ports']==[50001,50002] and proof['socket_pids']==[41]


@pytest.mark.parametrize('change,code',[('duplicate','PrivateRuntimeListenerNotLoopback'),('wildcard','PrivateRuntimeListenerNotLoopback'),
    ('other-loopback','PrivateRuntimeListenerNotLoopback'),('foreign-pid','PrivateRuntimeSocketPidMismatch'),
    ('foreign-uid','PrivateRuntimeJavaIdentityMismatch'),('foreign-group','PrivateRuntimeJavaIdentityMismatch'),
    ('foreign-exe','PrivateRuntimeJavaIdentityMismatch'),('jdbc-source','PrivateRuntimeJdbcSourceNotLoopback'),
    ('jdbc-peer','PrivateRuntimeJdbcDatabaseMismatch'),('jdbc-set','PrivateRuntimeJdbcDatabaseMismatch'),
    ('udp','PrivateRuntimeUnexpectedUdpSocket'),('mutable','PrivateMutableDirectoryMismatch'),
    ('distribution','PrivateRuntimeDistributionChanged'),('outbound','PrivateRuntimeOutboundMetadataChanged'),
    ('nginx','PrivateRuntimeProxyExposurePossible'),('tls','PrivateRuntimeTlsProofMissing')])
def test_full_mapped_runtime_proof_preserves_other_isolation_and_jdbc_guards(change,code,monkeypatch,tmp_path):
    m=module();runtime,state=native_mapped_runtime_fixture(m,monkeypatch,tmp_path)
    if change=='duplicate':state['listeners'].append(state['listeners'][0])
    elif change=='wildcard':state['listeners'][0]=state['listeners'][0].replace('[::ffff:127.0.0.1]','[::]')
    elif change=='other-loopback':state['listeners'][0]=state['listeners'][0].replace('127.0.0.1','127.0.0.2')
    elif change=='foreign-pid':state['listeners'][0]=state['listeners'][0].replace('pid=41','pid=52')
    elif change=='foreign-uid':state['java_uid']=998
    elif change=='foreign-group':state['group_members']=[40]
    elif change=='foreign-exe':state['exe']='/usr/bin/foreign-java'
    elif change=='jdbc-source':state['connections'][0]=state['connections'][0].replace('[::ffff:127.0.0.1]:50001','[::1]:50001')
    elif change=='jdbc-peer':state['connections'][0]=state['connections'][0].replace('[::ffff:127.0.0.1]:5544','[::1]:5544')
    elif change=='jdbc-set':state['db_ports']=[50001]
    elif change=='udp':state['udp']=b'UNCONN 0 0 127.0.0.1:12345 *:* users:(("java",pid=41,fd=12))'
    elif change=='mutable':state['mutable_mode']=0o755
    elif change=='distribution':state['tree']=dict(runtime.expected_tree,sha256=digest('changed'))
    elif change=='outbound':state['outbound']={'safe':False}
    elif change=='nginx':state['nginx']=b'proxy_pass http://127.0.0.1:8089;'
    else:runtime.tls_verified=False
    with pytest.raises(m.RecoveryRefused,match='^'+code+'$'):runtime.proof()


@pytest.mark.parametrize('port',[1,50001,65535])
def test_jdbc_source_port_parser_remains_numeric_bounded_and_exact_loopback(port):
    m=module()
    assert m._exact_loopback_port('[::ffff:127.0.0.1]:'+str(port))==port
    assert m._exact_loopback_port('127.0.0.1:'+str(port))==port


@pytest.mark.parametrize('failure,code',[('tcp','PrivateRuntimeUnexpectedTcpListener'),('udp','PrivateRuntimeUnexpectedUdpSocket'),
                                      ('both','PrivateRuntimeUnexpectedTcpListener')])
def test_network_refusal_distinguishes_tcp_udp_and_records_both_once(failure,code,monkeypatch,tmp_path):
    m=module();runtime,state=native_mapped_runtime_fixture(m,monkeypatch,tmp_path)
    if failure in {'tcp','both'}:state['listeners'].append('LISTEN 0 4096 [::ffff:127.0.0.1]:43210 *:* users:(("java",pid=41,fd=99))')
    if failure in {'udp','both'}:state['udp']=b'UNCONN 0 0 127.0.0.1:12345 *:* users:(("java",pid=41,fd=12))'
    with pytest.raises(m.RecoveryRefused,match='^'+code+'$'):runtime.proof()
    assert len(state['writes'])==1
    path,witness=state['writes'][0]
    assert path==runtime.receipts/'private-runtime-network-refusal.json'
    assert witness['tcp_listener_count']==(4 if failure in {'tcp','both'} else 3)
    assert witness['udp_listener_count']==(1 if failure in {'udp','both'} else 0)
    assert witness['tcp_ports']==([8089,8449,9009,43210] if failure in {'tcp','both'} else [8089,8449,9009])
    assert witness['udp_ports']==([12345] if failure in {'udp','both'} else [])
    assert witness['pid']==41 and witness['start_ticks']==200 and len(witness['source_sha256'])==64
    assert state['ss_calls'].count(['ss','-Hltnp'])==1 and state['ss_calls'].count(['ss','-Hlunp'])==1
    assert ['ss','-Hntp'] not in state['ss_calls']


def test_passing_socket_proof_never_writes_refusal_receipt(monkeypatch,tmp_path):
    m=module();runtime,state=native_mapped_runtime_fixture(m,monkeypatch,tmp_path)
    runtime.proof();assert state['writes']==[]


def test_network_refusal_witness_bounds_ports_and_never_emits_raw_endpoints_or_args(monkeypatch,tmp_path):
    m=module();runtime,state=native_mapped_runtime_fixture(m,monkeypatch,tmp_path)
    state['listeners'] += [f'LISTEN 0 4096 private-secret-host.invalid:{10000+i} *:* users:(("secret-argv",pid=41,fd=99))' for i in range(100)]
    with pytest.raises(m.RecoveryRefused,match='PrivateRuntimeUnexpectedTcpListener'):runtime.proof()
    witness=state['writes'][0][1];serialized=json.dumps(witness)
    assert witness['tcp_listener_count']==103 and len(witness['tcp_ports'])==64 and witness['port_lists_truncated'] is True
    assert witness['tcp_endpoint_classes']['unparseable']==100
    assert 'secret' not in serialized and '127.0.0.1' not in serialized and 'fd=99' not in serialized
    assert all(type(port) is int and 1<=port<=65535 for port in witness['tcp_ports'])


def test_refusal_receipt_write_failure_stops_owned_runtime_and_does_not_continue(monkeypatch,tmp_path):
    m=module();runtime,state=native_mapped_runtime_fixture(m,monkeypatch,tmp_path)
    state['udp']=b'UNCONN 0 0 127.0.0.1:12345 *:* users:(("java",pid=41,fd=12))'
    def fail_write(*args):raise m.RecoveryRefused('PrivateReceiptWriteFailed')
    monkeypatch.setattr(m,'_write_private',fail_write)
    stopped=[];runtime._start_owned=runtime.proof;runtime.stop=lambda:stopped.append('owned-stop')
    with pytest.raises(m.RecoveryRefused,match='PrivateReceiptWriteFailed'):runtime.start()
    assert stopped==['owned-stop'] and runtime.java_pid is None


def test_private_runtime_selects_supported_socket_free_process_id_only_without_changing_transactions():
    m=module();candidate='keycloak_recovery_20261027_abcdef12'
    flag='-Dcom.arjuna.ats.internal.arjuna.utils.processImplementation=com.arjuna.ats.internal.arjuna.utils.MBeanProcessId'
    recipe=m.runtime_recipe(candidate,browser_tls=True)
    java_options=[item for item in recipe['argv'] if item.startswith('JAVA_OPTS_APPEND=')]
    assert len(java_options)==1 and java_options[0].split().count(flag)==1
    assert flag not in ' '.join(m.private_build_recipe(candidate)['argv'])
    assert 'processImplementation' not in (ROOT/'deploy/keycloak/keycloak.conf').read_text()
    assert 'processImplementation' not in (ROOT/'tools/keycloak/install.sh').read_text()
    assert 'JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m' in recipe['argv'] and recipe['cache']=='local'
    assert '--optimized' in recipe['argv'] and not any('transaction' in arg.lower() or 'recoveryenabled' in arg.lower() for arg in recipe['argv'])
