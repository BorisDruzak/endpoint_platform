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
    assert command[-3].startswith("--config-file=/var/lib/keycloak-recovery/")
    assert command[-4].startswith("/var/lib/keycloak-recovery/")
    assert not any("/opt/keycloak" in arg for arg in command)
    assert any("JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m" == arg for arg in command)
    assert any('-Duser.home=/var/lib/keycloak-recovery/keycloak_recovery_20261027_abcdef12/work' in arg for arg in command)
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
    assert values["https-certificate-key-file"] == "/var/lib/keycloak-recovery/" + candidate + "/tls/key.pem"
    assert values["https-certificate-file"] == "/var/lib/keycloak-recovery/" + candidate + "/tls/fullchain.pem"
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
    runtime.private = Path('/var/lib/keycloak-recovery/keycloak_recovery_20261027_abcdef12')
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
    assert any(arg.startswith('HOME=/var/lib/keycloak-recovery/') for arg in recipe['argv'])
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
        cwd=None,environment={},prefix='/var/lib/keycloak-recovery/keycloak_recovery_20261027_abcdef12',forbidden={90,91})
    if scenario=='timeout':
        with pytest.raises(m.subprocess.TimeoutExpired):invoke()
    else:invoke()
    assert signals==[(40,m.signal.SIGTERM)] and not state['members']
