from pathlib import Path
import subprocess


def bash():
    path = Path("C:/Program Files/Git/bin/bash.exe")
    return str(path) if path.exists() else "bash"


def test_installer_preserves_public_archive_modes_and_uses_intended_user_gate():
    install = Path("tools/keycloak/install.sh").read_text(encoding="utf-8")
    extraction = next(line for line in install.splitlines() if line.startswith("tar -xzf "))
    assert "--same-permissions" in extraction
    build = install.index("/opt/keycloak/current/bin/kc.sh build")
    assert "umask 022" in install[build - 60:build]
    gate = "runuser -u keycloak -- /opt/keycloak/current/bin/kc.sh --version"
    assert gate in install
    assert build < install.index(gate) < install.index("systemctl daemon-reload")


def test_recovery_is_opt_in_pinned_and_does_not_touch_configuration_or_data():
    repair = Path("tools/keycloak/repair_distribution_permissions.sh").read_text(encoding="utf-8")
    assert "--apply" in repair
    assert "expected_version=26.8.1" in repair
    assert "4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8" in repair
    assert "sha256sum --check --status" in repair
    assert 'readlink "$release_dir/data"' in repair
    assert "find -P" in repair
    assert "chmod a+rX" in repair
    assert "chmod -R" not in repair
    assert "chown" not in repair
    assert "systemctl start" not in repair
    assert "systemctl restart" not in repair
    assert "pg_" not in repair
    assert "psql" not in repair
    assert "/etc/keycloak" not in repair
    assert "runuser -u keycloak -- /opt/keycloak/current/bin/kc.sh --version" in repair


def test_recovery_shell_parses_without_execution():
    subprocess.run([bash(), "-n", "tools/keycloak/repair_distribution_permissions.sh"], check=True, capture_output=True)


def test_installer_actual_service_identity_gate_stops_on_permission_denial():
    install = Path("tools/keycloak/install.sh").read_text(encoding="utf-8")
    gate = next(line for line in install.splitlines() if line.startswith("runuser -u keycloak -- /opt/keycloak/current/bin/kc.sh --version"))
    # Execute the actual installer gate with a blocked/successful service-user
    # command. This ensures a root-only distribution cannot reach completion.
    for status in (126, 0):
        script = f"""set -euo pipefail
runuser() {{
  [[ "$*" == '-u keycloak -- /opt/keycloak/current/bin/kc.sh --version' ]] || return 99
  return {status}
}}
{gate}
printf 'completed\\n'
"""
        result = subprocess.run([bash(), "-s"], input=script, capture_output=True, text=True)
        assert result.returncode == status
        assert ("completed" in result.stdout) == (status == 0)
