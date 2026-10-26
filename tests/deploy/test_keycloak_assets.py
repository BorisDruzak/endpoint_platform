from pathlib import Path
import json
import subprocess
import shlex

from datetime import UTC, datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def test_installer_tls_preflight_rejects_a_trusted_wrong_hostname(tmp_path):
    """Use the actual installer's verify command with real signed certificates."""
    openssl = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    executable = str(openssl) if openssl.exists() else "openssl"
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test CA")])
    ca = x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256())
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    install = Path("tools/keycloak/install.sh").read_text(encoding="utf-8")
    # Extract the executed gate, rather than testing a separately invented command.
    line = next(line for line in install.splitlines() if line.startswith("openssl verify "))
    args = shlex.split(line.split(">", 1)[0])
    for hostname, expected_ok in (("unrelated.example", False), ("sso.sosnadmin.local", True)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_key, hashes.SHA256())
        cert_path = tmp_path / f"{hostname}.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        substitutions = {"$ldap_ca": str(ca_path), "$tls_cert": str(cert_path)}
        command = [executable] + [substitutions.get(arg, arg) for arg in args[1:]]
        result = subprocess.run(command, capture_output=True)
        assert (result.returncode == 0) == expected_ok, (hostname, result.stdout, result.stderr)


def test_distribution_is_pinned_and_runtime_is_isolated():
    release = json.loads(Path("deploy/keycloak/release.json").read_text(encoding="utf-8"))
    assert release["version"] == "26.8.1"
    assert len(release["sha256"]) == 64
    config = Path("deploy/keycloak/keycloak.conf").read_text(encoding="utf-8")
    assert "jdbc:postgresql://127.0.0.1:5544/keycloak" in config
    assert "http-host=127.0.0.1" in config
    assert "http-management-host=127.0.0.1" in config
    assert "http-port=8088" in config
    assert "truststore-paths=/etc/keycloak/trust" in config
    assert "hostname=https://sso.sosnadmin.local" in config
    unit = Path("deploy/keycloak/keycloak.service").read_text(encoding="utf-8")
    assert "User=keycloak" in unit
    assert "ReadWritePaths=/var/lib/keycloak" in unit
    assert "ProtectSystem=strict" in unit


def test_proxy_does_not_publish_admin_or_health_and_replaces_headers():
    config = Path("deploy/keycloak/keycloak.nginx.conf").read_text(encoding="utf-8")
    assert "location /admin/ { deny all; }" in config
    assert "location /realms/master/ { deny all; }" in config
    assert "9008" not in config
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in config
    assert 'proxy_set_header Forwarded "";' in config
    assert "access_log off;" in config


def test_install_and_backup_keep_secret_and_database_boundaries():
    install = Path("tools/keycloak/install.sh").read_text(encoding="utf-8")
    assert "--auth-host=scram-sha-256" in install
    assert 'pg_conftool 16 keycloak set listen_addresses "\'127.0.0.1\'"' in install
    assert '--resume-before-database' in install
    assert 'pg_conftool -s 16 keycloak show port' in install
    assert "Unexpected existing application role" in install
    assert "--verify" not in install  # No permissive custom TLS flags.
    assert "-verify_hostname AD-MAIN.sosnadmin.local" in install
    assert "-verify_return_error" in install
    assert "sha256sum --check --status" in install
    assert "systemctl start keycloak" not in install
    assert "systemctl restart" not in install
    assert "db-password=%s" in install
    backup = Path("tools/keycloak/backup.sh").read_text(encoding="utf-8")
    assert "pg_dump -p 5544 -Fc keycloak" in backup
    assert backup.index("config.tar.gz") < backup.index('touch "$backup_dir/COMPLETE"')
    assert "umask 077" in backup


def test_shell_assets_parse_without_execution():
    bash = Path("C:/Program Files/Git/bin/bash.exe")
    command = str(bash) if bash.exists() else "bash"
    for script in ("tools/keycloak/install.sh", "tools/keycloak/backup.sh", "tools/keycloak/sign_dc_certificate.sh"):
        subprocess.run([command, "-n", script], check=True, capture_output=True)
