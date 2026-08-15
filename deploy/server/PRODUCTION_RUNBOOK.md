# Endpoint Platform Production Runbook

Run this procedure from the operator workstation after a clean, verified commit.
It intentionally does not place the CA, leaf certificate, or private key in the
repository or workspace.

## 1. Local release gate and archive

Verify that the tree is clean and record the commit:

```powershell
git status --short
git rev-parse HEAD
python -m pytest tests -q
python tools/contracts/generate_contract_artifacts.py --check
python -m alembic upgrade head --sql
```

Create a temporary archive containing only the server runtime. It has no Git
metadata, environment file, certificate, or secret. Do not upload it until the
production preflight in the next section succeeds:

```powershell
$releaseCommit = git rev-parse --short=12 HEAD
$releaseArchive = Join-Path $env:TEMP "endpoint-platform-$releaseCommit.tar.gz"
git archive --format=tar.gz --output="$releaseArchive" --prefix="endpoint-platform-$releaseCommit/" HEAD endpoint_server endpoint_contracts alembic.ini requirements-server.txt
```

## 2. Re-check production conditions

Immediately before mutation, the following must show at least 10 GiB available,
free ports 80/443/8000, and the expected DNS address:

```powershell
ssh endpoint-platform-server "df -h /; ss -ltn '( sport = :80 or sport = :443 or sport = :8000 )'"
Resolve-DnsName endpoint.sosnadmin.local -Type A
```

Abort if `endpoint.sosnadmin.local` does not resolve to `192.168.100.19`.

## 3. Install operating-system components and local database

On the production host, install only the required packages and create the
non-login service user and private directories:

```bash
sudo apt-get update
sudo apt-get install -y postgresql postgresql-client nginx python3.12-venv python3-pip
sudo systemctl disable --now nginx
sudo rm -f /etc/nginx/sites-enabled/default
sudo adduser --system --group --home /var/lib/endpoint-platform --shell /usr/sbin/nologin endpoint-platform
sudo install -d -o root -g root -m 0755 /opt/endpoint-platform/releases /etc/endpoint-platform
sudo install -d -o endpoint-platform -g endpoint-platform -m 0750 /var/lib/endpoint-platform/artifacts
sudo install -d -o root -g endpoint-platform -m 0710 /etc/endpoint-platform/secrets
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET listen_addresses = '127.0.0.1,::1'"
sudo systemctl restart postgresql
sudo -u postgres psql -Atqc "SHOW listen_addresses"
sudo ss -ltnp | grep postgres
```

Create the root-owned `0600` environment file and three independent regular
secret files in one root shell. `db_password` remains in that shell and none of
these commands prints it:

```bash
sudo bash -s <<'SCRIPT'
set -euo pipefail
db_password="$(openssl rand -hex 32)"
if ! sudo -u postgres psql -Atqc "SELECT 1 FROM pg_roles WHERE rolname = 'endpoint_platform'" | grep -qx 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_password="$db_password" -c "CREATE ROLE endpoint_platform LOGIN PASSWORD :'db_password'"
else
  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_password="$db_password" -c "ALTER ROLE endpoint_platform LOGIN PASSWORD :'db_password'"
fi
if ! sudo -u postgres psql -Atqc "SELECT 1 FROM pg_database WHERE datname = 'endpoint_platform'" | grep -qx 1; then
  sudo -u postgres createdb -O endpoint_platform endpoint_platform
fi
printf '%s\n' \
  "DATABASE_URL=postgresql+asyncpg://endpoint_platform:${db_password}@127.0.0.1:5432/endpoint_platform" \
  'PUBLIC_BASE_URL=https://endpoint.sosnadmin.local' \
  'DEVICE_TOKEN_PEPPER_FILE=/etc/endpoint-platform/secrets/device-token-pepper' \
  'SERVICE_TOKEN_PEPPER_FILE=/etc/endpoint-platform/secrets/service-token-pepper' \
  'SESSION_SECRET_FILE=/etc/endpoint-platform/secrets/session-secret' \
  'ALLOWED_AGENT_CIDRS=192.168.100.0/24,192.168.101.0/24' \
  'ALLOWED_ADMIN_CIDRS=192.168.100.0/24,192.168.101.0/24' \
  'TRUSTED_PROXY_CIDRS=127.0.0.1/32' \
  'ARTIFACT_ROOT=/var/lib/endpoint-platform/artifacts' |
  install -o root -g root -m 0600 /dev/stdin /etc/endpoint-platform/endpoint-platform.env
for secret_name in device-token-pepper service-token-pepper session-secret; do
  openssl rand -hex 48 | install -o endpoint-platform -g endpoint-platform -m 0600 /dev/stdin "/etc/endpoint-platform/secrets/${secret_name}"
done
SCRIPT
```

Never use symlinks for the environment or secret files.

## 4. Install release and service assets

Extract the uploaded archive to its immutable versioned directory and create
the virtual environment:

```powershell
scp $releaseArchive endpoint-platform-server:/tmp/
ssh endpoint-platform-server "printf '%s\n' '$releaseCommit' | sudo install -o root -g root -m 0644 /dev/stdin /etc/endpoint-platform/release-commit"
Remove-Item -LiteralPath $releaseArchive
```

```bash
release_commit="$(sudo cat /etc/endpoint-platform/release-commit)"
release_dir="/opt/endpoint-platform/releases/endpoint-platform-${release_commit}"
sudo tar -xzf "/tmp/endpoint-platform-${release_commit}.tar.gz" -C /opt/endpoint-platform/releases
sudo rm -f "/tmp/endpoint-platform-${release_commit}.tar.gz"
sudo python3.12 -m venv "${release_dir}/venv"
sudo "${release_dir}/venv/bin/pip" install --upgrade pip
sudo "${release_dir}/venv/bin/pip" install -r "${release_dir}/requirements-server.txt"
sudo chown -R root:root "${release_dir}"
previous_release="$(sudo readlink -f /opt/endpoint-platform/current 2>/dev/null || true)"
if [ -n "${previous_release}" ]; then
  printf '%s\n' "${previous_release}" | sudo install -o root -g root -m 0644 /dev/stdin /etc/endpoint-platform/previous-release
fi
sudo ln -sfn "${release_dir}" /opt/endpoint-platform/current
```

Install the non-secret assets from the operator worktree. Enable the Nginx
configuration symlink for validation only; Nginx remains stopped until the
loopback API health check passes:

```powershell
scp deploy/server/endpoint-platform.service deploy/server/endpoint-platform-worker.service deploy/server/endpoint-platform-migrate.service deploy/server/endpoint-platform.nginx.conf endpoint-platform-server:/tmp/
ssh endpoint-platform-server "sudo install -o root -g root -m 0644 /tmp/endpoint-platform.service /etc/systemd/system/endpoint-platform.service; sudo install -o root -g root -m 0644 /tmp/endpoint-platform-worker.service /etc/systemd/system/endpoint-platform-worker.service; sudo install -o root -g root -m 0644 /tmp/endpoint-platform-migrate.service /etc/systemd/system/endpoint-platform-migrate.service; sudo install -o root -g root -m 0644 /tmp/endpoint-platform.nginx.conf /etc/nginx/sites-available/endpoint-platform; sudo ln -sfn /etc/nginx/sites-available/endpoint-platform /etc/nginx/sites-enabled/endpoint-platform; sudo rm -f /tmp/endpoint-platform.service /tmp/endpoint-platform-worker.service /tmp/endpoint-platform-migrate.service /tmp/endpoint-platform.nginx.conf; sudo systemctl daemon-reload"
```

Validate the configured application before any public listener is enabled:

Run the validation with the same environment as systemd; do not type secret
values into the terminal:

```bash
sudo systemd-run --wait --collect --property=User=endpoint-platform --property=Group=endpoint-platform --property=EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env --working-directory=/opt/endpoint-platform/current /opt/endpoint-platform/current/venv/bin/python -c "from endpoint_server.config import Settings; Settings.from_environment()"
```

## 5. Transfer TLS material without a workspace file

Use the root key that already authenticates to the TLS source. Stream the leaf
and key directly to privileged paths on the Endpoint host; neither command
writes a local file:

```powershell
ssh endpoint-platform-server 'sudo install -d -o root -g root -m 0700 /etc/nginx/ssl'
ssh -i 'C:\Users\admin-2\.ssh\id_ed25519' root@192.168.100.12 'cat /etc/nginx/ssl/sosnadmin-wildcard.crt.pem' | ssh endpoint-platform-server 'sudo install -m 0644 /dev/stdin /etc/nginx/ssl/endpoint.sosnadmin.local.leaf.pem'
ssh -i 'C:\Users\admin-2\.ssh\id_ed25519' root@192.168.100.12 'cat /etc/nginx/ssl/sosnadmin-wildcard.key.pem' | ssh endpoint-platform-server 'sudo install -m 0600 /dev/stdin /etc/nginx/ssl/endpoint.sosnadmin.local.key.pem'
```

Upload the operator-held CA certificate only to the host, then make the public
fullchain and remove the temporary leaf file:

```powershell
scp 'C:\Users\admin-2\Desktop\Новая папка (2)\тех\сертификат\sosnadmin-local-ca.crt' endpoint-platform-server:/tmp/sosnadmin-local-ca.crt
ssh endpoint-platform-server "sudo install -o root -g root -m 0644 /tmp/sosnadmin-local-ca.crt /etc/endpoint-platform/sosnadmin-local-ca.crt; sudo sh -c 'cat /etc/nginx/ssl/endpoint.sosnadmin.local.leaf.pem /etc/endpoint-platform/sosnadmin-local-ca.crt > /etc/nginx/ssl/endpoint.sosnadmin.local.fullchain.pem'; sudo rm -f /etc/nginx/ssl/endpoint.sosnadmin.local.leaf.pem /tmp/sosnadmin-local-ca.crt; sudo chmod 0644 /etc/nginx/ssl/endpoint.sosnadmin.local.fullchain.pem; sudo chown root:root /etc/nginx/ssl/endpoint.sosnadmin.local.fullchain.pem /etc/nginx/ssl/endpoint.sosnadmin.local.key.pem"
```

Confirm the key's metadata without displaying it and validate Nginx:

```bash
sudo stat -c '%a %U:%G %n' /etc/nginx/ssl/endpoint.sosnadmin.local.key.pem
sudo nginx -t
```

## 6. Migrate, start, and validate

Migrations are forward-only. Do not start the public API if this one-shot unit
fails, and do not run an automatic downgrade:

```bash
sudo systemctl start endpoint-platform-migrate.service
sudo systemctl start endpoint-platform.service
for attempt in $(seq 1 10); do
  if curl --fail --silent --show-error --connect-timeout 1 --max-time 2 http://127.0.0.1:8000/healthz; then
    break
  fi
  if [ "${attempt}" -eq 10 ]; then
    echo "Endpoint Platform API did not become ready after 10 attempts" >&2
    exit 1
  fi
  sleep 1
done
sudo systemctl enable --now endpoint-platform-worker.service
sudo systemctl enable --now nginx
sudo systemctl reload nginx
```

Check service state and migration revision:

```bash
systemctl is-active postgresql endpoint-platform endpoint-platform-worker nginx
sudo systemctl show endpoint-platform-migrate.service -p Result --value
sudo systemd-run --wait --collect --property=User=endpoint-platform --property=Group=endpoint-platform --property=EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env --working-directory=/opt/endpoint-platform/current /opt/endpoint-platform/current/venv/bin/python -m alembic current
```

From the operator workstation, verify the actual DNS name, CA chain, and
hostname. Do not substitute an IP address:

```powershell
openssl s_client -connect endpoint.sosnadmin.local:443 -servername endpoint.sosnadmin.local -verify_hostname endpoint.sosnadmin.local -verify_return_error -CAfile 'C:\Users\admin-2\Desktop\Новая папка (2)\тех\сертификат\sosnadmin-local-ca.crt'
curl.exe --fail --noproxy '*' --cacert 'C:\Users\admin-2\Desktop\Новая папка (2)\тех\сертификат\sosnadmin-local-ca.crt' https://endpoint.sosnadmin.local/healthz
```

Only after all checks pass, open a TTY on the host and run the existing
interactive bootstrap. The password is entered twice by the operator and never
appears in the command line:

```bash
sudo systemd-run --pty --wait --collect --property=User=endpoint-platform --property=Group=endpoint-platform --property=EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env --working-directory=/opt/endpoint-platform/current /opt/endpoint-platform/current/venv/bin/python -m endpoint_server.auth.bootstrap_admin ADMIN_USERNAME
```

Replace `ADMIN_USERNAME` with the administrator login approved by the operator.

### Runtime diagnostic target integration

Provision the Helpdesk service credential through the existing protected
service-credential administration flow. Its service client identifier must be
exactly `helpdesk` and its scopes must include exactly
`helpdesk.diagnostic_target.read`; no other client identifier is authorized by
this route. Deliver the bearer only through the approved secret channel and do
not paste it into a shell command, ticket, audit record, or this runbook.

Helpdesk calls `GET /service/v1/runtime/devices/{device_ref}` only over
`https://endpoint.sosnadmin.local`, with its service bearer and a non-empty
`X-Correlation-ID`. `device_ref` is the Endpoint UUID already selected by
Helpdesk; Endpoint does not resolve Registry data. An installed agent records
`POST /agent/v1/runtime/heartbeat` through its device bearer. The server marks
the device online only for 90 seconds after its server-observed heartbeat.
Malformed, unavailable, or correlation-mismatched results are fail-closed and
are not equivalent to the correlated `endpoint_device_not_found` response.

## 7. Release rollback

If the API release fails after migrations have succeeded, use the recorded
prior release; stop if the marker is missing or does not name a release
directory:

```bash
previous_release="$(sudo cat /etc/endpoint-platform/previous-release)"
test -d "${previous_release}"
sudo systemctl stop endpoint-platform.service
sudo systemctl stop endpoint-platform-worker.service
sudo ln -sfn "${previous_release}" /opt/endpoint-platform/current
sudo systemctl start endpoint-platform.service
curl --fail http://127.0.0.1:8000/healthz
sudo systemctl start endpoint-platform-worker.service
```

Then repeat the strict TLS and HTTPS health commands above. Never downgrade a
production migration automatically; investigate and approve a specific schema
rollback separately.
