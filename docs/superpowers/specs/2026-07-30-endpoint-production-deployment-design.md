# Endpoint Platform Production Deployment Design

## Purpose

Deploy the already verified Endpoint Platform server to
`endpoint.sosnadmin.local` on `192.168.100.19` without weakening TLS, storing
secrets in Git, or exposing PostgreSQL or Uvicorn to the network.

## Scope

This deployment adds production assets for the existing FastAPI application:

- an ASGI entrypoint that loads the existing fail-closed `Settings`;
- a versioned application release under `/opt/endpoint-platform/releases` and
  an atomic `current` symlink used by systemd;
- a local PostgreSQL database and least-privilege application role;
- an unprivileged `endpoint-platform` systemd service bound to `127.0.0.1:8000`;
- an Nginx virtual host for `endpoint.sosnadmin.local` that proxies only to
  that loopback listener;
- an operator-only deployment runbook and validation steps.

The deployment does not deploy `web_ovpn`, change network configuration,
install an agent on production, or issue provisioning claims.

## Network and TLS

The public origin is exactly `https://endpoint.sosnadmin.local`.  Nginx is the
only public listener and uses the verified wildcard certificate
`*.sosnadmin.local`, copied from the current TLS source host through an SSH
stream without writing the certificate or private key into this repository or
the operator workspace.

Uvicorn listens only on `127.0.0.1:8000` with proxy-header interpretation
disabled.  Nginx overwrites `X-Forwarded-For` with `$remote_addr`; it does not
append caller-provided values.  The application sets
`TRUSTED_PROXY_CIDRS=127.0.0.1/32` and retains ownership of client-address
validation.

Both `ALLOWED_AGENT_CIDRS` and `ALLOWED_ADMIN_CIDRS` are initially limited to
`192.168.100.0/24,192.168.101.0/24`.

## Runtime and secret boundaries

`endpoint-platform` is a dedicated system user with no login shell.  It owns
its writable state below `/var/lib/endpoint-platform`; application releases
remain root-owned and read-only.  The systemd unit enables standard filesystem
and privilege hardening and writes only to the application state directory.

The PostgreSQL application password is a fresh random value held only in a
root-owned `0600` systemd environment file.  The device-token pepper,
service-token pepper, and session secret are independent random `0600` regular
files readable only by the application user.  The Nginx private key remains
root-owned `0600`; the public certificate is not treated as a secret.  No
secret, password, certificate, private key, or connection string is committed,
printed, or copied into the workspace.

The first administrator is created only after the service is healthy, using
the existing interactive bootstrap command on a TTY.  Its password is entered
by the operator, never supplied through an argument, environment variable, or
log.

## Installation and migration order

1. Re-run the local test and generated-contract gates for the selected commit,
   then transfer a release archive to a new immutable release directory.
2. Re-check host capacity and install the operating-system PostgreSQL and
   Nginx packages.  Create the database role and database; PostgreSQL remains
   loopback-only.
3. Create the system user, directories, secret files, environment file,
   systemd unit, and Nginx configuration.  Validate the settings as the service
   user before enabling a public listener.
4. Install the certificate and key directly from the TLS source host with
   restrictive permissions, then validate the Nginx configuration.
5. Run `alembic upgrade head` through a one-shot service that has the same
   protected environment as the API.  Do not start the public API before this
   step succeeds.
6. Start the API service, make a loopback health request, enable/reload Nginx,
   and make a strict TLS health request using the internal CA and the DNS name.
7. Bootstrap the first administrator interactively, then record the deployed
   commit, migration revision, service status, and TLS result in the handoff.

## Failure handling and rollback

Any failure before enabling Nginx leaves the public endpoint unavailable and
does not run a destructive rollback.  A migration failure stops the deployment
and preserves the database for diagnosis; no automatic downgrade runs on
production.

For a release failure after a successful migration, stop the API, repoint
`/opt/endpoint-platform/current` to the previous verified release, restart the
service, and repeat loopback and strict TLS health checks.  Database migrations
are forward-only unless a separately reviewed migration rollback is required.

## Verification

Before production changes: generated contract artifacts, all `tests/` suites,
targeted ALT packaging tests, static Alembic SQL, and `git diff --check` pass.

After deployment: `systemctl` reports the API, PostgreSQL, and Nginx active;
the API is not reachable except through loopback; the database reports Alembic
revision `0010_device_session_last_seen_index`; and HTTPS validation succeeds
for `endpoint.sosnadmin.local` with hostname verification enabled and the
internal CA.
