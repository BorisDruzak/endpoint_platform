"""Restore a signed synthetic release bundle into a new loopback database."""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
from time import perf_counter
from uuid import UUID, uuid4
import zipfile

import aiohttp
import asyncpg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import make_url

from endpoint_server.auth.admin_sessions import issue_admin_session
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import AdminUser, CommandResult, UpdateTarget
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.updates.service import create_rollout, register_build
from tests.gateway.conftest import PEPPER, gateway_settings, seed_device
from tests.gateway.test_stability_capacity import _connect, _grant, _receive, _result, _send_result
from tests.gateway.test_stability_recovery import _api
from tests.server.test_update_postgresql import update_service_database_url, update_service_provider


_RESTORED_API = """
import ipaddress
import os
from pathlib import Path

import uvicorn

from endpoint_server.config import Settings
from endpoint_server.main import create_app

root = Path(os.environ["ENDPOINT_RESTORE_ROOT"])
identity = root / "identity"
loopback = (ipaddress.ip_network("127.0.0.0/8"),)
app = create_app(Settings(
    database_url=os.environ["ENDPOINT_RESTORE_DATABASE_URL"],
    public_base_url="https://endpoint.sosnadmin.local",
    artifact_root=root / "artifacts",
    device_token_pepper=(identity / "device-pepper").read_bytes(),
    service_token_pepper=(identity / "service-pepper").read_bytes(),
    session_secret=(identity / "session-secret").read_bytes(),
    allowed_agent_cidrs=loopback, allowed_admin_cidrs=loopback, trusted_proxy_cidrs=loopback,
))
uvicorn.run(app, host="127.0.0.1", port=int(os.environ["ENDPOINT_RESTORE_API_PORT"]),
            ws="websockets", proxy_headers=False, workers=1,
            log_level="info", timeout_graceful_shutdown=5)
"""
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@asynccontextmanager
async def _restored_api(root, database_url, *, application=None, port=0):
    env = {**os.environ, "ENDPOINT_RESTORE_DATABASE_URL": database_url,
           "ENDPOINT_RESTORE_API_PORT": str(port), "ENDPOINT_RESTORE_ROOT": str(root), "PYTHONPATH": ""}
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-u", "-c", _RESTORED_API, cwd=application or root / "application", env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    try:
        async with asyncio.timeout(15):
            startup = []
            while line := await process.stdout.readline():
                startup.append(line.decode(errors="replace"))
                bound = re.search(rb"Uvicorn running on http://127\.0\.0\.1:(\d+)", line)
                if bound is not None:
                    break
            else:
                pytest.fail("Restored API exited during startup: " + "".join(startup))
        yield f"http://127.0.0.1:{bound[1].decode()}", process
    finally:
        if process.returncode is None:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.terminate()
            try:
                await asyncio.wait_for(process.communicate(), 10)
            except TimeoutError:
                process.kill()
                await process.wait()


def _digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _pg_tool(tool, url, *arguments):
    parsed = make_url(url)
    assert parsed.host in {"127.0.0.1", "localhost", "::1"}
    assert re.fullmatch(r"endpoint_update_service_[a-f0-9]{32}", parsed.database)
    binary_root = os.getenv("ENDPOINT_TEST_POSTGRES_BIN")
    executable = str(Path(binary_root) / (tool + (".exe" if os.name == "nt" else ""))) if binary_root else tool
    env = {**os.environ, "PGHOST": parsed.host, "PGPORT": str(parsed.port or 5432),
           "PGUSER": parsed.username, "PGDATABASE": parsed.database, "PGCONNECT_TIMEOUT": "5"}
    if parsed.password is not None:
        env["PGPASSWORD"] = parsed.password
    result = subprocess.run([executable, "--no-password", *map(str, arguments)], env=env,
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@asynccontextmanager
async def _empty_destination(source_url):
    admin_url = make_url(os.environ["ENDPOINT_TEST_POSTGRES_URL"])
    assert admin_url.host in {"127.0.0.1", "localhost", "::1"}
    name = f"endpoint_update_service_{uuid4().hex}"
    admin = await asyncpg.connect(admin_url.set(drivername="postgresql").render_as_string(hide_password=False))
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        try:
            yield make_url(source_url).set(database=name).render_as_string(hide_password=False)
        finally:
            await admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
    finally:
        await admin.close()


@pytest.mark.skipif(os.getenv("ENDPOINT_STABILITY_RESTORE") != "1", reason="opt-in restore rehearsal")
async def test_restore_signed_release_and_resume(update_service_provider, update_service_database_url, tmp_path):
    source = update_service_provider
    source_url = update_service_database_url
    workspace = tmp_path / "source"
    artifacts = workspace / "artifacts"
    artifacts.mkdir(parents=True)
    signing = Ed25519PrivateKey.generate()
    identity = workspace / "identity"
    identity.mkdir()
    identity.joinpath("device-pepper").write_bytes(PEPPER)
    identity.joinpath("service-pepper").write_bytes(secrets.token_bytes(32))
    identity.joinpath("session-secret").write_bytes(secrets.token_bytes(32))
    identity.joinpath("signing-key").write_bytes(signing.private_bytes_raw())
    device_token = uuid4().hex
    device = await seed_device(source, token=device_token)
    instance = uuid4()
    release_name = f"restore-{uuid4().hex}"
    artifact = artifacts / f"{release_name}.tar.gz"
    artifact.write_bytes(b"Synthetic Endpoint Core artifact for backup acceptance\n")
    settings = replace(
        gateway_settings(artifact_root=artifacts), database_url=source_url,
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        session_secret=identity.joinpath("session-secret").read_bytes(),
    )
    version = f"4.5.{uuid4().int % 1_000_000}"
    artifact_route = f"/agent/v1/updates/artifacts/{release_name}"
    now = datetime.now(UTC)
    async with source() as db:
        admin = AdminUser(username=uuid4().hex, password_digest="fixture-only", scopes=["updates:write"])
        db.add(admin)
        await db.flush()
        issued = issue_admin_session(admin.id, settings.session_secret)
        admin_name = admin.username
        db.add(issued.record)
        build = await register_build(db, {
            "schema_version": "update_build_manifest_v1", "build_identifier": release_name,
            "version": version, "platform": "linux_amd64", "channel": "canary",
            "artifact_url": f"{settings.public_base_url}{artifact_route}", "artifact_name": artifact.name,
            "archive_type": "tar.gz", "sha256": _digest(artifact), "size": artifact.stat().st_size,
        }, admin.id, "restore-register")
        rollout = await create_rollout(db, build.id, "canary", [device.id], None, admin.id, "restore-rollout")
        target = await db.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id))
        operation_id = target.operation_id
        db.add(ContextCollection(
            device_id=device.id, profile="health_v1", requested_by="stability-restore",
            idempotency_key="before-backup", status="requested", requested_at=now,
            expires_at=now + timedelta(minutes=5),
        ))
        await db.commit()
    async with aiohttp.ClientSession(trust_env=False) as client:
        async with _api(settings, source) as base, AsyncExitStack() as stack:
            ws = await _connect(client, stack, f"{base}/agent/v1/connect", device.id, instance, device_token)
            command_id = (await _receive(ws, "command"))["command_id"]
            await _grant(ws, device.id, command_id)
            frame = _result(device.id, command_id, 5)

    dump = workspace / "endpoint.dump"
    await asyncio.to_thread(_pg_tool, "pg_dump", source_url, "--format=custom", "--file", dump)
    # The application is quiescent when the logical export takes its snapshot.
    captured_at = datetime.now(UTC)
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=_REPOSITORY_ROOT, text=True, timeout=15,
    ).strip()
    subprocess.run([
        "git", "archive", "--format=zip", f"--output={workspace / 'application.zip'}", revision,
        "--", "endpoint_server", "endpoint_contracts", "shared", "browser_sensor",
        "alembic.ini", "requirements-server.txt",
    ], cwd=_REPOSITORY_ROOT, check=True, timeout=30)
    release_files = {
        str(path.relative_to(workspace).as_posix()): _digest(path)
        for path in workspace.rglob("*") if path.is_file() and path.parent != identity
    }
    manifest = json.dumps({"revision": revision, "schema": "0053_activity_dirty_since",
                           "files": release_files}, sort_keys=True).encode()
    workspace.joinpath("release.json").write_bytes(manifest)
    workspace.joinpath("release.sig").write_bytes(signing.sign(manifest))
    trusted_public = signing.public_key().public_bytes_raw()
    backup = tmp_path / "backup"
    shutil.copytree(workspace, backup)
    # Independent data committed after the backup provides a known RPO marker.
    after = await seed_device(source, token=uuid4().hex)
    loss_at = datetime.now(UTC)

    restore_started = perf_counter()
    async with _empty_destination(source_url) as destination_url:
        restored = tmp_path / "restored"
        shutil.copytree(backup, restored)
        restored_manifest = restored.joinpath("release.json").read_bytes()
        public = Ed25519PublicKey.from_public_bytes(trusted_public)
        public.verify(restored.joinpath("release.sig").read_bytes(), restored_manifest)
        metadata = json.loads(restored_manifest)
        assert metadata["revision"] == revision
        assert all(_digest(restored / name) == digest for name, digest in metadata["files"].items())
        with zipfile.ZipFile(restored / "application.zip") as application:
            assert application.comment.decode() == revision
            application.extractall(restored / "application")
        restored_signer = Ed25519PrivateKey.from_private_bytes(restored.joinpath("identity/signing-key").read_bytes())
        public.verify(restored_signer.sign(b"restore-proof"), b"restore-proof")
        await asyncio.to_thread(_pg_tool, "pg_restore", destination_url, "--exit-on-error",
                                "--single-transaction", "-d", make_url(destination_url).database,
                                restored / "endpoint.dump")
        provider = AsyncSessionProvider(destination_url)
        try:
            async with _restored_api(restored, destination_url) as (base, _):
                await _verify_restored_service(provider, base, device.id, instance, device_token, frame,
                    issued.token, admin_name, artifact_route, operation_id,
                    release_files[f"artifacts/{artifact.name}"], after.id, metadata["schema"])
                accepted_at = perf_counter()
        finally:
            await provider.close()
        print(json.dumps({"restore_seconds": round(accepted_at - restore_started, 3),
                          "backup_to_loss_marker_seconds": round((loss_at - captured_at).total_seconds(), 3),
                          "release_revision": revision, "schema": metadata["schema"]}), flush=True)


async def _verify_restored_service(provider, base, device_id, instance, device_token, frame,
                                   admin_token, admin_name, artifact_route, operation_id, artifact_digest,
                                   after_backup_id, schema):
    from sqlalchemy import text
    from endpoint_server.db.models import Device

    async with AsyncExitStack() as stack:
        client = await stack.enter_async_context(aiohttp.ClientSession(trust_env=False))
        proxy_headers = {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"}
        async with client.get(f"{base}/api/admin/console/session", headers={
            **proxy_headers, "Cookie": f"endpoint_admin_session={admin_token}",
        }) as response:
            assert response.status == 200
            assert (await response.json())["username"] == admin_name
        ws = await _connect(client, stack, f"{base}/agent/v1/connect", device_id, instance, device_token)
        await _send_result(ws, frame)
        await _send_result(ws, frame)
        headers = {**proxy_headers, "Authorization": f"Bearer {device_token}"}
        async with client.post(f"{base}/agent/v1/updates/{operation_id}/ack", headers=headers,
                               json={"schema_version": "agent_update_ack_v1", "status": "requested"}) as response:
            assert response.status == 204
        async with client.get(f"{base}{artifact_route}", headers=headers) as response:
            assert response.status == 200
            assert hashlib.sha256(await response.read()).hexdigest() == artifact_digest
        async with provider() as db:
            assert await db.scalar(text("SELECT version_num FROM alembic_version")) == schema
            assert await db.get(Device, after_backup_id) is None
            assert await db.scalar(select(func.count()).select_from(CommandResult).where(
                CommandResult.command_id == UUID(frame["payload"]["command_id"]))) == 1
            assert await db.scalar(select(func.count()).select_from(ContextSnapshot).where(
                ContextSnapshot.device_id == device_id)) == 1
