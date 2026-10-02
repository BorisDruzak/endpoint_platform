"""Isolated Windows source-runtime exercise with a private localhost HTTPS fixture.

Never controls installed SCM services. The offline worker's existing injected
AgentService boundary manages only a child process beneath the supplied root.
Use an external, empty artifact directory; secrets are deleted after the run.
The exact ZIP is verified by its packaged executable; its online candidate is
a source process with machine-wide IPC disabled. Use --packaged-candidate only on a dedicated host without installed Agent
services. Neither mode claims real LocalService or SCM acceptance.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import ssl
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def protect_test_owner(root: Path) -> None:
    """Model MSI-owned test handoff paths using the real production DACL validator."""
    import win32api
    import win32con
    import win32security
    from pc_agent.platform.windows.acl import PyWin32AclAdapter
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
        win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
    privilege = win32security.LookupPrivilegeValue(None, "SeRestorePrivilege")
    win32security.AdjustTokenPrivileges(token, False, [(privilege, win32con.SE_PRIVILEGE_ENABLED)])
    try:
        owner = win32security.ConvertStringSidToSid("S-1-5-18")
        acl = PyWin32AclAdapter()
        for path in [root, *root.rglob("*")]:
            if path.is_symlink():
                raise ValueError("unsafe canary path")
            acl.protect_update_path(path)
            win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION, owner, None, None, None)
    finally:
        token.Close()


def make_tls(root: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated recovery canary")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256()))
    ca = root / "endpoint-ca.crt"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private = root / "server-key.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # Protect the temporary TLS private key; never install it in the system store.
    subprocess.run(["icacls.exe", str(private), "/inheritance:r", "/grant:r",
        "*S-1-5-18:F", "*S-1-5-32-544:F"], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(ca), str(private))
    return ca, private, context


async def scenario(root: Path, artifact: Path, revision: str, negative: bool, packaged: bool):
    try:
        return await _scenario(root, artifact, revision, negative, packaged)
    finally:
        # Setup can fail before a runner/process exists; always remove secrets.
        for name in ("server-key.pem", "device-credential"):
            (root / "data" / name).unlink(missing_ok=True)


async def _scenario(root: Path, artifact: Path, revision: str, negative: bool, packaged: bool):
    from aiohttp import web
    from endpoint_contracts import AgentUpdateRecommendationV1
    from pc_agent.runtime import application
    from pc_agent.platform.windows.update_supervisor import WindowsRecoveryUpdateSupervisor
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.platform.windows.updater_service import WindowsUpdater
    from pc_agent.version import AGENT_VERSION

    root.mkdir()
    data = root / "data"
    install = root / "install"
    data.mkdir()
    install.mkdir()
    (root / "Tray").mkdir()
    bearer = secrets.token_urlsafe(32)
    credential = data / "device-credential"
    credential.write_text(bearer, encoding="ascii")
    subprocess.run(["icacls.exe", str(credential), "/inheritance:r", "/grant:r",
        "*S-1-5-18:F", "*S-1-5-32-544:F"], check=True, capture_output=True)
    write_json(data / "enrollment-identity.json", {
        "device_id": str(uuid4()), "schema_version": "endpoint_enrollment_identity_v1"})
    previous = "3.2.78"
    write_json(install / "current.json", {"schema_version": 1,
        "source_revision": revision, "version": previous})
    ca, private, tls = make_tls(data)
    operation = str(uuid4())
    facts = {"wss_failures": 0, "handshakes": 0, "recommendations": 0,
        "artifact_downloads": 0, "acks": [], "reports": [], "trigger_requested": False}
    wss_failed = asyncio.Event()
    root_running = asyncio.Event()
    candidate_allowed = False
    terminal = False
    scheduled = False
    origin = ""
    process = None

    @web.middleware
    async def auth(request, handler):
        if request.headers.get("Authorization") != f"Bearer {bearer}":
            return web.Response(status=401)
        return await handler(request)

    async def connect(request):
        if not candidate_allowed or negative:
            facts["wss_failures"] += 1
            wss_failed.set()
            return web.Response(status=503)
        socket = web.WebSocketResponse()
        await socket.prepare(request)
        hello = await socket.receive_json()
        assert hello["kind"] == "agent_hello"
        assert hello["payload"]["agent_version"] == AGENT_VERSION
        facts["handshakes"] += 1
        await socket.send_json({"schema_version": "gateway_ws_envelope_v1",
            "sequence": 0, "kind": "gateway_hello", "payload": {
                "schema_version": "gateway_hello_v1", "session_id": str(uuid4()),
                "heartbeat_interval_seconds": 30, "maximum_message_bytes": 65536,
                "policy_revision": 0, "effective_capabilities": [],
                "server_time": datetime.now(UTC).isoformat()}})
        async for _message in socket:
            pass
        return socket

    async def recommendation(_request):
        facts["recommendations"] += 1
        if terminal or candidate_allowed:
            return web.Response(status=204)
        await asyncio.wait_for(wss_failed.wait(), 15)
        root_running.set()
        contract = AgentUpdateRecommendationV1(
            schema_version="agent_update_recommendation_v1", operation_id=operation,
            build_identifier=f"recovery-{AGENT_VERSION}", version=AGENT_VERSION,
            platform="windows_amd64", channel="canary", artifact_url=origin + "/artifact.zip",
            artifact_name="candidate.zip", archive_type="zip",
            sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(), size=artifact.stat().st_size,
            reason="scheduled_rollout")
        return web.json_response(contract.model_dump(mode="json"))

    async def download(_request):
        facts["artifact_downloads"] += 1
        return web.FileResponse(artifact)

    async def ack(request):
        nonlocal scheduled
        status = (await request.json())["status"]
        facts["acks"].append(status)
        scheduled |= status == "scheduled"
        return web.Response(status=204)

    async def report(request):
        nonlocal terminal
        status = (await request.json())["status"]
        if status in {"applied", "rolled_back"} and not scheduled:
            return web.Response(status=409)
        facts["reports"].append(status)
        terminal = True
        return web.json_response({})

    server = web.Application(middlewares=[auth])
    server.router.add_get("/agent/v1/connect", connect)
    server.router.add_get("/agent/v1/updates/recommendation", recommendation)
    server.router.add_get("/artifact.zip", download)
    server.router.add_post("/agent/v1/updates/{operation}/ack", ack)
    server.router.add_post("/agent/v1/updates/{operation}/reports", report)
    runner = web.AppRunner(server, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=tls)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    origin = f"https://localhost:{port}"
    settings = application.RuntimeSettings(data_root=data, install_root=install,
        ca_file=ca, endpoint_origin=origin, transport_mode="gateway_wss")
    paths = WindowsUpdatePaths(install, data / "updates/pending_update.json")

    def isolated_trigger():
        facts["trigger_requested"] = True

    def create_recovery(settings, token, publish):
        return (WindowsRecoveryUpdateSupervisor(
            check=lambda: application._run_windows_update_check(settings, token),
            report=lambda: application._run_windows_startup_report(settings, token),
            trigger=isolated_trigger, publish=publish).run(),)

    # Exclude machine-wide sensor pipes and service identities from this canary.
    # All HTTPS, transport, stager, root cancellation and proof code stays real.
    deps = replace(application._default_dependencies(settings),
        start_local_sensor=lambda _: None, create_completion_sink=lambda _: None,
        create_connected_tasks=lambda *_: (), create_service_tasks=create_recovery,
        load_hello=lambda s: application._load_hello(s).model_copy(update={
            "agent_version": previous, "launcher_version": previous}))
    runtime = application.RuntimeApplication(settings, deps)
    task = asyncio.create_task(runtime.run())
    try:
        discovery = asyncio.create_task(root_running.wait())
        try:
            done, _ = await asyncio.wait({task, discovery}, timeout=30,
                return_when=asyncio.FIRST_COMPLETED)
            if discovery not in done:
                if task in done:
                    raise RuntimeError(f"baseline stopped before discovery: exit={task.result()} phase={runtime.status.phase}")
                raise TimeoutError("baseline did not discover recommendation")
        finally:
            discovery.cancel()
            await asyncio.gather(discovery, return_exceptions=True)
        assert not task.done(), "runtime did not remain alive through WSS failure"
        assert await asyncio.wait_for(task, 90) == 42
        assert facts["handshakes"] == 0
        assert paths.pending_path.is_file()
        facts["staged_before_handshake"] = True
        protect_test_owner(paths.updates_root)

        class ChildService:
            def stop(self):
                nonlocal process
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)
            def wait_stopped(self):
                return process is None or process.poll() is not None
            def start(self):
                nonlocal process, candidate_allowed
                current = json.loads(paths.current_path.read_text())["version"]
                if current == previous:
                    return  # The restored source harness reports below.
                candidate_allowed = True
                exe = paths.versions_root / current / "pc_agent.exe"
                log = (root / "candidate.log").open("ab")
                try:
                    command = ([str(exe)] if packaged else [sys.executable, "-m",
                        "tools.canary.verify_windows_recovery", "--isolated-source-candidate"])
                    process = subprocess.Popen([*command, "--data-dir", str(data),
                        "--install-root", str(install), "--ca-file", str(ca),
                        "--endpoint-origin", origin, "--transport-mode", "gateway_wss"],
                        stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                        creationflags=subprocess.CREATE_NO_WINDOW)
                finally:
                    log.close()
            def crashed_early(self):
                return process is not None and process.poll() is not None

        service = ChildService()
        # The real worker validates the real ACLs, hash, ZIP manifest, candidate
        # --verify, selector, fresh operation/attempt-bound confirmation and rollback.
        outcome = await asyncio.to_thread(WindowsUpdater(paths, service=service,
            deadline_seconds=25).run_once)
        facts["updater_result"] = outcome.status
        assert outcome.status == ("rolled_back" if negative else "applied"), outcome.message
        facts["startup_confirmation"] = (paths.updates_root / "startup-confirmation.json").exists()
        facts["selected_version"] = json.loads(paths.current_path.read_text())["version"]
        if negative:
            assert not facts["startup_confirmation"]
            assert facts["selected_version"] == previous
        else:
            assert facts["handshakes"] >= 1
            assert facts["startup_confirmation"]
            assert facts["selected_version"] == AGENT_VERSION
            assert json.loads(paths.current_path.read_text())["source_revision"] == revision
        # Use the exact runtime HTTPS report boundary; proof still originates
        # only from the packaged candidate after its successful WSS handshake.
        assert await application._run_windows_startup_report(settings, bearer)
        assert facts["reports"][-1] == ("rolled_back" if negative else "applied")
        service.stop()
        facts["scope"] = ("packaged online candidate on dedicated Windows host; process AgentService adapter"
            if packaged else "source candidate with isolated process adapters; packaged executable only for offline verification")
        facts["baseline"] = "source runtime, selector/hello 3.2.78; recovery code from source revision"
        facts["packaged_online_candidate_verified"] = packaged
        facts["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        facts["source_revision"] = revision
        write_json(root / "evidence.json", facts)
        return facts
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if process is not None and process.poll() is None:
            process.terminate()
            await asyncio.to_thread(process.wait, 15)
        await runner.cleanup()
        private.unlink(missing_ok=True)
        credential.unlink(missing_ok=True)


def source_candidate(argv):
    from pc_agent.runtime import application
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--endpoint-origin", required=True)
    parser.add_argument("--transport-mode", choices=["gateway_wss"], required=True)
    args = parser.parse_args(argv)
    # This source-only composition deliberately cannot execute arbitrary normal
    # commands or open machine-wide pipes; production entrypoints are unchanged.
    settings = application.RuntimeSettings(data_root=args.data_dir,
        install_root=args.install_root, ca_file=args.ca_file,
        endpoint_origin=args.endpoint_origin, transport_mode=args.transport_mode)
    deps = replace(application._default_dependencies(settings),
        start_local_sensor=lambda _: None, create_completion_sink=lambda _: None,
        create_connected_tasks=lambda *_: ())
    return asyncio.run(application.RuntimeApplication(settings, deps).run())


def main():
    if sys.argv[1:2] == ["--isolated-source-candidate"]:
        raise SystemExit(source_candidate(sys.argv[2:]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packaged-candidate", action="store_true", help="Requires a dedicated Windows host with installed Agent services absent")
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("requires an elevated isolated Windows canary operator")
    import zipfile
    from pc_agent.version import AGENT_VERSION
    with zipfile.ZipFile(args.artifact) as archive:
        manifest = json.loads(archive.read("endpoint-update-manifest.json"))
    if manifest["source_revision"] != args.source_revision or manifest["version"] != AGENT_VERSION:
        parser.error("artifact manifest does not match requested source/version")
    source_manifest = Path("source-manifest.json")
    if source_manifest.exists():
        source = json.loads(source_manifest.read_text())
        if source["source_revision"] != args.source_revision:
            parser.error("source revision mismatch")
        for name, expected in source["files"].items():
            if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
                parser.error("source file hash mismatch: " + name)
    else:
        subprocess.run(["git", "diff", "--exit-code", args.source_revision, "--", "pc_agent", "endpoint_contracts"],
            check=True, capture_output=True)
    if args.packaged_candidate:
        state = subprocess.check_output(["powershell", "-NoProfile", "-Command",
            "@(Get-Service EndpointAgent,EndpointAgentUpdater,EndpointBrowserPolicy -ErrorAction SilentlyContinue).Count"], text=True)
        if state.strip() != "0":
            parser.error("packaged candidate requires installed Agent services to be absent")
    root = args.output_root.resolve()
    production = Path(r"C:\Program Files\Endpoint Platform\Agent")
    if root.exists() or root == production or production in root.parents:
        parser.error("output root must be new and outside installed Agent state")
    if Path(r"C:\ProgramData\Endpoint Platform") in root.parents:
        parser.error("output root must be outside installed Agent state")
    root.mkdir(parents=True)
    async def run():
        await scenario(root / "positive", args.artifact.resolve(), args.source_revision, False, args.packaged_candidate)
        await scenario(root / "negative", args.artifact.resolve(), args.source_revision, True, args.packaged_candidate)
    fixtures = []
    try:
        if args.packaged_candidate:
            # Production ACLs resolve canonical virtual service SIDs. Register
            # disabled records only; they cannot run and point to no executable.
            for name in ("EndpointAgent", "EndpointAgentUpdater"):
                subprocess.run(["sc.exe", "create", name, "binPath=", str(root / "never-run.exe"),
                    "start=", "disabled"], check=True, capture_output=True)
                fixtures.append(name)
        asyncio.run(run())
    finally:
        for name in reversed(fixtures):
            subprocess.run(["sc.exe", "delete", name], check=True, capture_output=True)
    print(json.dumps({"positive": "passed", "negative": "passed", "evidence_root": str(root)}))


if __name__ == "__main__":
    main()
