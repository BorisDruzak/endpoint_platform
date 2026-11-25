"""Verify a recorded ALT kit and register its exact signed RPMs when authorized."""

from argparse import ArgumentParser, Namespace
import asyncio
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
from tempfile import TemporaryDirectory
from uuid import UUID

from tools.release import agent_reservations
from tools.release.agent_candidate_artifacts import MAX_METADATA, _fingerprint, alt_rpm_names, verify_recorded_candidate
from tools.release.linux_native_verifier import MAX_RPM, NativeRPMVerifier, PUBLISHER, publication_verifier, snapshot


ROOT = Path(__file__).resolve().parents[2]


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--request-id", required=True, type=UUID)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--public-key", type=Path, default=ROOT / "packaging/alt/pilot/endpoint-rpm-release.asc")
    parser.add_argument("--reviewed-by", required=True, help="Operator identity recorded in the native registry")
    parser.add_argument("--execute", action="store_true", help="Register the pair in the configured provider")


def _retain_rpms(candidate, artifact_dir, output, verifier):
    version = candidate["version"]
    name = f"endpoint-alt-pilot-{version}-1"
    members = candidate["members"]
    pair = alt_rpm_names(members, version)
    with ExitStack() as stack:
        retained = {}
        for label, proof in candidate["artifacts"].items():
            limit = 3 * MAX_RPM + MAX_METADATA if label == "archive" else MAX_METADATA
            path, digest = stack.enter_context(snapshot(artifact_dir / proof["filename"], max_bytes=limit))
            if digest != proof["sha256"] or path.stat().st_size != proof["size"]:
                raise ValueError("ALT kit changed during retention")
            retained[label] = path
        verifier.verify_detached((retained[label], retained[f"{label}_signature"]) for label in ("archive", "manifest"))
        manifest = json.loads(retained["manifest"].read_bytes())
        expected = {"schema_version": "endpoint_alt_native_kit_v3", "kit_name": name, "agent_version": version,
                    "agent_source_revision": candidate["build_revision"], "publisher_fingerprint": PUBLISHER,
                    "frozen_manifest_sha256": candidate["frozen_manifest_sha256"], "files": members}
        if any(manifest.get(field) != value for field, value in expected.items()):
            raise ValueError("Signed ALT manifest differs from the recorded candidate")
        try:
            with tarfile.open(retained["archive"], "r:gz") as archive:
                for filename in pair:
                    proof = members[filename]
                    member = archive.getmember(f"{name}/{filename}")
                    if not member.isfile() or member.size != proof["size"] or not 0 < member.size <= MAX_RPM:
                        raise ValueError("ALT kit member differs from the signed manifest")
                    path = output / filename
                    with archive.extractfile(member) as source, path.open("xb") as destination:
                        shutil.copyfileobj(source, destination, length=1024 * 1024)
                    if _fingerprint(path, MAX_RPM) != {"filename": filename, **proof}:
                        raise ValueError("ALT kit RPM differs from the signed manifest")
                    path.chmod(0o400)
        except (KeyError, EOFError, tarfile.TarError) as exc:
            raise ValueError("Signed ALT kit cannot supply the exact RPM pair") from exc
    return output / pair[0], output / pair[1]


def _verified_native_source(verifier, candidate, core, sensor, reviewed_by):
    left, right = verifier(core), verifier(sensor)
    version, revision = candidate["version"], candidate["build_revision"]
    frozen_manifest = candidate["frozen_manifest_sha256"]
    members = candidate["members"]
    for proof, path, package in ((left, core, "endpoint-agent"), (right, sensor, "endpoint-agent-user-sensor")):
        if (proof.nevra, proof.package, proof.version, proof.source_revision, proof.frozen_manifest_sha256,
                proof.signer_fingerprint, proof.sha256) != (path.stem, package, version, revision, frozen_manifest,
                    PUBLISHER, members[path.name]["sha256"]):
            raise ValueError("Signed RPM identity differs from the recorded ALT candidate")
    if left.setup_sha256 != members["endpoint-agent-setup"]["sha256"]:
        raise ValueError("ALT kit Setup differs from the Setup bound by signed Core")
    return {"version": version, "source_revision": revision, "core_nevra": left.nevra, "core_rpm_sha256": left.sha256,
            "user_sensor_nevra": right.nevra, "user_sensor_rpm_sha256": right.sha256,
            "signer_fingerprint": PUBLISHER, "frozen_manifest_sha256": frozen_manifest, "reviewed_by": reviewed_by}


async def _publish(database_url, source, core, sensor, public_key, request_id):
    from endpoint_server.db.session import create_session_provider
    from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeReview, publish_native_release

    provider = create_session_provider(database_url)
    try:
        async with provider() as session:
            release = await publish_native_release(session, LinuxNativeReview.model_validate(source), core, sensor,
                                                   verify_rpm=publication_verifier(public_key), request_id=str(request_id))
            await session.commit()
            return str(release.id)
    finally:
        await provider.close()


def register(args: Namespace) -> dict:
    candidate = verify_recorded_candidate(agent_reservations.reservation_status(args), "alt", args.artifacts_dir)
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("ALT native verification requires the privileged Linux publisher environment")
    database_url = os.environ.get("DATABASE_URL")
    if args.execute and not database_url:
        raise ValueError("DATABASE_URL is required to register the ALT native pair")

    verifier = NativeRPMVerifier(args.public_key)
    with TemporaryDirectory(prefix="endpoint-alt-publish-") as work:
        core, sensor = _retain_rpms(candidate, args.artifacts_dir, Path(work), verifier)
        source = _verified_native_source(verifier, candidate, core, sensor, args.reviewed_by)
        result = {"schema_version": 1, "platform": "alt", "state": "verified", "request_id": candidate["request_id"],
                  "kit_sha256": candidate["artifacts"]["archive"]["sha256"], "native_source": source}
        if not args.execute:
            return result
        release_id = asyncio.run(_publish(database_url, source, core, sensor, args.public_key, args.request_id))
        return {**result, "state": "registered", "native_release_id": release_id}
