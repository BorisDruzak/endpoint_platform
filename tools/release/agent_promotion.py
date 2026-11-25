"""Preview or promote a recorded Windows candidate using the canonical publisher."""

from argparse import ArgumentParser, Namespace
import asyncio
import os
from pathlib import Path
from uuid import UUID

from tools.release import agent_reservations
from tools.release.agent_candidate_artifacts import verify_recorded_candidate


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--request-id", required=True, type=UUID)
    parser.add_argument("--platform", required=True, choices=("windows",))
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--expected-publisher", required=True)
    parser.add_argument("--qualification-id", required=True, type=UUID)
    campaign = parser.add_mutually_exclusive_group()
    campaign.add_argument("--default-campaign-id", type=UUID)
    campaign.add_argument("--without-auto-enrollment", action="store_true", help="Explicit diagnostic exception")
    parser.add_argument("--execute", action="store_true", help="Apply the authorized same-row promotion")


def promote(args: Namespace) -> dict:
    from tools.register_windows_setup_release import preview_promotion, register_release, validate_release_inputs

    candidate = verify_recorded_candidate(agent_reservations.reservation_status(args), args.platform,
                                          args.artifacts_dir)
    artifacts = candidate["artifacts"]
    paths = {kind: args.artifacts_dir / proof["filename"] for kind, proof in artifacts.items()}
    metadata = validate_release_inputs(paths["manifest"], paths["setup"], paths["msi"], paths["msi_manifest"],
                                       args.expected_publisher, candidate_only=True)
    if (metadata.version, metadata.agent_version, metadata.source_commit, metadata.msi_source_commit,
            metadata.setup_sha256, metadata.msi_sha256) != (
            candidate["version"], candidate["version"], candidate["build_revision"], candidate["msi_source_revision"],
            artifacts["setup"]["sha256"], artifacts["msi"]["sha256"]):
        raise ValueError("Setup metadata differs from the recorded candidate")
    database_url = os.environ.get("DATABASE_URL")
    artifact_root = os.environ.get("ARTIFACT_ROOT")
    if not database_url or not artifact_root:
        raise ValueError("DATABASE_URL and ARTIFACT_ROOT are required on the selected provider")
    destination = dict(database_url=database_url, artifact_root=Path(artifact_root),
                       default_campaign_id=args.default_campaign_id,
                       include_in_auto_campaign=not args.without_auto_enrollment)
    result = {"schema_version": 1, "platform": "windows", "version": candidate["version"],
              "build_revision": candidate["build_revision"], "request_id": candidate["request_id"],
              "sha256": metadata.setup_sha256, "qualification_id": str(args.qualification_id)}
    if not args.execute:
        preview = asyncio.run(preview_promotion(metadata, qualification_id=args.qualification_id, **destination))
        return {**result, "state": "preview", **preview}
    release = asyncio.run(register_release(metadata, paths["setup"],
                                           promotion_qualification_id=args.qualification_id, **destination))
    return {**result, "state": "published", "release_id": str(release.id),
            "download_published": release.download_published,
            "auto_enrollment_action": "preserve" if args.without_auto_enrollment else "include_default"}
