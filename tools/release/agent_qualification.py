"""Run the selected canonical builder from a bound release checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from uuid import UUID

from tools.release import agent_reservations, compatibility_matrix, linux_native_verifier, release_plan
from tools.release.agent_candidate_artifacts import MAX_METADATA, _fingerprint, verify_recorded_candidate
from tools.release.alt_build_receipt import read_build_receipt, signing_content_sha256


BUILDERS = {
    "windows_full_setup": "packaging/windows/build-setup.ps1",
    "windows_core_zip": "packaging/windows/build-update-zip.ps1",
    "alt_native_rpm": "packaging/alt/build-rpm.sh",
    "alt_core_ota": "tools/build_linux_agent.py",
}
SETUP_PARAMETERS = {
    "endpoint_origin": "EndpointOrigin",
    "ca_file": "EndpointCaFile",
    "initial_runtime_manifest": "InitialRuntimeManifest",
    "initial_runtime_stage_root": "InitialRuntimeStageRoot",
    "initial_runtime_stage_evidence": "InitialRuntimeStageEvidence",
    "certificate_thumbprint": "CodeSigningCertificateThumbprint",
    "timestamp_server": "TimestampServer",
}
SETUP_SWITCHES = {
    "approve_initial_runtime_transition": "ApproveInitialRuntimeTransition",
    "approve_initial_runtime_source_change": "ApproveInitialRuntimeSourceChange",
}
PATH_INPUTS = {"ca_file", "initial_runtime_manifest", "initial_runtime_stage_root",
               "initial_runtime_stage_evidence", "runtime_root"}


def _add_request_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--request-id", type=UUID, required=True)
    parser.add_argument("--platform", choices=("windows", "alt"), required=True)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    _add_request_arguments(parser)
    parser.add_argument("--base", required=True, help="Reviewed baseline for delivery selection")
    parser.add_argument("--output-root", type=Path, required=True, help="New directory outside the source checkout")
    parser.add_argument("--inputs", type=Path, help="Local JSON with the selected builder inputs")
    parser.add_argument("--runtime-contract", type=Path, help="Source-bound ALT Core compatibility receipt")
    parser.add_argument("--observed-launcher", help="Verified launcher version of the source profile")
    parser.add_argument("--execute", action="store_true", help="Run the build on the approved platform worker")


def add_matrix_arguments(parser: argparse.ArgumentParser) -> None:
    _add_request_arguments(parser)
    parser.add_argument("--artifacts-dir", type=Path, required=True, help="Directory of the recorded native artifacts")
    compatibility_matrix.add_observation_arguments(parser)


def matrix(args: argparse.Namespace) -> dict:
    candidate = verify_recorded_candidate(agent_reservations.reservation_status(args), args.platform,
                                          args.artifacts_dir)
    artifacts = candidate["artifacts"]
    primary = artifacts[agent_reservations.PRIMARY_ARTIFACT[args.platform]]
    target = {"platform": args.platform, "version": candidate["version"], "sha256": primary["sha256"]}
    if args.platform == "alt" and args.alt_lab_evidence:
        from tools.release.agent_candidate_artifacts import alt_rpm_names

        members = candidate["members"]
        target["native_identity"] = {
            "version": candidate["version"],
            "source_revision": candidate["build_revision"],
            **{key: members[name]["sha256"] for key, name in
               zip(compatibility_matrix.ALT_RPM_DIGESTS, alt_rpm_names(members, candidate["version"]), strict=True)},
        }
    report = compatibility_matrix.plan_from_files(args, target)
    report["reservation"] = {"request_id": candidate["request_id"], "build_revision": candidate["build_revision"],
                             "artifacts": artifacts}
    return report


def _assert_source(root: Path, revision: str) -> None:
    current = agent_reservations._git(root, "rev-parse", "HEAD^{commit}").decode().strip()
    if current != revision:
        raise ValueError("Build worker must check out the bound build revision")
    if agent_reservations._git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("Qualification build requires a clean checkout")


def _inputs(path: Path | None) -> dict:
    if path is None:
        return {}
    result = json.loads(path.read_bytes())
    if not isinstance(result, dict):
        raise ValueError("Build inputs must be a JSON object")
    for name in PATH_INPUTS & result.keys():
        value = result[name]
        if not isinstance(value, str) or not value.strip() or value.startswith("-") or "\0" in value:
            raise ValueError(f"Expected a file or directory argument: {name}")
        result[name] = os.path.abspath(path.parent / value)
    return result


def _strings(inputs: dict, required: set[str], allowed: set[str], switches: frozenset[str] = frozenset()) -> None:
    if not required <= inputs.keys() or inputs.keys() - allowed - switches:
        raise ValueError("Missing or unknown fields in the selected builder inputs")
    for name, value in inputs.items():
        if name in switches:
            if not isinstance(value, bool):
                raise ValueError(f"Expected a boolean build input: {name}")
        elif not isinstance(value, str) or not value.strip() or value.startswith("-") or "\0" in value:
            raise ValueError(f"Expected a non-empty argument value: {name}")


def _recipe(root: Path, artifact: str, output: Path, version: str, revision: str,
            inputs: dict, minimum: str | None) -> tuple[list[str], list[Path]]:
    script = str(root / BUILDERS[artifact])
    if artifact == "alt_native_rpm":
        _strings(inputs, set(), set())
        return ["bash", script, "--with-native-setup", "--with-user-sensor", "--output", str(output)], []
    if artifact == "alt_core_ota":
        _strings(inputs, {"runtime_root", "channel"}, {"runtime_root", "channel"})
        if inputs["channel"] not in ("canary", "stable"):
            raise ValueError("ALT OTA channel must be canary or stable")
        stem = f"endpoint-agent-linux_amd64-{version}"
        return [sys.executable, script, "--source", inputs["runtime_root"], "--output", str(output),
                "--channel", inputs["channel"], "--version", version, "--revision", revision], [
                    output / f"{stem}.tar.gz", output / f"{stem}.manifest.json",
                ]

    command = ["pwsh", "-NoProfile", "-NonInteractive", "-File", script, "-Version", version]
    if artifact == "windows_core_zip":
        _strings(inputs, {"runtime_root"}, {"runtime_root"})
        archive = output / f"EndpointCore-{version}-{revision[:7]}.zip"
        return command + ["-RuntimeRoot", inputs["runtime_root"], "-SourceRevision", revision,
                          "-MinimumLauncherVersion", minimum, "-OutputPath", str(archive)], [archive]

    _strings(inputs, {"endpoint_origin", "ca_file"}, set(SETUP_PARAMETERS), frozenset(SETUP_SWITCHES))
    command += ["-WixBuildRoot", str(output)]
    for name, parameter in SETUP_PARAMETERS.items():
        if name in inputs:
            command += [f"-{parameter}", inputs[name]]
    for name, parameter in SETUP_SWITCHES.items():
        if inputs.get(name):
            command.append(f"-{parameter}")
    release = output / "releases"
    msi, setup = f"EndpointAgent-{version}-x64", f"EndpointAgentSetup-{version}-x64"
    return command, [release / filename for filename in (f"{msi}.msi", f"{msi}.release.json",
                      f"{setup}.exe", f"{setup}.release.json")]


def _build_host(selected: str) -> bool:
    if selected == "windows":
        return sys.platform == "win32" and platform.machine().lower() == "amd64"
    return (sys.platform == "linux" and platform.machine().lower() == "x86_64"
            and platform.freedesktop_os_release().get("ID") == "altlinux")


def _inspect_built_alt_pair(paths: list[Path], version: str, revision: str) -> tuple[list[dict], dict]:
    """Verify builder output before handing the pair to the publisher."""
    if len(paths) != 2:
        raise ValueError("Expected the Core and UserSensor RPM pair")
    native = linux_native_verifier
    pair = {}
    outputs = []
    for path in paths:
        fingerprint = _fingerprint(path, native.MAX_RPM)
        query = "%{NAME}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{EPOCH}"
        package, rpm_version, release, arch, epoch = native.run(
            ["/usr/bin/rpm", "-qp", "--qf", query, str(path)]
        ).decode().split("\t")
        if (package not in native.NATIVE_PATHS or package in pair or rpm_version != version
                or not re.fullmatch(r"[A-Za-z0-9._]+", release) or arch != "x86_64" or epoch not in {"(none)", "0"}
                or path.name != f"{package}-{version}-{release}.{arch}.rpm"):
            raise ValueError(f"Unexpected ALT build RPM identity: {path.name}")
        with tempfile.TemporaryFile() as payload:
            native.run(["/usr/bin/rpm2cpio", str(path)], output_file=payload, limit=native.MAX_PAYLOAD, timeout=90)
            files, metadata = native.read_cpio(payload)
        source_path = native.NATIVE_PATHS[package]
        source = metadata.get(source_path)
        if source is None:
            raise ValueError(f"ALT RPM is missing its native source manifest: {path.name}")
        del files[source_path]
        core_manifest = metadata.get(f"/opt/endpoint-agent/versions/{version}/manifest.json")
        digest = hashlib.sha256(core_manifest).hexdigest() if core_manifest is not None else None
        source_revision, manifest_sha = native.inspect_source(source, package, version, files,
                                                              core_manifest_digest=digest)
        if (source_revision != revision or
                (core_manifest is not None and native._json(core_manifest).get("source_revision") != revision)):
            raise ValueError(f"ALT RPM source differs from the bound revision: {path.name}")
        pair[package] = (release, manifest_sha)
        if package == "endpoint-agent":
            setup = files.get("/usr/lib/endpoint-agent-setup/endpoint-agent-setup")
            if setup is None or setup["mode"] != "0755":
                raise ValueError("ALT Core RPM is missing the executable native Setup")
            setup_sha = setup["sha256"]
        signing_content = signing_content_sha256(path, unsigned_only=True)
        if fingerprint != _fingerprint(path, native.MAX_RPM):
            raise ValueError(f"ALT RPM changed while checking build output: {path.name}")
        outputs.append({**fingerprint, "path": path.name, "signing_content_sha256": signing_content})
    if len(set(pair.values())) != 1:
        raise ValueError("ALT Core and UserSensor must share the release and the same native source manifest")
    return outputs, {"frozen_manifest_sha256": manifest_sha, "setup_sha256": setup_sha}


def inspect_unsigned_alt_build(receipt_path: Path, binding: dict) -> str:
    if not _build_host("alt"):
        raise ValueError("Record the unsigned ALT build on its ALT x64 build worker")
    with receipt_path.open("rb") as stream:
        raw = stream.read(MAX_METADATA + 1)
    if len(raw) > MAX_METADATA:
        raise ValueError("ALT build receipt exceeds its size limit")
    receipt = read_build_receipt(raw, binding)
    paths = sorted(receipt_path.parent.glob("*.rpm"))
    outputs, native = _inspect_built_alt_pair(paths, binding["version"], binding["build_revision"])
    digest = hashlib.sha256(raw).hexdigest()
    if (receipt.get("outputs") != outputs or receipt.get("alt_native") != native
            or _fingerprint(receipt_path, MAX_METADATA)["sha256"] != digest):
        raise ValueError("ALT build receipt differs from the unsigned RPM pair")
    return digest


def _run_builder(command, root: Path, output: Path, environment: dict, *, recreates_output: bool) -> int:
    log_path = output / "builder.log"
    # WiX recreates its entire work directory. Keep the open log and the
    # exclusive output claim in a sibling until the native builder exits.
    owner = output.with_name(f".{output.name}.qualification-build") if recreates_output else output
    owner.mkdir(parents=True, exist_ok=False)
    active_log = owner / "builder.log"
    try:
        if recreates_output:
            output.mkdir(exist_ok=False)
        with active_log.open("xb") as log:
            status = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                    env=environment, check=False)
        return status.returncode
    finally:
        if recreates_output:
            if active_log.is_file():
                output.mkdir(exist_ok=True)
                active_log.rename(log_path)
            owner.rmdir()


def build(args: argparse.Namespace) -> dict:
    root, output = args.repo_root.resolve(), args.output_root.resolve()
    if output.is_relative_to(root):
        raise ValueError("Qualification build output must be outside the source checkout")
    reserved = agent_reservations.reservation_status(args)
    if reserved["platform"] not in (args.platform, "both"):
        raise ValueError("Platform is outside the reservation")
    if args.platform in reserved.get("candidates", {}):
        raise ValueError("Candidate bytes already recorded; continue with the recorded artifact")
    revision = reserved.get("build_revision")
    if revision is None:
        raise ValueError("Bind the build source before qualifying it")
    _assert_source(root, revision)
    version = reserved["version"]
    inputs = _inputs(args.inputs)
    if "runtime_root" in inputs:
        _strings(inputs, {"runtime_root"}, {"runtime_root", "channel"})
    if args.observed_launcher is not None and not release_plan.VERSION.fullmatch(args.observed_launcher):
        raise ValueError("Observed launcher must be a numeric version triplet")
    if args.runtime_contract and args.platform != "alt":
        raise ValueError("Windows Core reads compatibility from the frozen runtime directory")
    contract_path = args.runtime_contract
    if args.platform == "windows" and "runtime_root" in inputs:
        contract_path = Path(inputs["runtime_root"]) / "endpoint-runtime-contract.json"
    contract = json.loads(contract_path.read_bytes()) if contract_path else None
    delivery = release_plan.plan(root, args.base, revision, args.platform, contract=contract,
                                 observed_launcher=args.observed_launcher)
    artifacts = [name for name in delivery["artifacts"] if name in BUILDERS]
    if delivery["unclassified"] or len(artifacts) != 1 or delivery["version"] != version:
        raise ValueError("Build requires one classified agent artifact for the reserved version")
    artifact, = artifacts
    compatibility = delivery["core_compatibility"]
    minimum = compatibility["minimum_launcher_version"] if compatibility else None
    if artifact == "windows_core_zip" and not minimum:
        raise ValueError("Windows Core build requires the authored runtime contract")
    command, paths = _recipe(root, artifact, output, version, revision, inputs, minimum)
    result = {
        "schema_version": 1, "state": "preview", "request_id": str(args.request_id), "platform": args.platform,
        "version": version, "build_revision": revision, "baseline_revision": delivery["baseline_revision"],
        "artifact": artifact, "builder": BUILDERS[artifact], "output_root": str(output),
        "delivery_state": delivery["state"], "core_compatibility": compatibility,
    }
    if not args.execute:
        return result

    if compatibility and compatibility["status"] == "below_minimum":
        raise ValueError("The observed launcher is below the candidate minimum")
    if not _build_host(args.platform):
        raise ValueError("Execute qualification builds on the selected platform's approved x64 build worker")
    environment = {**os.environ, "SOURCE_REVISION": revision}
    if artifact == "alt_native_rpm":
        environment["PYTHON"] = sys.executable
    exit_code = _run_builder(command, root, output, environment, recreates_output=artifact == "windows_full_setup")
    if exit_code:
        raise ValueError(f"Canonical builder exited {exit_code}; see {output / 'builder.log'}")
    _assert_source(root, revision)
    if artifact == "alt_native_rpm":
        outputs, result["alt_native"] = _inspect_built_alt_pair(sorted(output.glob("*.rpm")), version, revision)
    else:
        outputs = [{**_fingerprint(path), "path": path.relative_to(output).as_posix()} for path in paths]
    result.update(state="built", outputs=outputs)
    (output / "qualification-build.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result
