"""Run the selected canonical builder from a bound release checkout."""

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from uuid import UUID

from tools.release import agent_reservations, compatibility_matrix, release_plan
from tools.release.agent_candidate_artifacts import _fingerprint, verify_recorded_candidate


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
    # An output slot has a single owner. Preserve partial build outputs and logs on failure.
    output.mkdir(parents=True, exist_ok=False)
    environment = {**os.environ, "SOURCE_REVISION": revision}
    if artifact == "alt_native_rpm":
        environment["PYTHON"] = sys.executable
    log_path = output / "builder.log"
    with log_path.open("xb") as log:
        status = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, env=environment, check=False)
    if status.returncode:
        raise ValueError(f"Canonical builder exited {status.returncode}; see {log_path}")
    _assert_source(root, revision)
    if artifact == "alt_native_rpm":
        paths = sorted(output.glob("*.rpm"))
        if len(paths) != 2:
            raise ValueError("Expected the Core and UserSensor RPM pair")
    result.update(state="built", outputs=[{**_fingerprint(path), "path": path.relative_to(output).as_posix()}
                                         for path in paths])
    (output / "qualification-build.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result
