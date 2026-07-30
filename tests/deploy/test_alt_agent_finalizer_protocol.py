"""End-to-end contract tests for the root-controlled ALT claim finalizer.

The real installer intentionally exposes no path override.  These tests run a
temporary copy with the same fixed-path protocol rewritten to a private temp
root and only fake the OS account/root checks that cannot be exercised by a
Windows developer workstation.  The actual request parsing, path validation,
credential proof and unlink sequence are executed by Bash.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "deploy" / "agent" / "alt" / "install-endpoint-agent.sh"


def _testable_installer() -> str:
    source = INSTALLER.read_text(encoding="utf-8")
    source = source.replace("/opt/endpoint-agent", "__TEST_ROOT__/opt/endpoint-agent")
    source = source.replace(
        "/var/lib/endpoint-agent", "__TEST_ROOT__/var/lib/endpoint-agent"
    )
    source = source.replace("/etc/endpoint-agent", "__TEST_ROOT__/etc/endpoint-agent")
    source = source.replace(
        "/var/log/endpoint-agent", "__TEST_ROOT__/var/log/endpoint-agent"
    )
    source = re.sub(
        r"require_root\(\) \{\n.*?\n\}",
        "require_root() { :; }",
        source,
        count=1,
        flags=re.DOTALL,
    )
    source = re.sub(
        r"validate_existing_service_account\(\) \{\n.*?\n\}\n\nrequire_service_secret_file",
        "validate_existing_service_account() { :; }\n\nrequire_service_secret_file",
        source,
        count=1,
        flags=re.DOTALL,
    )
    source = re.sub(
        r"require_service_secret_file\(\) \{\n.*?\n\}\n\nrequire_opaque_permanent_credential",
        'require_service_secret_file() { require_regular_file "$1" "$2"; [[ -s "$2" ]] || die "$1 must not be empty"; }\n\nrequire_opaque_permanent_credential',
        source,
        count=1,
        flags=re.DOTALL,
    )
    source = re.sub(
        r"require_root_secret_file\(\) \{\n.*?\n\}\n\nis_nonlogin_shell",
        'require_root_secret_file() { require_regular_file "$1" "$2"; [[ -s "$2" ]] || die "$1 must not be empty"; }\n\nis_nonlogin_shell',
        source,
        count=1,
        flags=re.DOTALL,
    )
    return source


def _run_harness(tmp_path: Path, scenario: str) -> subprocess.CompletedProcess[str]:
    installer = tmp_path / "install-endpoint-agent.sh"
    installer.write_text(_testable_installer(), encoding="utf-8")
    installer.chmod(0o700)
    harness = tmp_path / "run-finalizer.sh"
    harness.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
root=$(mktemp -d /tmp/endpoint-finalizer.XXXXXX)
trap 'rm -rf "$root"' EXIT
sed "s|__TEST_ROOT__|$root|g" {installer.as_posix()!s} > "$root/installer"
chmod 700 "$root/installer"
mkdir -p "$root/etc/endpoint-agent" "$root/var/lib/endpoint-agent"
credential="$root/var/lib/endpoint-agent/device-credential"
request="$root/var/lib/endpoint-agent/claim-removal-request.json"
claim="$root/etc/endpoint-agent/provisioning-claim"
printf '%s' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > "$credential"
printf '%s' 'ic_0123456789abcdef0123456789abcdef.abcdefghijklmnopqrstuvwxyzABCDEFG' > "$claim"
chmod 600 "$credential" "$claim"
digest=$(sha256sum -- "$credential" | awk '{{ print $1 }}')
case {scenario!r} in
  success) ;;
  invalid-request) digest=$(printf '%064d' 0) ;;
  credential-failure) printf '%s' short > "$credential"; digest=$(sha256sum -- "$credential" | awk '{{ print $1 }}') ;;
  already-finalized) rm -f "$claim" "$request" ;;
  *) exit 97 ;;
esac
if [[ {scenario!r} != already-finalized ]]; then
  printf '{{"claim_credential_name":"endpoint-enrollment-claim","credential_path":"%s","credential_sha256":"%s","device_id":"9c83f6de-3435-4fc3-a7e0-7bcddc744f3b","schema_version":"endpoint_claim_removal_request_v1"}}' "$credential" "$digest" > "$request"
  chmod 600 "$request"
fi
set +e
bash "$root/installer" --finalize-handoff
status=$?
set -e
printf 'status=%s claim=%s request=%s credential=%s\n' "$status" "$([[ -e "$claim" || -L "$claim" ]] && echo present || echo absent)" "$([[ -e "$request" || -L "$request" ]] && echo present || echo absent)" "$([[ -e "$credential" || -L "$credential" ]] && echo present || echo absent)"
exit 0
""",
        encoding="utf-8",
    )
    harness.chmod(0o700)
    return subprocess.run(
        ["bash", harness.as_posix()], capture_output=True, text=True, check=True
    )


def test_verified_bootstrap_request_removes_only_the_exact_claim_and_request(
    tmp_path: Path,
) -> None:
    result = _run_harness(tmp_path, "success")

    assert "status=0 claim=absent request=absent credential=present" in result.stdout


def test_invalid_request_or_credential_keeps_the_claim_and_request_for_recovery(
    tmp_path: Path,
) -> None:
    for scenario in ("invalid-request", "credential-failure"):
        result = _run_harness(tmp_path, scenario)
        assert (
            "status=1 claim=present request=present credential=present" in result.stdout
        )


def test_finalizer_is_idempotent_after_a_completed_claim_removal(
    tmp_path: Path,
) -> None:
    result = _run_harness(tmp_path, "already-finalized")

    assert "status=0 claim=absent request=absent credential=present" in result.stdout
