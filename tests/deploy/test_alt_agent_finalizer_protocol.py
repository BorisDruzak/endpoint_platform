"""End-to-end contract tests for the root-controlled ALT claim finalizer.

The real installer intentionally exposes no path override.  These tests run a
temporary copy with the same fixed-path protocol rewritten to a private temp
root.  The real file owner, mode, path and request validators execute in Bash.
The harness supplies an isolated account lookup executable because the Windows
developer workstation has no ``endpoint-agent`` system account.

Linux runtime validation of actual symlinks is exercised whenever Git Bash can
create them. Git Bash on the operator Windows filesystem cannot represent the
strict POSIX modes required by the installer, so a test-copy metadata seam
supplies those values to the real Bash validators. Production always uses
native ``stat`` and the shell's native ``-L`` check.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "deploy" / "agent" / "alt" / "install-endpoint-agent.sh"

_PRODUCTION_METADATA_HELPERS = """file_owner_uid() {
    stat -c %u -- "$1"
}

file_owner_gid() {
    stat -c %g -- "$1"
}

file_mode() {
    stat -c %a -- "$1"
}"""

_WINDOWS_METADATA_SEAM = """file_owner_uid() {
    case "${ENDPOINT_AGENT_TEST_SCENARIO:-}" in
        claim-owner) [[ "$1" == *provisioning-claim ]] && { printf '999999\\n'; return; } ;;
        request-owner) [[ "$1" == *claim-removal-request.json ]] && { printf '999999\\n'; return; } ;;
        credential-owner) [[ "$1" == *device-credential ]] && { printf '999999\\n'; return; } ;;
    esac
    id -u
}

file_owner_gid() { id -g; }

file_mode() {
    case "$1" in
        */var/lib/endpoint-agent|*/var/log/endpoint-agent) printf '750\\n' ;;
        */etc/systemd/system/endpoint-agent.service) printf '644\\n' ;;
        */etc/endpoint-agent) printf '755\\n' ;;
        */provisioning-claim)
            [[ "${ENDPOINT_AGENT_TEST_SCENARIO:-}" == claim-mode ]] && printf '644\\n' || printf '600\\n'
            ;;
        */claim-removal-request.json)
            [[ "${ENDPOINT_AGENT_TEST_SCENARIO:-}" == request-mode ]] && printf '644\\n' || printf '600\\n'
            ;;
        */device-credential)
            [[ "${ENDPOINT_AGENT_TEST_SCENARIO:-}" == credential-mode ]] && printf '644\\n' || printf '600\\n'
            ;;
        *) printf '755\\n' ;;
    esac
}"""


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
    source = source.replace(
        "/etc/systemd/system/$SERVICE_NAME",
        "__TEST_ROOT__/etc/systemd/system/$SERVICE_NAME",
    )
    for production_parent, test_parent in (
        ("/opt", "__TEST_ROOT__/opt"),
        ("/etc/systemd/system", "__TEST_ROOT__/etc/systemd/system"),
        ("/etc/systemd", "__TEST_ROOT__/etc/systemd"),
        ("/etc", "__TEST_ROOT__/etc"),
        ("/var/lib", "__TEST_ROOT__/var/lib"),
        ("/var/log", "__TEST_ROOT__/var/log"),
        ("/var", "__TEST_ROOT__/var"),
    ):
        source = source.replace(
            f"require_trusted_root_parent {production_parent}",
            f"require_trusted_root_parent {test_parent}",
        )
    # Windows Git Bash cannot elevate the pytest process.  This is the only
    # control-flow seam: all file/path/owner/mode validators stay real Bash.
    source = re.sub(
        r"require_root\(\) \{\n.*?\n\}",
        "require_root() { :; }",
        source,
        count=1,
        flags=re.DOTALL,
    )
    # The production expectation remains root:root.  The copied installer has
    # no privileged test process, so its trusted fixture owner/group are the
    # real current Git-Bash account.  No destination or file validator is
    # replaced; they still read ``stat`` and reject mismatches.
    source = source.replace(
        "root_owner_uid() {\n    id -u root\n}",
        "root_owner_uid() { id -u; }",
    ).replace(
        "root_owner_gid() {\n    id -g root\n}",
        "root_owner_gid() { id -g; }",
    )
    source = source.replace(_PRODUCTION_METADATA_HELPERS, _WINDOWS_METADATA_SEAM)
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
mkdir -p "$root/opt" "$root/etc/endpoint-agent" "$root/etc/systemd/system" "$root/var/lib/endpoint-agent" "$root/var/log/endpoint-agent"
mkdir -p "$root/bin"
cat > "$root/etc/systemd/system/endpoint-agent.service" <<'UNIT'
[Service]
Environment=ENDPOINT_AGENT_ENROLLMENT_REQUIRED=1
LoadCredential=endpoint-agent-config:/etc/endpoint-agent/config.yaml
LoadCredential=endpoint-agent-ca:/etc/endpoint-agent/ca.crt
LoadCredential=endpoint-enrollment-claim:/etc/endpoint-agent/provisioning-claim
Environment=ENDPOINT_AGENT_CONFIG=%d/endpoint-agent-config
Environment=ENDPOINT_AGENT_CA_FILE=%d/endpoint-agent-ca
Environment=ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE=%d/endpoint-enrollment-claim
UNIT
chmod 644 "$root/etc/systemd/system/endpoint-agent.service"
export ENDPOINT_AGENT_TEST_UID=$(id -u)
export ENDPOINT_AGENT_TEST_GID=$(id -g)
export ENDPOINT_AGENT_TEST_SCENARIO={scenario!r}
cat > "$root/bin/getent" <<'GETENT'
#!/usr/bin/env bash
if [[ "$1" == passwd && "$2" == endpoint-agent ]]; then
  printf 'endpoint-agent:x:999:%s::/nonexistent:/usr/sbin/nologin\\n' "$ENDPOINT_AGENT_TEST_GID"
  exit 0
fi
if [[ "$1" == group && "$2" == endpoint-agent ]]; then
  printf 'endpoint-agent:x:%s:\\n' "$ENDPOINT_AGENT_TEST_GID"
  exit 0
fi
exit 2
GETENT
cat > "$root/bin/id" <<'ID'
#!/usr/bin/env bash
if [[ "$1" == -u && "$2" == endpoint-agent ]]; then
  printf '%s\\n' "$ENDPOINT_AGENT_TEST_UID"
  exit 0
fi
exec /usr/bin/id "$@"
ID
chmod 700 "$root/bin/getent" "$root/bin/id"
cat > "$root/bin/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
[[ "$1" == daemon-reload ]]
SYSTEMCTL
chmod 700 "$root/bin/systemctl"
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
  claim-mode) chmod 644 "$claim" ;;
  request-mode) request_mode=644 ;;
  credential-mode) chmod 644 "$credential" ;;
  claim-owner|request-owner|credential-owner) ;;
  claim-symlink) rm -f "$claim"; ln -s "$credential" "$claim" ;;
  request-symlink) request_symlink=true ;;
  credential-symlink) mv "$credential" "$credential.real"; ln -s "$credential.real" "$credential"; digest=$(sha256sum -- "$credential.real" | awk '{{ print $1 }}') ;;
  parent-symlink) mkdir "$root/claim-parent"; mv "$claim" "$root/claim-parent/provisioning-claim"; rm -rf "$root/etc/endpoint-agent"; ln -s "$root/claim-parent" "$root/etc/endpoint-agent" ;;
  already-finalized) rm -f "$claim" "$request" ;;
  *) exit 97 ;;
esac
if [[ {scenario!r} != already-finalized ]]; then
  printf '{{"claim_credential_name":"endpoint-enrollment-claim","credential_path":"%s","credential_sha256":"%s","device_id":"9c83f6de-3435-4fc3-a7e0-7bcddc744f3b","schema_version":"endpoint_claim_removal_request_v1"}}' "$credential" "$digest" > "$request"
  chmod "${{request_mode:-600}}" "$request"
  if [[ "${{request_symlink:-false}}" == true ]]; then
    mv "$request" "$request.real"
    ln -s "$request.real" "$request"
  fi
fi
set +e
PATH="$root/bin:$PATH" bash "$root/installer" --finalize-handoff
status=$?
set -e
unit="$root/etc/systemd/system/endpoint-agent.service"
printf 'status=%s claim=%s request=%s credential=%s unit_claim=%s unit_handoff=%s unit_gateway=%s\n' "$status" "$([[ -e "$claim" || -L "$claim" ]] && echo present || echo absent)" "$([[ -e "$request" || -L "$request" ]] && echo present || echo absent)" "$([[ -e "$credential" || -L "$credential" ]] && echo present || echo absent)" "$(grep -c '^LoadCredential=endpoint-enrollment-claim:' "$unit" || true)" "$(grep -c '^Environment=ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE=' "$unit" || true)" "$(grep -c '^Environment=ENDPOINT_AGENT_GATEWAY_READY=1$' "$unit" || true)"
exit 0
""",
        encoding="utf-8",
    )
    harness.chmod(0o700)
    return subprocess.run(
        ["bash", harness.as_posix()], capture_output=True, text=True, check=True
    )


def _supports_shell_visible_symlinks(tmp_path: Path) -> bool:
    target = tmp_path / "symlink-target"
    link = tmp_path / "symlink-link"
    target.write_text("target", encoding="utf-8")
    return subprocess.run(
        ["bash", "-lc", "ln -s symlink-target symlink-link && [[ -L symlink-link ]]"],
        cwd=tmp_path,
        check=False,
    ).returncode == 0


def test_verified_bootstrap_request_removes_only_the_exact_claim_and_request(
    tmp_path: Path,
) -> None:
    result = _run_harness(tmp_path, "success")

    assert "status=0 claim=absent request=absent credential=present" in result.stdout
    assert "unit_claim=0 unit_handoff=0 unit_gateway=1" in result.stdout


def test_invalid_request_or_credential_keeps_the_claim_and_request_for_recovery(
    tmp_path: Path,
) -> None:
    for scenario in ("invalid-request", "credential-failure"):
        result = _run_harness(tmp_path, scenario)
        assert (
            "status=1 claim=present request=present credential=present" in result.stdout
        )


@pytest.mark.parametrize(
    "scenario",
    (
        "claim-mode",
        "request-mode",
        "credential-mode",
        "claim-owner",
        "request-owner",
        "credential-owner",
    ),
)
def test_finalizer_rejects_wrong_owner_or_mode_without_removing_recovery_state(
    tmp_path: Path, scenario: str
) -> None:
    result = _run_harness(tmp_path, scenario)

    assert "status=1 claim=present request=present credential=present" in result.stdout


@pytest.mark.parametrize(
    "scenario",
    ("claim-symlink", "request-symlink", "credential-symlink", "parent-symlink"),
)
def test_finalizer_rejects_leaf_and_parent_symlinks_without_unlinking(
    tmp_path: Path, scenario: str
) -> None:
    if not _supports_shell_visible_symlinks(tmp_path):
        pytest.skip(
            "Windows Git Bash does not expose test symlinks to -L; "
            "requires the isolated Linux finalizer harness"
        )
    result = _run_harness(tmp_path, scenario)

    assert "status=1 claim=present request=present credential=present" in result.stdout


def test_finalizer_is_idempotent_after_a_completed_claim_removal(
    tmp_path: Path,
) -> None:
    result = _run_harness(tmp_path, "already-finalized")

    assert "status=0 claim=absent request=absent credential=present" in result.stdout
