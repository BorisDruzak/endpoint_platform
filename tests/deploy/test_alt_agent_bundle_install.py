"""Task 2 contracts for verified ALT release-bundle installation.

The Linux-only behavioural harness belongs to Task 3.  These tests pin the
installer's security and rollback boundary without executing host mutations.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "deploy" / "agent" / "alt" / "install-endpoint-agent.sh"
SERVICE = ROOT / "deploy" / "agent" / "alt" / "endpoint-agent.service"
LINUX_HARNESS = ROOT / "tests" / "deploy" / "verify_alt_agent_bundle_linux_harness.sh"
PYTHON = Path(__import__("sys").executable).as_posix()


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _body(text: str, function: str, next_function: str) -> str:
    return text[text.index(f"{function}() {{") : text.index(f"{next_function}() {{")]


def _installer_function_library() -> str:
    """Return the real installer helpers with only the CLI dispatcher removed."""
    source = _text(INSTALLER)
    source = source.replace(
        "/opt/endpoint-agent", "__TEST_ROOT__/opt/endpoint-agent"
    )
    return source.split("while [[ $# -gt 0 ]]; do", maxsplit=1)[0]


def _run_selection_harness(tmp_path: Path, failure: str) -> subprocess.CompletedProcess[str]:
    library = tmp_path / "installer-lib.template"
    library.write_text(_installer_function_library(), encoding="utf-8")
    harness = tmp_path / "selection-harness.sh"
    harness.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
root=$(mktemp -d /tmp/endpoint-selection.XXXXXX)
trap 'rm -rf -- "$root"' EXIT
sed "s|__TEST_ROOT__|$root|g" {library.as_posix()!s} > "$root/installer-lib"
mkdir -p "$root/bin"
cat > "$root/bin/python3" <<'PYTHON3'
#!/usr/bin/env bash
exec "{PYTHON}" "$@"
PYTHON3
chmod 700 "$root/bin/python3"
cat > "$root/bin/mv" <<'MV'
#!/usr/bin/env bash
source=${{@: -2:1}}
target=${{@: -1}}
printf 'mv:%s:%s\\n' "$source" "$target" >> "$SELECTION_LOG"
case "${{FAIL_MV_STAGE:-}}:$source:$target" in
  backup-launcher:*/endpoint-agent/launcher:*/previous-selection/launcher|\
  backup-current:*/endpoint-agent/current.json:*/previous-selection/current.json|\
  publish-launcher:*/new-launcher:*/endpoint-agent/launcher|\
  publish-current:*/new-current.secure:*/endpoint-agent/current.json)
    exit 1
    ;;
esac
exec /bin/mv "$@"
MV
chmod 700 "$root/bin/mv"
export PATH="$root/bin:$PATH"
export SELECTION_LOG="$root/selection.log"
export FAIL_MV_STAGE={failure!r}
source "$root/installer-lib"
fsync_tree() {{ printf 'fsync-tree:%s\\n' "$1" >> "$SELECTION_LOG"; }}
fsync_path() {{ printf 'fsync-path:%s\\n' "$1" >> "$SELECTION_LOG"; }}
release_stage="$root/release-stage"
mkdir -p "$INSTALL_ROOT/versions/old/pc_agent" "$release_stage"
printf 'old-launcher' > "$INSTALL_ROOT/launcher"
printf '{{"schema_version":1,"version":"old","source_revision":"oldrev"}}\\n' > "$INSTALL_ROOT/current.json"
printf 'old-agent' > "$INSTALL_ROOT/versions/old/pc_agent/pc_agent"
mkdir -p "$INSTALL_ROOT/versions/new/pc_agent"
release_version_target="$INSTALL_ROOT/versions/new"
release_version_was_new=true
printf 'new-launcher' > "$release_stage/new-launcher"
printf '{{"schema_version":1,"version":"new","source_revision":"newrev"}}\\n' > "$release_stage/new-current.secure"
if publish_release_selection "$release_stage/new-launcher" "$release_stage/new-current"; then
  printf 'unexpected-success\\n'
  exit 2
fi
rollback_release_selection
[[ "$(<"$INSTALL_ROOT/launcher")" == old-launcher ]]
[[ "$(<"$INSTALL_ROOT/current.json")" == '{{"schema_version":1,"version":"old","source_revision":"oldrev"}}' ]]
[[ -f "$INSTALL_ROOT/versions/old/pc_agent/pc_agent" ]]
[[ ! -e "$INSTALL_ROOT/versions/new" ]]
printf 'rollback-preserved:%s\\n' "{failure}"
""",
        encoding="utf-8",
    )
    harness.chmod(0o700)
    return subprocess.run(
        ["bash", harness.as_posix()], capture_output=True, text=True, check=False
    )


@pytest.mark.parametrize(
    "failure", ["backup-launcher", "backup-current", "publish-launcher", "publish-current"]
)
def test_injected_selector_move_failures_preserve_the_previous_complete_selection(
    tmp_path: Path, failure: str
) -> None:
    """Deleting an old selector without its backup would lose a working release."""
    result = _run_selection_harness(tmp_path, failure)

    assert result.returncode == 0, result.stderr
    assert f"rollback-preserved:{failure}" in result.stdout


def test_current_is_published_only_after_version_durability_boundaries(tmp_path: Path) -> None:
    """Publishing current before version fsync could select a non-durable release after crash."""
    library = tmp_path / "installer-lib.template"
    library.write_text(_installer_function_library(), encoding="utf-8")
    harness = tmp_path / "order-harness.sh"
    harness.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
root=$(mktemp -d /tmp/endpoint-selection-order.XXXXXX)
trap 'rm -rf -- "$root"' EXIT
sed "s|__TEST_ROOT__|$root|g" {library.as_posix()!s} > "$root/installer-lib"
mkdir -p "$root/bin"
cat > "$root/bin/python3" <<'PYTHON3'
#!/usr/bin/env bash
exec "{PYTHON}" "$@"
PYTHON3
chmod 700 "$root/bin/python3"
export PATH="$root/bin:$PATH"
source "$root/installer-lib"
fsync_tree() {{ printf 'tree:%s\\n' "$1"; }}
fsync_path() {{ printf 'path:%s\\n' "$1"; }}
mv() {{ local source=${{@: -2:1}} target=${{@: -1}}; printf 'mv:%s:%s\\n' "$source" "$target"; command mv "$@"; }}
release_stage="$root/stage"
release_version_target="$INSTALL_ROOT/versions/new"
release_version_was_new=true
mkdir -p "$release_stage" "$release_version_target/pc_agent" "$INSTALL_ROOT/versions/old/pc_agent"
printf old > "$INSTALL_ROOT/launcher"
printf '{{"schema_version":1,"version":"old","source_revision":"oldrev"}}\\n' > "$INSTALL_ROOT/current.json"
printf new > "$release_stage/new-launcher"
printf '{{"schema_version":1,"version":"new","source_revision":"newrev"}}\\n' > "$release_stage/new-current.secure"
publish_release_selection "$release_stage/new-launcher" "$release_stage/new-current"
""",
        encoding="utf-8",
    )
    harness.chmod(0o700)
    result = subprocess.run(
        ["bash", harness.as_posix()], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
    events = result.stdout.splitlines()
    current_move = next(
        index for index, event in enumerate(events) if event.endswith("/current.json")
    )
    assert events.index(next(event for event in events if event.endswith("/versions/new"))) < current_move
    assert events.index(next(event for event in events if event.endswith("/versions"))) < current_move


@pytest.mark.parametrize("difference", ["launcher", "manifest"])
def test_version_reuse_rejects_a_stored_bundle_with_different_full_identity(
    tmp_path: Path, difference: str
) -> None:
    """Comparing only pc_agent would silently reuse a colliding version label."""
    library = tmp_path / "installer-lib.template"
    library.write_text(_installer_function_library(), encoding="utf-8")
    harness = tmp_path / "identity-harness.sh"
    harness.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
root=$(mktemp -d /tmp/endpoint-identity.XXXXXX)
trap 'rm -rf -- "$root"' EXIT
sed "s|__TEST_ROOT__|$root|g" {library.as_posix()!s} > "$root/installer-lib"
mkdir -p "$root/bin"
cat > "$root/bin/python3" <<'PYTHON3'
#!/usr/bin/env bash
exec "{PYTHON}" "$@"
PYTHON3
chmod 700 "$root/bin/python3"
export PATH="$root/bin:$PATH"
source "$root/installer-lib"
mkdir -p "$root/stored/pc_agent" "$root/staged/pc_agent"
printf launcher-a > "$root/stored/launcher"
printf launcher-a > "$root/staged/launcher"
printf agent > "$root/stored/pc_agent/pc_agent"
printf agent > "$root/staged/pc_agent/pc_agent"
printf '{{"schema_version":1,"version":"v","source_revision":"first"}}\\n' > "$root/stored/manifest.json"
printf '{{"schema_version":1,"version":"v","source_revision":"first"}}\\n' > "$root/staged/manifest.json"
if [[ {difference!r} == launcher ]]; then printf launcher-b > "$root/staged/launcher"; else printf '{{"schema_version":1,"version":"v","source_revision":"second"}}\\n' > "$root/staged/manifest.json"; fi
if verify_existing_release_identity "$root/stored" "$root/staged"; then exit 1; else status=$?; fi
[[ "$status" -eq 1 ]]
""",
        encoding="utf-8",
    )
    harness.chmod(0o700)
    result = subprocess.run(
        ["bash", harness.as_posix()], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr


def test_digest_mismatch_is_rejected_before_service_account_creation() -> None:
    """Removing the verifier call would let a tampered payload reach ``useradd``."""
    installer = _text(INSTALLER)
    package = _body(installer, "install_package", "finalize_handoff")

    assert "verify_agent_bundle" in installer
    assert "hashlib.sha256" in installer
    assert package.index("verify_agent_bundle") < package.index("ensure_service_account")


def test_verifier_rejects_links_incomplete_and_unexpected_bundle_tree() -> None:
    """Weakening any tree check could make a manifest attest a different onedir tree."""
    installer = _text(INSTALLER)

    for required in (
        "schema_version",
        "source_revision",
        "manifest.json",
        "pc_agent/pc_agent",
        "symbolic link",
        "unexpected bundle entry",
        "missing manifest payload",
        "path traversal",
        "mode mismatch",
        "digest mismatch",
    ):
        assert required in installer


def test_installer_stages_and_reverifies_the_complete_bundle_before_selection() -> None:
    """Skipping staging verification could select files different from reviewed input."""
    installer = _text(INSTALLER)
    install = _body(installer, "install_atomically", "install_package")

    assert install.count("verify_agent_bundle") >= 1
    assert 'cp -a -- "$agent_bundle/." "$bundle_stage/"' in install
    assert 'mv -f "$version_stage" "$version_target"' in install
    assert 'publish_release_selection "$launcher_stage" "$current_stage"' in install


def test_failed_activation_restores_the_prior_complete_selection() -> None:
    """The behavioural injected-move checks below exercise these rollback helpers."""
    installer = _text(INSTALLER)

    for required in (
        "backup_previous_selection",
        "rollback_release_selection",
        "cleanup_release_backup",
    ):
        assert required in installer


def test_service_executes_the_stable_launcher_not_a_version_payload() -> None:
    """Pointing systemd at a versioned payload would bypass the durable selector."""
    service = _text(SERVICE)

    assert "ConditionPathExists=/opt/endpoint-agent/launcher" in service
    assert "ExecStart=/opt/endpoint-agent/launcher " in service
    assert "/versions/" not in service


def test_linux_harness_is_present_for_the_bundle_installation_scenarios() -> None:
    """The wrapper pins the isolated harness contract for a Linux test host."""
    assert LINUX_HARNESS.is_file(), "missing isolated ALT bundle Linux harness"
    text = _text(LINUX_HARNESS)

    for scenario in (
        "valid",
        "digest-mismatch",
        "bundle-symlink",
        "incomplete-onedir",
        "activation-failure-rollback",
        "idempotent-second-install",
    ):
        assert scenario in text


def test_linux_harness_proves_isolation_and_reaches_the_injected_restart_failure() -> None:
    """A generic failure must not be accepted as proof of activation rollback."""
    text = _text(LINUX_HARNESS)

    for required in (
        "assert_isolated_installer_copy",
        "snapshot_live_paths",
        "assert_live_paths_unchanged",
        "reset_systemctl_log",
        'grep -Fx -- "restart endpoint-agent.service"',
        "/opt/.endpoint-agent-stage",
        "require_trusted_root_parent /etc/systemd/system",
    ):
        assert required in text


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux shell semantics")
def test_linux_harness_executes_without_host_path_mutation() -> None:
    """Run the real isolated harness only where its shell/filesystem semantics exist."""
    if __import__("os").geteuid() != 0:
        pytest.skip("run the isolated installer harness with sudo on a Linux test host")

    result = subprocess.run(
        ["bash", LINUX_HARNESS.as_posix(), INSTALLER.as_posix()],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "ALT bundle Linux harness: all cases passed" in result.stdout
