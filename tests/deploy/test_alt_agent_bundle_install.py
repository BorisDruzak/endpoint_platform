"""Task 2 contracts for verified ALT release-bundle installation.

The Linux-only behavioural harness belongs to Task 3.  These tests pin the
installer's security and rollback boundary without executing host mutations.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "deploy" / "agent" / "alt" / "install-endpoint-agent.sh"
SERVICE = ROOT / "deploy" / "agent" / "alt" / "endpoint-agent.service"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _body(text: str, function: str, next_function: str) -> str:
    return text[text.index(f"{function}() {{") : text.index(f"{next_function}() {{")]


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
    assert 'mv -f "$launcher_stage" "$LAUNCHER_TARGET"' in install
    assert 'mv -f "$version_stage" "$version_target"' in install
    assert 'mv -f "$current_stage.secure" "$CURRENT_TARGET"' in install


def test_failed_activation_restores_the_prior_complete_selection() -> None:
    """Removing rollback would leave launcher/current pointing at an unactivated release."""
    installer = _text(INSTALLER)
    package = _body(installer, "install_package", "finalize_handoff")

    for required in (
        "backup_previous_selection",
        "rollback_release_selection",
        "cleanup_release_backup",
    ):
        assert required in installer
    assert package.index("rollback_release_selection") < package.index("die 'service did not become active'")


def test_service_executes_the_stable_launcher_not_a_version_payload() -> None:
    """Pointing systemd at a versioned payload would bypass the durable selector."""
    service = _text(SERVICE)

    assert "ConditionPathExists=/opt/endpoint-agent/launcher" in service
    assert "ExecStart=/opt/endpoint-agent/launcher " in service
    assert "/versions/" not in service
