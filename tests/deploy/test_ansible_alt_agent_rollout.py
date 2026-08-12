"""Contract checks for the portable external-controller ALT rollout role."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
ROLE_ROOT = ROOT / "deploy" / "ansible" / "roles" / "endpoint_agent_alt"
TASKS_PATH = ROLE_ROOT / "tasks" / "main.yml"
README_PATH = ROLE_ROOT / "README.md"
PLAYBOOK_PATH = ROOT / "deploy" / "ansible" / "playbooks" / "endpoint_agent_alt_pilot.yml"


def _tasks() -> list[dict[str, object]]:
    return yaml.safe_load(TASKS_PATH.read_text(encoding="utf-8"))


def _walk_tasks(items: list[object]) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        found.append(item)
        for key in ("block", "always"):
            nested = item.get(key)
            if isinstance(nested, list):
                found.extend(_walk_tasks(nested))
    return found


def test_role_protects_controller_secrets_and_revokes_campaigns() -> None:
    """Dropping redaction or always-cleanup would leak authority after a failed rollout."""
    tasks = _tasks()
    all_tasks = _walk_tasks(tasks)
    secret_tasks = [
        task
        for task in all_tasks
        if "claim" in str(task.get("name", "")).lower()
        or "campaign" in str(task.get("name", "")).lower()
    ]

    assert secret_tasks
    assert all(task.get("no_log") is True for task in secret_tasks)
    assert any(isinstance(task.get("always"), list) for task in tasks)


def test_role_uses_named_tls_gateway_and_documents_vault_only() -> None:
    """Replacing DNS/TLS validation or storing a claim in Vault would violate deployment trust."""
    tasks = _tasks()
    rendered = TASKS_PATH.read_text(encoding="utf-8")
    readme = README_PATH.read_text(encoding="utf-8")

    uri_tasks = [task["ansible.builtin.uri"] for task in _walk_tasks(tasks) if "ansible.builtin.uri" in task]
    assert uri_tasks
    assert all(uri.get("validate_certs") is True for uri in uri_tasks)
    assert "https://endpoint.sosnadmin.local" in rendered
    assert "vault_endpoint_provisioning_token" in readme
    assert "endpoint_install_claim:" not in readme


def test_role_requires_a_clean_host_and_removes_claim_on_failure() -> None:
    """A rerun must not consume a claim for an already-enrolled host or leave it behind."""
    all_tasks = _walk_tasks(_tasks())
    task_names = [str(task.get("name", "")) for task in all_tasks]

    assert any("clean Endpoint Agent host" in name for name in task_names)
    assert any("local one-time claim" in name.lower() for name in task_names)
    assert any("RPM tools" in name for name in task_names)


def test_role_checks_rpm_tool_presence_without_calling_rpm2cpio_help() -> None:
    """ALT's rpm2cpio returns 1 for --help even when the binary is installed."""
    rendered = TASKS_PATH.read_text(encoding="utf-8")

    assert "rpm2cpio --help" not in rendered
    assert "command -v {{ item }}" in rendered


def test_role_requires_explicit_safe_recovery_for_a_failed_pre_stage() -> None:
    """A failed pre-stage may be retried only after proving no enrollment material exists."""
    rendered = TASKS_PATH.read_text(encoding="utf-8")
    defaults = yaml.safe_load((ROLE_ROOT / "defaults" / "main.yml").read_text(encoding="utf-8"))

    assert defaults["endpoint_agent_recover_partial_install"] is False
    assert "endpoint_agent_recover_partial_install | bool" in rendered
    assert "rpm -e endpoint-agent" in rendered
    assert "! test -e /var/lib/endpoint-agent/device-credential" in rendered
    assert "Remove verified unmanaged legacy Endpoint Agent service shadow" in rendered
    assert "! test -e /etc/systemd/system/endpoint-agent.service" in rendered


def test_role_renders_campaign_expiry_without_invalid_percent_escaping() -> None:
    """The controller must form a valid GNU date lookup before calling Gateway."""
    rendered = TASKS_PATH.read_text(encoding="utf-8")

    assert "%%Y" not in rendered
    assert "~ endpoint_agent_campaign_lifetime_minutes ~" in rendered


def test_role_writes_the_claim_without_trailing_whitespace() -> None:
    """The RPM rejects a systemd claim whose bytes contain a trailing newline."""
    tasks = _walk_tasks(_tasks())
    claim_task = next(task for task in tasks if task.get("name") == "Install one-time Endpoint Agent claim")

    assert claim_task["ansible.builtin.copy"]["content"] == "{{ endpoint_agent_install_claim.json.claim }}"


def test_role_pre_stages_rpm_before_issuing_claim_and_uses_official_helper() -> None:
    """The first-install flow must get the fingerprint from the reviewed RPM itself."""
    rendered = TASKS_PATH.read_text(encoding="utf-8")

    assert rendered.index("Install reviewed Endpoint Agent RPM before enrollment") < rendered.index(
        "Create per-host rollout campaign"
    )
    assert "/usr/lib/endpoint-agent/endpoint-agent-fingerprint --enrollment-binding" in rendered
    assert rendered.index("Install non-secret Endpoint Agent configuration") < rendered.index(
        "Create per-host rollout campaign"
    )
    assert "endpoint_agent_enrollment_binding.hardware_fingerprint" in rendered
    assert "endpoint_agent_enrollment_binding.installation_id" in rendered
    assert "/etc/credstore/endpoint-enrollment-claim" in rendered
    assert "/etc/endpoint-agent/bootstrap/provisioning-claim" not in rendered
    assert "endpoint-agent-finalize.path" not in rendered


def test_role_renders_fixed_https_configuration_without_a_claim() -> None:
    """The agent configuration is non-secret and cannot embed bootstrap authority."""
    template = (ROLE_ROOT / "templates" / "config.yaml.j2").read_text(encoding="utf-8")

    assert "https://endpoint.sosnadmin.local" in template
    assert "/etc/endpoint-agent/ca.crt" in template
    assert "/var/lib/endpoint-agent/device-credential" in template
    assert "provisioning-claim" not in template
    assert "vault_" not in template


def test_example_pins_a_complete_lowercase_rpm_sha256() -> None:
    """A malformed example digest would make every controller fail before rollout."""
    example = yaml.safe_load(
        (ROOT / "deploy" / "ansible" / "group_vars" / "endpoint_agent_alt_pilot.example.yml").read_text(
            encoding="utf-8"
        )
    )

    assert isinstance(example["endpoint_agent_rpm_sha256"], str)
    assert len(example["endpoint_agent_rpm_sha256"]) == 64
    assert example["endpoint_agent_rpm_sha256"].islower()
    assert all(character in "0123456789abcdef" for character in example["endpoint_agent_rpm_sha256"])


def test_readme_documents_pre_stage_before_claim() -> None:
    """Operators must not attempt to obtain a claim before RPM fingerprinting."""
    readme = README_PATH.read_text(encoding="utf-8")

    assert "before its first service start" in readme
    assert "endpoint-agent-fingerprint" in readme


def test_pilot_playbook_explicitly_loads_controller_vault() -> None:
    """The standalone pilot play must see the existing controller Vault variables."""
    playbook = yaml.safe_load(PLAYBOOK_PATH.read_text(encoding="utf-8"))

    assert playbook[0]["vars_files"] == ["../group_vars/vault.yml"]
