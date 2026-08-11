"""Contract checks for the portable external-controller ALT rollout role."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
ROLE_ROOT = ROOT / "deploy" / "ansible" / "roles" / "endpoint_agent_alt"
TASKS_PATH = ROLE_ROOT / "tasks" / "main.yml"
README_PATH = ROLE_ROOT / "README.md"


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
