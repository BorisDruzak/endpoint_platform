"""
Точка входа launcher: запуск текущей версии агента, при exit 42 или наличии pending_update — установка обновления.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# Минимальные зависимости; installer импортируется здесь
from pc_agent.core.runtime_paths import resolve_data_root, resolve_install_root
from pc_agent.launcher.installer import apply_update, _find_agent_binary
from pc_agent.alt_update_installer import (
    apply_alt_rollback,
    apply_alt_update,
    write_alt_rollback_request,
)
from pc_agent.version import AGENT_VERSION, EXIT_UPDATE_PENDING


IMMEDIATE_CRASH_WINDOW_SEC = 20.0
IMMEDIATE_CRASH_RETRY_LIMIT = 3


def alt_update_mode_enabled() -> bool:
    """Keep the ALT updater opt-in so desktop installs retain their workflow."""
    return os.environ.get("ENDPOINT_AGENT_ALT_UPDATE_MODE") == "1"


def select_update_installation(
    *, data_root: Path
) -> tuple[Path, Callable[[Path, Path, Path], tuple[bool, str]]]:
    if alt_update_mode_enabled():
        return data_root / "updates" / "pending_alt_update.json", apply_alt_update
    return data_root / "updates" / "pending_update.json", apply_update


def pending_update_requires_privileged_worker(*, data_root: Path) -> bool:
    """Return whether the ALT agent must leave publication to the root worker."""
    pending_path, _ = select_update_installation(data_root=data_root)
    return alt_update_mode_enabled() and pending_path.exists()


def apply_pending_alt_update_as_worker(
    *, install_root: Path, data_root: Path
) -> tuple[bool, str]:
    """Consume one ALT pending update without launching an agent process."""
    pending_path = data_root / "updates" / "pending_alt_update.json"
    if not pending_path.exists():
        return True, "no pending ALT update"
    return apply_alt_update(install_root, data_root, pending_path)


def apply_pending_alt_rollback_as_worker(
    *, install_root: Path, data_root: Path
) -> tuple[bool, str]:
    """Consume one fixed ALT rollback request without caller-selected targets."""
    return apply_alt_rollback(install_root, data_root)


def _log(msg: str) -> None:
    print(f"[launcher] {msg}", flush=True)


def _load_current_state(
    current_path: Path, versions_dir: Path
) -> tuple[dict[str, Any], str, str | None, Path]:
    current = json.loads(current_path.read_text(encoding="utf-8-sig"))
    version = str(current.get("version") or "").strip()
    if not version:
        raise RuntimeError("current.json missing 'version'")
    previous = str(current.get("previous") or "").strip() or None
    version_dir = versions_dir / version
    if not version_dir.is_dir():
        raise RuntimeError(f"Version dir not found: {version_dir}")
    try:
        binary_path = _find_agent_binary(version_dir)
    except FileNotFoundError as exc:
        raise RuntimeError(str(exc)) from exc
    return current, version, previous, binary_path


def _append_update_history(updates_dir: Path, entry: dict[str, Any]) -> None:
    history_path = updates_dir / "update_history.json"
    if history_path.exists():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except Exception:
            history = []
    else:
        history = []
    if not isinstance(history, list):
        history = []
    history.append(entry)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(
        json.dumps(history[-100:], ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _write_failed_launch_marker(
    updates_dir: Path,
    *,
    crashed_version: str,
    rollback_version: str | None,
    exit_code: int,
    elapsed_sec: float,
    attempts: int,
    message: str | None = None,
    reason: str | None = None,
) -> None:
    payload = {
        "failed_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason
        or ("startup_crash_rollback" if rollback_version else "startup_crash"),
        "crashed_version": crashed_version,
        "rollback_version": rollback_version,
        "exit_code": exit_code,
        "elapsed_sec": round(elapsed_sec, 3),
        "attempts": attempts,
    }
    if message:
        payload["message"] = message
    updates_dir.mkdir(parents=True, exist_ok=True)
    (updates_dir / "last_failed_launch.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _rollback_current_version(
    current_path: Path, *, crashed_version: str, fallback_version: str
) -> None:
    current_path.write_text(
        json.dumps(
            {"version": fallback_version, "previous": crashed_version},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def _alt_previous_version(install_root: Path, *, current_version: str) -> str | None:
    """Read rollback authority only from the root-owned previous selector."""
    previous_path = install_root / "previous.json"
    try:
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        not isinstance(previous, dict)
        or set(previous) != {"schema_version", "source_revision", "version"}
        or previous.get("schema_version") != 1
        or not isinstance(previous.get("source_revision"), str)
        or not isinstance(previous.get("version"), str)
        or previous["version"] == current_version
    ):
        return None
    return previous["version"]


def _is_headless_entrypoint(binary_path: Path) -> bool:
    return (
        binary_path.name == "endpoint-agent"
        and binary_path.parent.name == "endpoint-agent"
    )


def _agent_argv(
    binary_path: Path,
    *,
    use_gui: bool,
    transport_mode: str | None,
    migration_http_pull_fallback: bool | None,
) -> list[str]:
    argv = [str(binary_path)]
    if not _is_headless_entrypoint(binary_path):
        argv.append("--gui" if use_gui else "--no-gui")
        return argv
    if transport_mode is not None:
        argv.extend(["--transport-mode", transport_mode])
    if migration_http_pull_fallback is not None:
        argv.append(
            "--migration-http-pull-fallback"
            if migration_http_pull_fallback
            else "--no-migration-http-pull-fallback"
        )
    return argv


def main() -> None:
    parser = argparse.ArgumentParser(description="PC Agent Launcher")
    parser.add_argument(
        "--data-dir", type=str, default=None, help="Data root (default: env/config)"
    )
    parser.add_argument(
        "--install-root",
        type=str,
        default=None,
        help="Install root (default: env/config)",
    )
    parser.add_argument(
        "--gui", action="store_true", help="Запустить агент с GUI (по умолчанию)"
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="Запустить агент без GUI (консольный режим)",
    )
    parser.add_argument(
        "--transport-mode",
        choices=("gateway_http_pull", "gateway_wss"),
        default=None,
        help="Transport passed only to the neutral headless entrypoint",
    )
    parser.add_argument(
        "--migration-http-pull-fallback",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Migration fallback passed only to the neutral headless entrypoint",
    )
    parser.add_argument(
        "--apply-alt-update",
        action="store_true",
        help="Apply one pending ALT update without starting the agent (root worker only)",
    )
    parser.add_argument(
        "--apply-alt-rollback",
        action="store_true",
        help="Apply the fixed ALT rollback request (root worker only)",
    )
    parser.add_argument("--print-version", action="store_true")
    args = parser.parse_args()
    if args.print_version:
        print(AGENT_VERSION)
        return
    use_gui = args.gui or not args.no_gui  # по умолчанию GUI включён
    data_root = resolve_data_root(cli_value=args.data_dir)
    install_root = resolve_install_root(cli_value=args.install_root)
    current_path = install_root / "current.json"
    pending_path, apply_pending_update = select_update_installation(data_root=data_root)
    updates_dir = data_root / "updates"
    versions_dir = install_root / "versions"
    if args.apply_alt_update and args.apply_alt_rollback:
        _log("ALT worker modes are mutually exclusive")
        raise SystemExit(2)
    if args.apply_alt_update or args.apply_alt_rollback:
        if not alt_update_mode_enabled():
            option = (
                "--apply-alt-rollback"
                if args.apply_alt_rollback
                else "--apply-alt-update"
            )
            _log(f"{option} requires ENDPOINT_AGENT_ALT_UPDATE_MODE=1")
            raise SystemExit(2)
        if os.name != "nt" and os.geteuid() != 0:
            _log("ALT worker mode must run from the root-owned systemd worker")
            raise SystemExit(1)
        if args.apply_alt_rollback:
            ok, message = apply_pending_alt_rollback_as_worker(
                install_root=install_root, data_root=data_root
            )
            operation = "rollback"
        else:
            ok, message = apply_pending_alt_update_as_worker(
                install_root=install_root, data_root=data_root
            )
            operation = "update"
        _log(
            f"Privileged ALT {operation} {'applied' if ok else 'failed'}: {message}; "
            "returning control to systemd"
        )
        # A handled verification or publish failure is durable in update
        # history.  Exit cleanly so the helper can restart the last known good
        # unprivileged service for outcome reporting.
        raise SystemExit(0)
    if not current_path.exists():
        _log(
            f"current.json not found at {current_path}; create it with initial version"
        )
        sys.exit(1)

    try:
        _, version, previous_version, binary_path = _load_current_state(
            current_path, versions_dir
        )
    except RuntimeError as e:
        _log(str(e))
        sys.exit(1)
    if alt_update_mode_enabled():
        previous_version = _alt_previous_version(install_root, current_version=version)
    if pending_update_requires_privileged_worker(data_root=data_root):
        _log("pending ALT update is delegated to the root-owned systemd worker")
        raise SystemExit(0)
    env = os.environ.copy()
    env["PC_AGENT_DATA_DIR"] = str(data_root)
    env["PC_AGENT_INSTALL_ROOT"] = str(install_root)
    backoff = 1.0
    max_backoff = 60.0
    immediate_crash_attempts = 0
    immediate_crash_version: str | None = None
    while True:
        if pending_path.exists():
            _log("pending_update.json found, applying update...")
            if alt_update_mode_enabled():
                ok_, msg = apply_pending_update(install_root, data_root, pending_path)
            else:
                ok_, msg = apply_pending_update(
                    install_root, data_root, pending_path, log_message=_log
                )
            if ok_:
                _log(f"Update applied: {msg}; restarting with new version")
            else:
                _log(f"Update failed: {msg}; restarting current version")
            backoff = 1.0
            try:
                _, version, previous_version, binary_path = _load_current_state(
                    current_path, versions_dir
                )
            except RuntimeError as e:
                _log(str(e))
                sys.exit(1)
            if alt_update_mode_enabled():
                previous_version = _alt_previous_version(
                    install_root, current_version=version
                )
            immediate_crash_attempts = 0
            immediate_crash_version = None
        agent_argv = _agent_argv(
            binary_path,
            use_gui=use_gui,
            transport_mode=args.transport_mode,
            migration_http_pull_fallback=args.migration_http_pull_fallback,
        )
        started_at = time.monotonic()
        proc = subprocess.Popen(
            agent_argv,
            env=env,
            cwd=str(binary_path.parent),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        ret = proc.wait()
        elapsed_sec = time.monotonic() - started_at
        if ret == EXIT_UPDATE_PENDING:
            if alt_update_mode_enabled():
                _log("Agent exited with update-pending (42); root worker will apply it")
                raise SystemExit(0)
            _log("Agent exited with update-pending (42); will apply update and restart")
            backoff = 1.0
            immediate_crash_attempts = 0
            immediate_crash_version = None
            continue
        if pending_path.exists():
            if alt_update_mode_enabled():
                _log("pending ALT update is delegated to the root-owned systemd worker")
                raise SystemExit(0)
            _log("pending_update.json present after exit; applying update")
            immediate_crash_attempts = 0
            immediate_crash_version = None
            continue
        if ret == 0:
            _log("Agent exited normally (code 0); stopping launcher")
            raise SystemExit(0)

        if elapsed_sec <= IMMEDIATE_CRASH_WINDOW_SEC:
            if immediate_crash_version != version:
                immediate_crash_version = version
                immediate_crash_attempts = 0
            immediate_crash_attempts += 1
            _log(
                f"Agent {version} crashed after {elapsed_sec:.1f}s with code {ret} "
                f"(attempt {immediate_crash_attempts}/{IMMEDIATE_CRASH_RETRY_LIMIT})"
            )
            if (
                immediate_crash_attempts >= IMMEDIATE_CRASH_RETRY_LIMIT
                and previous_version
                and previous_version != version
            ):
                if alt_update_mode_enabled():
                    try:
                        write_alt_rollback_request(
                            install_root, data_root, crashed_version=version
                        )
                    except (OSError, ValueError, json.JSONDecodeError) as exc:
                        _log(
                            "Root-mediated ALT rollback request failed: "
                            f"{type(exc).__name__}"
                        )
                        previous_version = None
                    else:
                        _log(
                            f"Terminal startup crash detected for {version}; "
                            f"requested root rollback to {previous_version}"
                        )
                        _append_update_history(
                            updates_dir,
                            {
                                "version": version,
                                "success": False,
                                "at": datetime.now(timezone.utc).isoformat(),
                                "reason": "startup_crash_rollback_requested",
                                "message": (
                                    f"Requested root rollback to {previous_version} after "
                                    f"{immediate_crash_attempts} immediate crashes "
                                    f"(exit code {ret})"
                                ),
                                "previous_version": previous_version,
                            },
                        )
                        _write_failed_launch_marker(
                            updates_dir,
                            crashed_version=version,
                            rollback_version=previous_version,
                            exit_code=ret,
                            elapsed_sec=elapsed_sec,
                            attempts=immediate_crash_attempts,
                            reason="startup_crash_rollback_requested",
                        )
                        raise SystemExit(0)
                else:
                    _log(
                        f"Terminal startup crash detected for {version}; "
                        f"rolling back to previous version {previous_version}"
                    )
                    _append_update_history(
                        updates_dir,
                        {
                            "version": version,
                            "success": False,
                            "at": datetime.now(timezone.utc).isoformat(),
                            "reason": "startup_crash_rollback",
                            "message": (
                                f"Rolled back to {previous_version} after "
                                f"{immediate_crash_attempts} immediate crashes "
                                f"(exit code {ret})"
                            ),
                            "previous_version": previous_version,
                        },
                    )
                    _write_failed_launch_marker(
                        updates_dir,
                        crashed_version=version,
                        rollback_version=previous_version,
                        exit_code=ret,
                        elapsed_sec=elapsed_sec,
                        attempts=immediate_crash_attempts,
                    )
                    _rollback_current_version(
                        current_path,
                        crashed_version=version,
                        fallback_version=previous_version,
                    )
                    try:
                        _, version, previous_version, binary_path = _load_current_state(
                            current_path, versions_dir
                        )
                    except RuntimeError as e:
                        _log(f"Rollback failed: {e}")
                        sys.exit(1)
                    backoff = 1.0
                    immediate_crash_attempts = 0
                    immediate_crash_version = None
                    continue
            if immediate_crash_attempts >= IMMEDIATE_CRASH_RETRY_LIMIT:
                message = (
                    f"Agent {version} failed to start {immediate_crash_attempts} times "
                    f"within {IMMEDIATE_CRASH_WINDOW_SEC:.0f}s; rollback is unavailable. "
                    "Stopping launcher. Check last_failed_launch.json and agent logs."
                )
                _log(message)
                _append_update_history(
                    updates_dir,
                    {
                        "version": version,
                        "success": False,
                        "at": datetime.now(timezone.utc).isoformat(),
                        "reason": "startup_crash",
                        "message": message,
                        "previous_version": previous_version,
                    },
                )
                _write_failed_launch_marker(
                    updates_dir,
                    crashed_version=version,
                    rollback_version=None,
                    exit_code=ret,
                    elapsed_sec=elapsed_sec,
                    attempts=immediate_crash_attempts,
                    message=message,
                )
                raise SystemExit(ret or 1)
        else:
            immediate_crash_attempts = 0
            immediate_crash_version = None
        _log(f"Agent exited with code {ret}; restart in {backoff:.0f}s")
        time.sleep(min(backoff, max_backoff))
        backoff = min(backoff * 2, max_backoff)


if __name__ == "__main__":
    main()
