"""Offline installer host; service lifecycle code is a separate entrypoint."""
from __future__ import annotations
import argparse
from typing import Sequence
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


def add_installer_arguments(parser, modes):
    modes.add_argument("--installer-launcher")
    parser.add_argument("--installer-launch-nonce")
    modes.add_argument("--installer-phase", choices=("inspect","inspect-compound","prepare","stage-online","seal-staged-switch","adopt-staged-switch",
            "begin-staged-trial","observe-staged-trial","accept-staged-trial",
            "restore-staged-companions","inspect-staged-recovery","recover-staged-owner","record-staged-reboot-3010","record-staged-reboot-1641",
            "inspect-staged-state","prepare-foundation-rollback","bind-foundation-rollback-roles","rollback-candidate-removed","rollback-native-committed","verify-foundation-rollback","msi-preflight","msi-enter","foundation-config","msi-complete","reconcile","finish","verify-settled",
            "compound-old-returned","compound-new-returned","compound-commit","compound-retire","compound-complete","compound-finalize",
            "compound-repair-returned","compound-repair-commit"))
    parser.add_argument("--installer-session")
    parser.add_argument("--foundation-state", type=int)
    parser.add_argument("--foundation-action", type=int)
    parser.add_argument("--runtime-state", type=int)
    parser.add_argument("--runtime-action", type=int)
    parser.add_argument("--rollback-disabled", default="")
    parser.add_argument("--uninstall-finalization", default="")
    parser.add_argument("--staged-removal", default="")
    parser.add_argument("--upgrade-detected")


def _parser():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    add_installer_arguments(parser, modes)
    return parser


def run_installer_args(args):
    if args.installer_launcher:
        try:
            from pc_agent.platform.windows.installer_launch_broker import run_launch_broker
            return run_launch_broker(args.installer_launcher, args.installer_launch_nonce)
        except Exception as error:
            try:
                from pc_agent.platform.windows.installer_phase_diagnostics import report_installer_phase_failure
                report_installer_phase_failure('launcher', error)
            except Exception:
                pass
            return 1
    if args.installer_phase:
        try:
            from pc_agent.platform.windows.installer_transaction_bridge import owner_authorized_phase, execute_authorized_phase
            from pc_agent.platform.windows.msi_inventory import package_read_scope, immutable_installer_media_roots
            from pc_agent.platform.windows.installer_phase_diagnostics import profile_installer_phase
            with owner_authorized_phase(args.installer_session,args.installer_phase) as client:
                paths = WindowsUpdatePaths.production()
                media_roots = immutable_installer_media_roots(paths, client.capability, args.installer_phase)
                prefetch = args.installer_phase in {
                    'inspect', 'prepare', 'seal-staged-switch', 'compound-finalize',
                    'compound-old-returned', 'compound-new-returned',
                    'msi-preflight', 'msi-enter', 'msi-complete', 'foundation-config',
                }
                with profile_installer_phase(args.installer_phase, paths), package_read_scope(
                        immutable_media_roots=media_roots, prefetch_media=prefetch):
                    execute_authorized_phase(client,paths,
                        feature_states=(args.foundation_state,args.foundation_action,args.runtime_state,args.runtime_action),
                        rollback_disabled=args.rollback_disabled,uninstall_finalization=args.uninstall_finalization,
                        upgrade_detected=args.upgrade_detected,staged_removal=args.staged_removal)
            return 0
        except Exception as error:
            # pywin32 errors need not inherit OSError. A windowed MSI helper
            # must return failure, never wait on an invisible exception dialog.
            try:
                detail = str(error)
            except Exception:
                detail = None
            try:
                from pc_agent.platform.windows.installer_phase_diagnostics import report_installer_phase_failure
                report_installer_phase_failure(args.installer_phase, error)
            except Exception:
                pass
            return {"UPDATE_IN_PROGRESS": 61, "UPDATE_STATE_INVALID": 62,
                    "PROVENANCE_CONFLICT": 63}.get(detail, 1)
    return None


def main(argv: Sequence[str] | None = None) -> int:
    result = run_installer_args(_parser().parse_args(argv))
    if result is None:
        raise ValueError("unsupported installer host mode")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
