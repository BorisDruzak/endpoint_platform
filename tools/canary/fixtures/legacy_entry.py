"""Separate frozen fixture entry; authority completes before runtime main."""
import sys

from pc_agent.runtime.main import _parser, main as runtime_main
from pc_agent.version import AGENT_VERSION
from tools.canary.fixtures import fixture_binding as binding
from tools.canary.fixtures.legacy_authority import Rejected, resolve
from tools.canary.fixtures.diagnostics import diagnostic_scope, report_diagnostic, runtime_trace


def _invalid_arguments(_message):
    raise Rejected("fixture_arguments")


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    with diagnostic_scope(getattr(sys, "frozen", False)
            and "--windows-service-child" in args and "--verify" not in args):
        return _run(args)


def _run(args):
    try:
        binding.require_binding(AGENT_VERSION)
        if not getattr(sys, "frozen", False):
            raise Rejected("frozen_fixture_required")
        if args == ["--print-version"]:
            print(AGENT_VERSION)
            return 0
        if len(args) > 128 or any(not isinstance(arg, str) or len(arg) > 8192 for arg in args):
            raise Rejected("fixture_arguments")
        if sum(map(len, args)) > 32768:
            raise Rejected("fixture_arguments")
        occurrences = sum(arg == "--launcher-version" or arg.startswith("--launcher-version=") for arg in args)
        if occurrences > 1:
            raise Rejected("fixture_arguments")
        parser = _parser()
        parser.allow_abbrev = False
        parser.error = _invalid_arguments
        parsed = parser.parse_args(args)
        if parsed.verify:
            # The immutable81 offline worker runs this before service launch.
            # Ordinary verification has no hello/startup-proof/network runtime.
            return runtime_main(args)
        if not parsed.windows_service_child:
            raise Rejected("service_child_required")
        report_diagnostic("authority_start")
        authority = resolve(parsed.launcher_version)
        if parsed.launcher_version is None:
            args.extend(["--launcher-version", authority.version])
    except (Rejected, ValueError, SystemExit) as error:
        report_diagnostic("authority_refused", error=error)
        # Never print argv, native exception messages, config or token data.
        print("endpoint fixture refused: authority_unavailable", file=sys.stderr)
        return 75
    print(f"endpoint fixture authority: {authority.kind} {authority.version}", file=sys.stderr)
    report_diagnostic("authority_resolved")
    with runtime_trace():
        try:
            result = runtime_main(args)
        except Exception as error:
            report_diagnostic("runtime_exception", error=error)
            raise
        report_diagnostic("runtime_exit", exit_code=result)
        return result


if __name__ == "__main__":
    raise SystemExit(main())
