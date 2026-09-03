# ADR 0003: Native Agent Packaging

- Status: Accepted
- Date: 2026-08-01

## Decision

One Git repository.
ALT uses RPM.
Windows uses MSI.
Common runtime and contracts; platform-specific service and package layers.

New Endpoint Platform MSI and RPM packages use the locked
`requirements/build-windows.txt` or `requirements/build-linux.txt` profile and
the corresponding `pc_agent/pyinstaller_endpoint_core_*.spec` file. Those
specifications package `pc_agent/runtime/main.py` only and exclude Qt,
Helpdesk UI, and Remote Assist dependencies.

Legacy GUI packaging specifications and dependency profiles have been removed.
Only the locked Endpoint Core build profiles are valid MSI/RPM inputs.

## Consequences

Shared runtime behavior and contracts stay in this repository. ALT and Windows
release artifacts use their native package formats and isolate platform service
and packaging details from the common runtime.
