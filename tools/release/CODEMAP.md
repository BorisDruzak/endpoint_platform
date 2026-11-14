# Server release tools

- `build_console_server_archive.ps1`: clean committed server source + local Console
  bundle, using actual native tar staging and Python3.12 safe-header finalization.
- `normalize_server_archive.py`: server-only archive writer; validates one regular
  source tree, preserves payload bytes, emits deterministic root0:0/0644/0755
  headers and refuses existing output. It never extracts or edits deployed files.
- `apply_query_safe_nginx.py`, `verify_query_safe_nginx.py`: independent reviewed
  configuration-only callback logging repair and isolated sentinel verification.
- `tests/deploy/test_server_archive_permissions.py`: actual Windows PowerShell/
  native-tar header, byte-preservation/reproducibility and unsafe-input regressions.
- `deploy/server/PRODUCTION_RUNBOOK.md`: immutable archive identity, protected
  root extraction and complete physical/mode/digest closure before venv/imports.
- `inventory_deployments.py`: read-only release-volume inventory with current,
  rollback, staged commit, explicit pins, observed Linux process references,
  and transitive protection through links between release directories.
  `--check-release-space` checks the 10 GiB deployment threshold on the
  release volume and works before the initial selector is created.
- `inventory_storage.py`: read-only artifact-volume inventory against the four
  release catalog owners. Both inventory modules ship in the server archive.
- `verify_server_release_payload.py`: operator-side, read-only comparison of a
  server archive's source payload with a deployed tree. Reports archive SHA-256,
  missing or different members and extra deployment paths.

No Agent release archive, native package, selector or live server is a target of
the server archive normalizer. Historical qualified bytes remain immutable.

- `worktime_helpdesk_staging.py`: fixed .118 server-only preparation/activation
  adapter for the reviewed runbook. Requires exact old selector/schema, frozen
  archive/digests, private capsule, fresh request, no in-flight operations, verified
  DB backup and unchanged personnel/grants. Additive migration44 stays applied on
  selector rollback. It never targets production or enables the feature flag.
