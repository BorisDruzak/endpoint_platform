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
  release volume and works before the initial selector is created. The
  worker uses the same check when running from a versioned release.
- `inventory_storage.py`: read-only artifact-volume inventory against the four
  release catalog owners. Both inventory modules ship in the server archive.
- `verify_server_release_payload.py`: operator-side, read-only comparison of a
  server archive's source payload with a deployed tree. Reports archive SHA-256,
  missing or different members and extra deployment paths.
- `prepare_endpoint_apt_windows.ps1`: verifies live APT trees on the Linux
  repository host and prepares date-only renewals with a Windows publisher.
  The Linux helper verifies the exact draft and signed package hash chain.
  `sign_endpoint_apt_release.ps1` keeps DPAPI and the private key on Windows.

No Agent release archive, native package, selector or live server is a target of
the server archive normalizer. Historical qualified bytes remain immutable.

- `worktime_helpdesk_staging.py`: fixed .118 server-only preparation/activation
  adapter for the reviewed runbook. Requires exact old selector/schema, frozen
  archive/digests, private capsule, fresh request, no in-flight operations, verified
  DB backup and unchanged personnel/grants. Additive migration44 stays applied on
  selector rollback. It never targets production or enables the feature flag.

## Agent release status

Run `python tools/release/agent_release.py status` from a checkout to read the
compact JSON projection. The tool reads the existing records and linked
receipts. The root version remains a historical checkpoint. JSON marked
`repository_record` describes observations made at the recorded times.
Unknown fields require a current observation from their owning catalog.

| Pointer | Checked-in source | Live authority |
| --- | --- | --- |
| Windows primary download | `primary_windows_release` and linked Setup receipt | Console installer catalog, newest active published row |
| Windows enrollment | No current campaign pointer in the checked-in projection | Single active default Windows AUTO campaign and trusted installer catalog |
| Windows existing devices | `current_windows_rollout` with an exact-ID receipt join for digest | Full Setup release, policy and coverage preview; Core has a separate builds and rollout catalog |
| ALT primary and native enrollment source | `linux`, linked signed kit receipt and its production native-source record | Published kit bytes, Linux native registry and applicable platform-bound enrollment campaign |
| ALT existing devices | No current delivery pointer in the checked-in projection | Native acceptance and Core OTA builds and rollouts |
| Ubuntu Noble and Debian Bookworm | `ubuntu_servers_197` and `proxmox_debian` | Per-suite verified signed `InRelease` and its hash-bound package index |
| Provider | `current_provider` | Deployed selector/source, schema and verified archive receipt |

The Windows download and fleet policy use distinct release UUIDs. A target that
differs from the primary receipt has an unknown digest in this projection.
The ALT native registry identifies source bytes. Campaign eligibility is
verified at enrollment. APT package entries alone do not prove that the signed
index is current; verify signature and expiry before using that delivery path.
