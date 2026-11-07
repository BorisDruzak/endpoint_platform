# Observer1.0.6, upward preparation and full Setup167 candidates

Checkpoint:2026-11-05T11:55:35Z. This is a build/publication/server-deployment
receipt, not native or fleet acceptance of167. The independent outbound support
tunnel selected by the user is a reviewed design only; it is not in this Setup.

## Result and immutable artifacts

- Core166 source:`9a47844c1db8effcbff311989402d5dadc54bec1`.
  `C:\endpoint-platform-wix-build\core166-observer-9a47844\EndpointCore-3.2.166-9a47844.zip`.
  SHA256:`9bfb4ce57434333a3f13c28efce0339b607b9b920a5aff65e27f38353ad698b9`,
  22931793bytes. All119 archive entries match manifest hashes/sizes; runtime
  contract explicitly requires Foundation158. Frozen executable reports166.
  Registered build:`d02d197b-b6b8-45f7-a404-963e2a4660e8`; no rollout assigned.
- Full167 runtime source:`ab313225e04b7cccefc0c30ae17b949d8fdd964d`, native
  packaging:`773f2dbeeee561cc565b124c9f2dcbac553bd48f`.
  `C:\endpoint-platform-wix-build\setup167-ab31322\native-setup-build\releases\EndpointAgentSetup-3.2.167-x64.exe`.
  SHA256:`7a994993281e0cbbdb2f4f190369968be46e3d142dc2605cf129b9d96803b9ae`,
  146243456bytes. MSI SHA256:
  `ffb3e7def4573a33551f424c0bbb9b7dde6a8617ce8dfb673993d129788bee70`,104431616bytes.
  Both Authenticode Valid with timestamp, publisher
  `4D4C23389F5FF77BC4EB32044761019EAE8FB776`.
- Full167 initial runtime:119files, tree
  `e0ce0ce8f513c432ff898bb5961acada8de982d205e5103f60562eeb05c4216a`,280
  committed source inputs, component`C98CD694-9170-56CE-9254-D5E6AAE5061F`.
  Compatibility contract authored before freeze. All native helpers rebuilt;
  no reuse of165 helpers across changed source. WiX4.0.6 used isolated matching
  Util4.0.6 cache, leaving the unrelated global extension cache unchanged.
- Full167 registered update release:`b3feccd9-ac42-4a86-8c17-9a7fc1509869`.
  No167 assignments, source qualifications or Windows enrollment release were
  created. Default enrollment download remains165. On qualification/public
  promotion, use canonical transactional inclusion in the existing AUTO campaign.
- All three uploaded files were checked on the server against exact local hashes
  and sizes, published without overwrite, root:endpoint-platform0640.

The source-bound signed observer1.0.6 remains the already published immutable
`f6359376cac7f5a5de6476ed9c41ea652fb95fe7e64c285d1ff2eaa8f6b0b069`.
Its exact bytes and payload metadata are present in the actual newly frozen
installer host. Recovery/grant functions are present in its PYZ;438 modules,
112 members, build-only modules absent. Full Setup bootstrap inspection also
passed. These checks do not demonstrate actual SYSTEM/domain-user task launch.

## Server deployment and live boundary

Server archive SHA256:
`5f4f8b8c6b64230a5eb1948bb5403757172458a4f78f2e9694b200a20e3ad091`.
Current:`/opt/endpoint-platform/releases/endpoint-platform-773f2dbeeee5`;
previous:`/opt/endpoint-platform/releases/endpoint-platform-96a487cdfcfa`.
Dependency versions pinned to previous actual freeze; pip check/import passed,
schema0045 unchanged. Available space before preparation5431091200bytes. Atomic
promotion retained guarded health rollback and release metadata restoration.
API/worker active; canonical HTTPS hostname/CA-verified health200/databaseok.

Policy remains revision3, disabled, target165, all-active with empty device list,
max2,`fleet_failure_requires_review`; one existing chain reserves a slot.
No workstation preparation, SSH install, MSI replay or observer replacement on146.
The one-off observer-only repair remains unexecuted; its source-validity guard
was not relaxed.

At11:55:35Z,120 still has accepted165 and UserSensor11:55:18Z.146's original
job`6bc214b4-50b3-4fe0-91b4-0732b8dea2e6`, original attempt
`43731f03-f211-465d-8cf2-f8dd1f8fc5fa`, is again reporting`verifying`/proofnull;
UserSensor remains09:03:42Z. Earlier`target_native_binding_differs` and user-supplied
null/unverified preflight with provenance conflict/state-invalid remain unresolved
diagnostic evidence. A later verifying heartbeat does not prove that defect gone.

User stopped Computer Use with Escape during this work. No further UI operations
or additional workstation commands were requested. Native167 canary, active-user
soak, source158/165 qualification, fresh enrollment and fleet enablement remain
outstanding. The user-selected support tunnel needs implementation/qualification
under its separate spec before it can provide service access to any workstation.

## Verification and limits

- `run-tests.ps1 tests/server/test_setup_direct_observer_preparation.py tests/server/test_setup_fleet_policy.py tests/server/test_setup_preparation.py tests/server/test_setup_recovery.py tests/server/test_setup_update_service.py -q`:75passed.
- `run-tests.ps1 pc_agent/tests/windows/test_native_setup_continuation.py pc_agent/tests/windows/test_compound_installer_phases.py pc_agent/tests/windows/test_installer_transaction_bridge.py pc_agent/tests/windows/test_staged_recovery.py -q`:195passed.
- `run-tests.ps1 tests/packaging/test_privileged_windows_bootstrap.py tests/packaging/test_initial_runtime_contract.py -q`:73passed.
- Contract generator:`tools/contracts/generate_contract_artifacts.py --check`:exit0.
- Real isolated PostgreSQL: first four-file run18passed/1failed. The new scenario
  had incorrectly assumed an empty global slot; the preceding test preserves an
  active chain. Fixed only its fixture limit to2. Reran the entire source module:
  2passed, including persisted one-child handoff across sessions. The other17
  tests had passed unchanged. Disposable databases/roles and local SSH tunnel
  cleaned after both runs; production application schema was not a test fixture.
- Canonical Console archive builder:`npm ci`/production build passed. Existing
  bundle-size warning remains. No new rendered-UI acceptance is claimed.
- Runtime166/167 freezes, all280 source hashes, native MSI package validation,
  isolated WiX composition, frozen imports and exact signed payload checks passed.
  `git diff --check` passed before commits. Native execution/owner-loss recovery
  still requires actual canary evidence; mocks/build success are insufficient.
- Earlier broad suite was not fully green: twelve remaining unmodified
  server/migration failures were not all independently established as baseline.
  No full-repository all-green claim. Known Yandex issue remains user-deferred.

## Commits, files and checks

| Commit | Message | Files / verification |
|---|---|---|
| `bdbf352c03820e7b1bbed80e180509fae68d18ef` | `docs(windows): specify independent pilot support tunnel` | Support spec/plan; independent builder check, no material unanswered questions. |
| `b17d29d0a504e4a5bccd0596985c27628f997625` | `docs(updates): record native continuation and qualification gates` | Native continuation spec/plan; source and195 focused tests. |
| `87d731db5ed06f082ee98256314fa75814454941` | `build(distribution): serve immutable Windows support artifacts` | `deploy/server/endpoint-windows-distribution.nginx.conf`; actual matching snippet and `nginx -t` passed. |
| `0a65680cd160b4b271d14df3e08c44e53be8ac0d` | `fix(updates): prepare missing modern observers without Core rollback` | Server policy/preparation, direct-preparation tests, PostgreSQL source test and runbook;75 unit tests, corrected PostgreSQL scenario and contract check above. |
| `9a47844c1db8effcbff311989402d5dadc54bec1` | `build(agent): stage Core 3.2.166 observer bootstrap` | `pc_agent/version.py`; imported/frozen print-version166 and119 ZIP entries. |
| `37ab6d666f2d8c234278e4fb6716ad9a9a555dbc` | `docs(release): record verified Core166 bootstrap candidate` | Core166 release JSON; actual archive, contract, signed payload and version checks. |
| `ab313225e04b7cccefc0c30ae17b949d8fdd964d` | `build(agent): stage full Setup 3.2.167 continuation fix` | `pc_agent/version.py`; imported167, actual frozen/native build above. |
| `773f2dbeeee561cc565b124c9f2dcbac553bd48f` | `build(windows): bind Setup167 to frozen runtime source` | New167 source binding; all280 source hashes and119 staged files validated, actual full build signed. |

No push or PR performed. Detailed machine-readable release records retain the
exact distinction between publication, native qualification and fleet acceptance.

Final checkpoint commit message:`docs(release): record Setup167 candidate and recovery limits`.
Files:AGENTS.md,Core166 release record,current-agent-release.json,new Windows167
release record,native-continuation plan,and this verification report. JSON shape,
exact recorded artifact hashes, generated contracts and diff whitespace checks
passed; the final commit SHA is reported in the operator reply.
