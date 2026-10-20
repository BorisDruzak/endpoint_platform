# Local changes reconciliation - 2026-10-20

Baseline: `origin/main` = `a97c330b95cb82603bf1dcd8c8b948a48f8c96fd`. Scope: 32 local commits not reachable from any fetched `origin/*` ref, plus tracked/untracked status in all 72 pre-existing registered worktrees. Ignored files are outside this unpublished-source inventory.

## Outcome

Eight commits have exact stable patch-ID equivalents in main. Eighteen more are already integrated with adaptations, superseded, environment-specific, or obsolete candidate/fixture history. Six commits contain applicable partial changes recovered here. Original SHAs/branches are preserved; publishing their current effects does not make those old SHAs ancestors of main.

Recovered Windows origin persistence, native headless ALT claim preparation, per-layout claim destinations, ALT prebuilt-payload protection, and two stale documentation boundaries. Review also found that fingerprint execution could not traverse the old root-only staging path; the public bundle now uses a root-owned service-readable staging directory, while private CA/installer inputs remain restricted. No runtime version, immutable manifest, fixture authority, target host, endpoint selection, or deployment is changed.

## Commit-by-commit disposition

| Original commit | Disposition | Evidence / action |
| --- | --- | --- |
| `2a1525e301896ed83e7c383d022246bbd6d3f01c` | Exact patch equivalent in main | `6ff7f57b58b9c1b8e37600fe453a6639b682cb6e` |
| `c781cdc5a55113649ba9368954e675955b69945c` | Already integrated | e7449e4, 0158f1c, 3b2075f, 9856cc7 and later changes include the harness, input checks, bounded diagnostics and service-account tests. |
| `25dff488c89806872c9a81848959aaabc40b7622` | Current remainder recovered | 44d16bd/25d6137 supplied service-origin reading; recover the missing atomic protected Windows provisioning writer and tests, without the obsolete 3.2.18 pins. |
| `9edc5a800c6de8b8820740b5766585ad44fb3b0c` | Exact patch equivalent in main | `662c55f9a42203e2f911a23267cad33a71a43cf4` |
| `6db12a1a34077a16e2e0de8730494a48dd8823a0` | Exact patch equivalent in main | `e9fbe329838e2bba0c31b1d05d714a1fe3c6b96e` |
| `9744669d4937cfa35f904bfa15a3ff19087ac87d` | Exact patch equivalent in main | `189569db27f32a73523cd8d29f54a7a56dfe09c2` |
| `da6d8eb67b53c7e09b2f2a7c7f99c05d40c13fca` | Exact patch equivalent in main | `9ce3ad3c0cbc68058292c85cedaa8e4f4828ea19` |
| `55dff744dfc56bca3b990388b378f766286c2604` | Exact patch equivalent in main | `4a287152baab09ac7b7e9f303a56b2bd8d4d173b` |
| `b5316b76d7ce385c4a30d9fcfd6c95f3a2650d5c` | Exact patch equivalent in main | `23dca1e2f1b2488e54c4dba4ad58a5131466ecb7` |
| `c4689d4a1c3b4a02aa789dcc79e391ab7f532386` | Current remainder recovered | 978b152 and later changes contain owner-scoped cancellation, OpenAPI and tests; add the missing contract documentation using current expired-collection semantics. |
| `0f32a074a033e6c9341f248637bfb70e6d63624e` | Superseded | c87364c/d136727 remove all 74 retired GUI/runtime paths; preserve the current headless runtime. |
| `aeff8442cef46e794a1bb7b63b358d7bc58da011` | Superseded | c87364c/d136727 remove legacy package inputs; preserve the intentionally rewritten current test_linux_packaging.py. |
| `9a339fb56aafdd67c6c2133ae917ac243deb9197` | Superseded | d136727 removes core/database.py and further restricts loader roots. |
| `9b668260df50f9b3e7ad3da42520acb8f21e2008` | Current remainder recovered | d136727 updates the active runtime documentation; replace the remaining obsolete MODULES.md description of the removed orchestrator/Protocol V3. |
| `06aca3fb66ba7583712b45400d3be48282b05d81` | Superseded release pin | 980a19f independently introduced 3.2.36; main now uses 3.2.121. Do not downgrade. |
| `eefab4da290133cd522ea96e73b12c1a84aab2d5` | Superseded artifact provenance | 2d3f767 records main 3.2.36 provenance against 980a19f; do not overwrite it with a manifest for a different source tree. |
| `30cf437e272f04477ba9aba8c94d9385acf48408` | Historical environment settings | Staging-only target/CIDR changes conflict with the currently approved fixed test target. Preserve current targeting. |
| `da882860acd2c61d4502efead197e047dd173e70` | Historical environment documentation | Old staging addresses and workflow wording do not supersede current approved target/runbooks. |
| `8a36fe78fed8871cc44ff45e5081ca6906d50605` | Current remainder recovered | Recover native headless bundle validation and fingerprint selection as a claim-only RPM flow. Preserve the separate legacy offline installer path and fixed target. |
| `4e33b73ac3279bd2613bc8f320ef54d8a11e1529` | Historical workflow; current docs adapted | Do not claim the legacy offline installer accepts headless RPM layouts. Document that distinction in the current controller runbook. |
| `b29692e6596385f85a88cdcd7d117236d3e16e4d` | Current remainder recovered | Restore __find_debuginfo_files suppression for manifest-covered prebuilt payloads; retain current alt3 release and runtime identity. |
| `e856197a4e7c002cd3ae0792cdfa6c93fda51612` | Superseded environment hardwire | 4727222 provides explicit validated Windows origin and one-host CIDR selection; do not restore the older fixed staging settings. |
| `16d93da03e7abb9343fcf2c1b7c58e3de2632929` | Historical host naming | The old staging alias text conflicts with the current approved test-host mapping; no missing product behavior. |
| `ed916445d3e68a1ad440f8b8e5f9664958d23c2c` | Current remainder recovered | Native RPM already uses systemd credstore; select that destination only for the headless bundle. Keep the legacy offline claim path. |
| `aa318d5a33139f31d8533ee234710dd399aae113` | Unpublished obsolete candidate plan | 3.2.38 candidate-only plan has no current release task. Preserve its original local Git object; do not publish it as an active plan. |
| `e0ab736008e8c7d91629068f6175b6e597b26526` | Unpublished obsolete candidate plan | Only corrects the previous 3.2.38 plan command. Preserve the final historical plan locally. |
| `572f3a0249bd4a49035cc97177279fbbf1e90068` | Unpublished obsolete candidate pin | 3.2.38 version/changelog/exact-version test would regress current 3.2.121 source. |
| `eccf633581254c69954bd0a9b1c7f5af64cb534f` | Unpublished obsolete candidate manifest | Manifest identifies the old candidate tree 572f3a0. It is not a current selected release; retain its historical identity locally. |
| `35131a99a49abd87341621c42f53e9256992db47` | Unpublished historical candidate evidence | Dated 3.2.38 package/preflight report records no installation or production release. Preserve locally without converting it into current readiness evidence. |
| `e7a08c829343caf8012ea67c424fa2f478ec706d` | Superseded fixture pin | 797b245 aligns the golden profile with current 3.2.121; do not restore 3.2.38. |
| `4c86d0fe97a7b5749f5db69d6c4fcfb80bb57038` | Exact patch equivalent in main | `4727222929f25ef02bb2cb31453904eb61343d5d` |
| `450593c8f7e9ed70323f41f4631ea64ea80f7eee` | Separate immutable fixture freeze | Main fixture_binding remains intentionally unbound; reviewed fixture source freezes are separate commits. Do not bind general main to the old 3.2.83 fixture. |

## Uncommitted working copies

All 72 pre-existing worktrees were checked. Sixty-six had no tracked/untracked changes; six had the following state. The integration worktree is additional and is not counted in this original inventory.

| Worktree category | Entries | Disposition |
| --- | ---: | --- |
| Primary checkout | 4 | Console test and initial Task13 audit report exactly match main. The local main.py auth patch is already in 90087a8; remaining differences are newer main functionality absent locally. The old hardening spec only has earlier approval/status wording. No new current patch. |
| Task13 recovery-admission worktree | 1 | Untracked RuntimeException RCA plan already exists in main with three completed steps; the local file has older unchecked boxes. Preserve the newer main record. |
| Legacy headless-runtime worktree | 49 | Local WiX tool cache, third-party binaries and extension files only. Do not publish dependencies/build tools. |
| Module-catalog-correlation worktree | 545 | All tracked differences disappear with git diff --ignore-space-at-eol; line-ending-only churn, no semantic patch. |
| Temporary provider checkout A | 763 | All tracked entries are deleted in an incomplete temporary checkout. No replacement source/untracked changes. Do not delete current main source to mirror that checkout. |
| Temporary provider checkout B | 848 | Same incomplete temporary-checkout condition; preserve current main and leave this checkout untouched. |

Original dirty status and file-content digests were retained locally for the final preservation check. No cleanup, reset, branch switch, write, or commit was performed in any original worktree.

## Recovered commits and files

- `ed6ecd867abaf36522b38ecd4f2bb38ba246f901` - `fix(windows): persist the provisioned endpoint origin`; files: `pc_agent/platform/windows/provision.py`, `pc_agent/tests/windows/test_provisioning_contract.py`.
- `ddd3562c837b692f04b1f33599c7fa58463b77ba` - `fix(canary): support native ALT pilot claim delivery`; files: `docs/runbooks/ALT_AGENT_TEST_PILOT.md`, `tests/deploy/test_alt_test_pilot_controller.py`, `tools/provision_alt_test_agent.py`.
- `67a8742063ddfb98cb69dfdd278c95522059c650` - `fix(packaging): preserve verified ALT runtime payloads`; files: `packaging/alt/endpoint-agent.spec`, `tests/packaging/test_alt_rpm_contract.py`.

The documentation commit containing this report also updates the operations cancellation contract, agent module boundary, and reconciliation plan. Its final SHA and remote publication receipt are reported in the task response.

## Verification

Python 3.12.14 was used from the existing local test environment. These commands were executed in the integration checkout:

```text
python -m pytest tests/deploy/test_alt_test_pilot_controller.py tests/packaging/test_alt_rpm_contract.py pc_agent/tests/windows/test_provisioning_contract.py pc_agent/tests/windows/test_service_launcher.py tests/deploy/test_windows_pilot_controller.py tests/architecture/test_no_helpdesk_agent_release_dependencies.py -q
256 passed, 1 skipped

python -m pytest tests/contracts tests/operations tests/deploy/test_alt_agent_bundle_install.py tests/deploy/test_alt_agent_finalizer_protocol.py tests/server/test_console_foundation.py pc_agent/tests/windows/test_probe_network.py -q
565 passed, 13 skipped, 2 existing httpx per-request-cookie deprecation warnings

python tools/contracts/generate_contract_artifacts.py --check
python -m compileall -q endpoint_contracts endpoint_server pc_agent
python -m compileall -q pc_agent/platform/windows/provision.py tools/provision_alt_test_agent.py
git diff --check
```

Windows and ALT/RPM regressions were observed failing before implementation, then passing. The independent reviewer found one important issue (the staging traversal failure); the fix had its own failing regression followed by the 256-test green run. No Critical or Minor review findings remain.

## Limits and retained gates

- The focused local checks cover source behavior and contracts; they are not the full Linux CI suite or installed-agent acceptance.
- The non-production Linux test host was unreachable over SSH. A native ALT RPM build, native systemd execution and live provisioning were not performed.
- GitNexus MCP initialization timed out twice; architecture conclusions were checked against committed source, tests and Git history. No reindex or group synchronization was requested.
- Context7 documentation requests were rejected because its monthly quota was exhausted. Official Python 3.12 and systemd documentation were consulted as fallback.
- No production deployment, service restart, real enrollment, acceptance-sequence execution, claim consumption, artifact publication or fleet-readiness claim is part of this reconciliation.
- Existing immutable evidence and historical candidate branches remain intact. Final remote SHA verification and preservation status are recorded in the task response.
