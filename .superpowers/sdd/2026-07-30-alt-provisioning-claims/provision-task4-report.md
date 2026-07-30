# Task 4 — local integration acceptance

## Scope and safety boundary

Acceptance ran locally on 2026-07-30 in `C:\Users\admin-2\Documents\endpoint`
at `b3f427b` (`codex/bootstrap-design`).  Panel checks used only the clean linked
worktree `C:\Users\admin-2\Documents\web_ovpn-device-context` at `a9053d7`
(`codex/device-context-integration`).  Both worktrees were clean before this
evidence file was created.

No remote host, test host, deployment target, systemd command, or ALT agent
binary was executed.  No package was published or fetched.  The only temporary
install was the reviewed Python SDK wheel into a disposable local virtual
environment for its required import-contract proof.

## Focused acceptance coverage

Endpoint Platform command:

```text
python -m pytest tests/contracts/test_contract_models.py tests/contracts/test_contract_artifacts.py tests/sdk/test_provisioning_client.py tests/sdk/test_packaging.py tests/server/test_provisioning_claim_api.py tests/server/test_enrollment_campaigns.py tests/server/test_agent_enrollment_api.py pc_agent/tests/test_enrollment_bootstrap.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py -q
282 passed, 4 skipped in 57.20s
```

This covers contract models/artifacts; typed provisioning client validation,
redaction, no-retry and wheel packaging; scoped claim issuance and enrollment
state; first-boot agent bootstrap; and offline ALT installer/finalizer contract
behavior.  The four skips are the existing platform-limited cases; there were
no failures.

Contract artifacts were also checked without rewriting them:

```text
python tools/contracts/generate_contract_artifacts.py --check
exit 0
```

Panel command, run only in the linked worktree:

```text
python -m pytest tests/test_provisioning_claim_writer.py tests/test_provisioning_controller.py tests/test_endpoint_platform_client.py tests/test_endpoint_context_api.py -q
22 passed, 1 skipped in 7.02s
```

The selected panel tests cover browser-session and CSRF authorization, safe
state-only response/audit behavior, replay and uncertain handoff handling,
scoped SDK boundary behavior, and Endpoint Context integration.  The one skip
is the POSIX Unix-socket writer round-trip, which is unavailable on this Windows
workstation.  Existing FastAPI/Starlette and pytest-asyncio deprecation warnings
were emitted but caused no failures.

The panel's full suite was deliberately not run: it contains 1098 tests,
including known slow QEMU coverage.  The focused provisioning and relevant
Endpoint integration tests above exercise this task's changed boundary without
starting that unrelated long-running suite.

## Standalone SDK and package evidence

The standalone SDK was built with no dependency resolution and installed only
into a disposable virtual environment:

```text
python -m pip wheel --no-deps --no-build-isolation --wheel-dir <temporary-wheelhouse> sdk/python
<temporary-venv>\Scripts\python.exe -m pip install --no-deps <built-wheel>
<temporary-venv>\Scripts\python.exe -c <panel-import-proof>
wheel-only-web-import EndpointPlatformClient EndpointProvisioningClient InstallClaim
```

The proof inserted only the panel worktree on `sys.path`, asserted that the
Endpoint Platform root was absent, imported the panel provisioning controller,
and verified that `endpoint_platform_client` resolved from the temporary
virtual environment's `site-packages`.  The temporary virtual environment used
the workstation's already-installed third-party runtime dependencies; it did
not use the Endpoint Platform source tree and did not fetch packages.

Temporary SDK wheel (not committed):

```text
C:\Temp\endpoint-task4-18366b1c92f640388c9b561917a952f8\wheelhouse\endpoint_platform_client-0.1.0-py3-none-any.whl
SHA-256: 4e053a77315d9ef3e09f7cce78ae45bcc82ad23fb22375c7b028d07e01c7b358
```

Generic Linux PyInstaller specifications and materials exist under `pc_agent`,
but there is no approved reproducible ALT-compatible single-executable/package
builder or canonical reviewed ALT binary in this worktree.  The offline
installer explicitly requires an externally supplied `--agent-binary`; the
tracked offline-install bundle inputs are the installer, unit, default
configuration, and runbook.  Producing an ALT-compatible binary would require
a separate approved build workflow and review, which are outside this
local-only task.

For source-integrity inspection only, a temporary `git archive` was created
from exactly those four reviewed inputs.  It is **not** a deployable ALT package
and must not be installed:

```text
C:\Temp\endpoint-task4-18366b1c92f640388c9b561917a952f8\endpoint-alt-package-b3f427b.tar.gz
SHA-256: 95e461bea6e2141d1dd190bbeae143716cadcfdea0a9e3a79f8d7a61bca7f79d
payload files: 4
```

This missing canonical builder/binary is the Task 4 package-build acceptance
blocker.  No binary or builder was invented, and the temporary source bundle is
not committed.

## Redaction and repository-state scan

The scan inspected content rather than semantic identifier names.  It searched
for the canonical install-claim wire grammar and for 43-character URL-safe
opaque values, reporting only counts and file classes so a scan cannot disclose
a candidate.  It skipped binary and files larger than 1 MiB.

```text
fixtures: 16 files, claim candidates 0, opaque-value candidates 0
artifacts: 3 files, claim candidates 0, opaque-value candidates 0
logs: 5 files, claim candidates 0, opaque-value candidates 0
environment examples: 12 files, claim candidates 0, opaque-value candidates 0
temporary ALT archive payload: 4 files, claim candidates 0, opaque-value candidates 0
```

The fixture count refers to `tests/fixtures`; test source is covered by the
executed redaction tests and is not treated as a runtime fixture.  No actual
claim or permanent device credential was found in the inspected logs, fixtures,
artifacts, environment examples, or archive payload.

Before this report was added, Endpoint unstaged and staged diffs were both zero
bytes, the panel diff was zero bytes, and both `git diff --check` commands
returned zero.  The final Endpoint diff is re-scanned before committing this
report; the panel worktree remains untouched.

## Evidence precision addendum

The endpoint test command did execute the installer in two non-installing,
isolated test modes. `test_package_layout_is_fixed_and_inspectable_without_root`
ran `bash deploy/agent/alt/install-endpoint-agent.sh --inspect-layout`, which
only printed the fixed layout. The finalizer protocol tests copied the installer
to a temporary, path-rewritten test root and exercised finalizer cases there.
Those executions did not run installation mode, use real host paths, create
users, start services, or mutate real host files.

### Reproducible content scan

The following PowerShell procedure is the exact scan method. It emits only
counts, never matching content. It scans the enumerated input categories:
Endpoint `tests/fixtures`, `artifacts`, all `*.log` files, all `.env.example`
files in both worktrees, the extracted temporary source-bundle payload, and the
final committed diff. Its heuristics search a canonical claim-shaped value and
a 43-character URL-safe opaque value; semantic names such as `claim` or
`token` are intentionally not treated as findings. It excludes files larger
than 1 MiB and content containing a NUL byte, and it does not treat test source
as a runtime fixture.

```powershell
$endpoint = 'C:\Users\admin-2\Documents\endpoint'
$web = 'C:\Users\admin-2\Documents\web_ovpn-device-context'
$archive = 'C:\Temp\endpoint-task4-18366b1c92f640388c9b561917a952f8\endpoint-alt-package-b3f427b.tar.gz'
$extract = Join-Path ([IO.Path]::GetTempPath()) 'endpoint-task4-scan'
New-Item -ItemType Directory -Force -Path $extract | Out-Null
tar -xzf $archive -C $extract
$claim = [regex]'(?<![A-Za-z0-9_-])ic_[0-9a-f]{32}\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])'
$opaque = [regex]'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])'
function Measure-Content([string]$label, [string]$content) {
  "$label claim_candidates=$($claim.Matches($content).Count) opaque_43_candidates=$($opaque.Matches($content).Count)"
}
function Scan-Files([string]$label, [IO.FileInfo[]]$files) {
  $text = [Text.StringBuilder]::new(); $count = 0
  foreach ($file in $files) {
    if ($file.Length -gt 1MB) { continue }
    try { $content = [IO.File]::ReadAllText($file.FullName) } catch { continue }
    if ($content.IndexOf([char]0) -ge 0) { continue }
    [void]$text.Append($content); $count++
  }
  "$label files=$count $(Measure-Content $label $text.ToString())"
}
Scan-Files 'fixtures' @(Get-ChildItem "$endpoint\tests\fixtures" -Recurse -File)
Scan-Files 'artifacts' @(Get-ChildItem "$endpoint\artifacts" -Recurse -File)
Scan-Files 'logs' @(Get-ChildItem $endpoint -Recurse -File -Filter '*.log')
Scan-Files 'env_examples' @(
  Get-ChildItem $endpoint -Recurse -Force -File -Filter '.env.example'
  Get-ChildItem $web -Recurse -Force -File -Filter '.env.example'
)
Scan-Files 'built_alt_archive_payload' @(Get-ChildItem $extract -Recurse -File)
Measure-Content 'final_committed_diff' ((git -C $endpoint show --format= --no-ext-diff HEAD) | Out-String)
git -C $endpoint show --check HEAD
```

For this evidence revision, the report is force-added because the SDD ledger
directory is intentionally ignored. The exact staged report diff is scanned
immediately before commit with the same two value heuristics, and the committed
diff is scanned again after commit. Both results are recorded as zero
claim-shaped and zero opaque-value candidates; `git show --check HEAD` exits
zero. The panel worktree stays at zero diff.

## Deployment gate

The local test evidence is green, but Task 4 is not fully accepted because a
reviewed, deployable ALT package cannot be built from the repository's current
assets.  Do not install on `test-agent-lin` or deploy anywhere until an approved
Linux package/binary build workflow exists and the resulting artifact receives
separate review.
