# Windows Canary Evidence Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a fresh installed Windows Endpoint Agent produce strict, redacted, truthful evidence for one headless diagnostic canary and its exact terminal completion.

**Architecture:** The Windows runtime writes a fixed protected status projection from real lifecycle and transport facts, while the installer wrapper retains and validates detached MSI provenance. The PowerShell collector only reads those protected artifacts, normalizes Windows SCM values, and feeds the existing Python validator. Preflight and post-operation completion are deliberately separate decisions.

**Tech Stack:** Python 3.14, asyncio, PowerShell 5.1, WiX 4, PyInstaller, pytest.

**Spec:** `docs/superpowers/specs/2026-08-25-windows-canary-evidence-closure-design.md`

## Global Constraints

- Work from a new linked worktree based on current `origin/main`; retain the design and this plan with the implementation branch.
- Endpoint Platform is the only repository changed; Helpdesk is a consumer only.
- Do not add dependencies, database migrations, public API versions, production deployment, claims, tokens, credentials, endpoint URLs, raw command parameters, command lines, certificates, or raw tool results to an evidence artifact.
- Every evidence reader must reject missing, malformed, unprotected, non-regular, or reparse-point artifacts; no default-ready values.
- Preserve the existing top-level `windows_agent_preflight_v1` projection and `command-completions.jsonl` record fields.
- Preflight does not require a completion record. Post-operation verification requires exactly one matching `context.diagnostic.collect` terminal-success record.
- The test device is the dedicated Windows staging agent only. Restore staging feature flags to disabled/legacy state after the fresh single operation.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `pc_agent/platform/windows/canary_status.py` | Fixed-path safe-status schema, strict read/write, redaction and reparse checks. |
| `pc_agent/runtime/application.py` | Windows-only status writer composition and release identity input. |
| `pc_agent/runtime/lifecycle.py` | Publish connecting/running/retry/failure transport facts and attach the exact completion marker. |
| `packaging/windows/build-msi.ps1` | Generate detached release manifest after WiX emits final MSI bytes. |
| `packaging/windows/Install-EndpointAgentCanary.ps1` | Administrator-only reviewed wrapper that validates, caches, then invokes MSI. |
| `tools/canary/Collect-WindowsAgentPreflight.ps1` | Read-only, fail-closed Windows projection collector; optional exact completion mode. |
| `tools/canary/verify_installed_windows_agent.py` | Strict schema validation for safe status, provenance and optional exact completion. |
| Tests listed below | TDD coverage for each trust boundary and regression. |
| `packaging/windows/README.md` | Document detached manifest, wrapper installation and preflight/post-operation workflow. |

## Task 1: Protected Windows canary-status model

**Files:**
- Create: `pc_agent/platform/windows/canary_status.py`
- Create: `pc_agent/tests/windows/test_canary_status.py`
- Modify: `pc_agent/platform/windows/completion_proof.py`

**Interfaces:**
- Consumes: `read_completion_proofs(data_root: Path) -> tuple[dict[str, object], ...]`.
- Produces: `CanaryStatusWriter(data_root: Path, release: Mapping[str, str])`, `write_transport(*, strict_tls: bool, hostname_valid: bool, redirected: bool, gateway_wss: bool, http_fallback: bool) -> None`, and `read_canary_status(data_root: Path) -> dict[str, object]`.
- Contract: the only serialized fields are `schema_version`, `release`, `transport`, `capability`, and `completion_proof`; `completion_proof` is `None` or one existing bounded completion record.

- [ ] **Step 1: Write failing schema and redaction tests**

```python
def test_status_round_trip_contains_only_bounded_public_fields(tmp_path: Path) -> None:
    writer = CanaryStatusWriter(tmp_path, {"version": "3.2.22", "source_revision": "a" * 40})
    writer.write_transport(strict_tls=True, hostname_valid=True, redirected=False, gateway_wss=True, http_fallback=False)
    status = read_canary_status(tmp_path)
    assert set(status) == {"schema_version", "release", "transport", "capability", "completion_proof"}
    assert status["transport"]["gateway_wss"] is True
    assert "endpoint_origin" not in repr(status)

def test_status_rejects_reparse_file_and_unknown_key(tmp_path: Path) -> None:
    path = tmp_path / CANARY_STATUS_FILENAME
    path.write_text('{"unexpected":true}', encoding="utf-8")
    with pytest.raises(CanaryStatusError, match="schema"):
        read_canary_status(tmp_path)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            "pc_agent.platform.windows.canary_status._is_reparse_point", lambda _path: True
        )
        with pytest.raises(CanaryStatusError, match="reparse"):
            read_canary_status(tmp_path)
```

- [ ] **Step 2: Run the focused test to verify failure**

Run: `python -m pytest pc_agent/tests/windows/test_canary_status.py -q`

Expected: collection fails because `canary_status` does not exist.

- [ ] **Step 3: Implement the fixed safe-status module**

```python
CANARY_STATUS_FILENAME = "canary-status.json"
CANARY_STATUS_SCHEMA = "endpoint_windows_canary_status_v1"
CANARY_CAPABILITY = "context.diagnostic.collect"

def read_canary_status(data_root: Path) -> dict[str, object]:
    _require_nonreparse_directory(data_root)
    path = data_root / CANARY_STATUS_FILENAME
    _require_regular_nonreparse_file(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    return _validate_status(value)
```

Use `lstat`, exact-key validation, UTF-8 JSON, atomic same-directory replacement,
mode `0o600`, and the existing completion-record validator. Store no transport
addresses or exception text. A writer must emit non-ready facts on start/retry/
failure rather than retain a previous successful state.

- [ ] **Step 4: Add completion-selection tests and implementation**

```python
def test_status_exposes_only_the_matching_completion_record(tmp_path: Path) -> None:
    writer = WindowsCompletionProofWriter(tmp_path)
    writer.append_marker(_marker("command-a"))
    writer.append_marker(_marker("command-b"))
    status = CanaryStatusWriter(tmp_path, _release())
    status.with_completion("command-b")
    assert read_canary_status(tmp_path)["completion_proof"] == _marker("command-b")
```

Expose `with_completion(command_id: str) -> None`; it reads validated existing
records, stores `None` when no matching marker exists, and rejects multiple
matching records. It must not append, mutate, or duplicate completion records.

- [ ] **Step 5: Run focused tests and commit**

Run: `python -m pytest pc_agent/tests/windows/test_canary_status.py pc_agent/tests/windows/test_completion_proof.py -q`

Expected: PASS.

```powershell
git add pc_agent/platform/windows/canary_status.py pc_agent/platform/windows/completion_proof.py pc_agent/tests/windows/test_canary_status.py
git commit -m "feat(agent): persist Windows canary status"
```

## Task 2: Publish truthful runtime lifecycle facts

**Files:**
- Modify: `pc_agent/runtime/application.py`
- Modify: `pc_agent/runtime/lifecycle.py`
- Modify: `pc_agent/tests/runtime/test_headless_lifecycle.py`
- Modify: `pc_agent/tests/runtime/test_command_completion_marker.py`
- Modify: `pc_agent/tests/transport/test_websocket_reconnect.py`

**Interfaces:**
- Consumes: `CanaryStatusWriter` from Task 1.
- Produces: a `RuntimeDependencies.create_canary_status_writer` factory and lifecycle transitions that publish only actual state.
- Contract: startup/retry/failure statuses are non-ready; only a successful WSS handshake with HTTPS settings records strict TLS, hostname validation, no redirect, WSS true and HTTP fallback false.

- [ ] **Step 1: Write failing runtime integration tests**

```python
@pytest.mark.asyncio
async def test_windows_wss_handshake_publishes_ready_transport(monkeypatch, settings):
    observed: list[dict[str, object]] = []
    dependencies = _dependencies_with_status_sink(observed.append)
    await RuntimeLifecycle(settings, dependencies, RuntimeStatus()).run()
    assert observed[-1]["transport"] == {
        "strict_tls": True, "hostname_valid": True, "redirected": False,
        "gateway_wss": True, "http_fallback": False,
    }
```

Add counterpart assertions for a retryable WSS failure and an enabled HTTP
migration fallback: neither may publish preflight-ready facts.

- [ ] **Step 2: Run focused runtime tests to verify failure**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/transport/test_websocket_reconnect.py pc_agent/tests/runtime/test_command_completion_marker.py -q`

Expected: new status assertions fail before runtime wiring exists.

- [ ] **Step 3: Add Windows-only status factory and lifecycle hooks**

```python
def _create_canary_status_writer(settings: object):
    if os.name != "nt" or not isinstance(settings, RuntimeSettings):
        return None
    return CanaryStatusWriter(settings.data_root, {
        "version": AGENT_VERSION, "source_revision": _read_selector_revision(settings.install_root),
    })
```

Extend `RuntimeDependencies` with an optional writer factory. In
`RuntimeLifecycle.run`, publish non-ready facts before connect and on all
retry/terminal paths. Immediately after `transport.connect(hello)` returns,
publish ready facts only when `settings.transport_mode == "gateway_wss"`,
`migration_http_pull_fallback is False`, and `endpoint_origin` passed existing
HTTPS validation. Do not add an HTTP probe or any separate network client.

- [ ] **Step 4: Attach exact completion after bounded marker emission**

```python
emit_command_completed_marker(command, result, duration_ms, completion_sink=completion_sink)
if status_writer is not None:
    status_writer.with_completion(str(command.command_id))
```

Keep this order inside the shared command-completion path so the status points
to an already durable bounded marker. Test that command parameters and result
items are absent from every status writer invocation.

- [ ] **Step 5: Run focused tests and commit**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/transport/test_websocket_reconnect.py pc_agent/tests/runtime/test_command_completion_marker.py pc_agent/tests/windows/test_canary_status.py -q`

Expected: PASS.

```powershell
git add pc_agent/runtime/application.py pc_agent/runtime/lifecycle.py pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/runtime/test_command_completion_marker.py pc_agent/tests/transport/test_websocket_reconnect.py
git commit -m "feat(agent): publish canary runtime facts"
```

## Task 3: Detached MSI provenance and reviewed installation wrapper

**Files:**
- Modify: `packaging/windows/build-msi.ps1`
- Create: `packaging/windows/Install-EndpointAgentCanary.ps1`
- Modify: `tests/packaging/test_windows_msi_contract.py`
- Create: `tests/packaging/test_windows_canary_wrapper_contract.py`

**Interfaces:**
- Produces detached `EndpointAgent-<version>-x64.release.json` with exact keys `schema_version`, `version`, `product_code`, `source_revision`, `initial_runtime_tree_sha256`, `package_sha256`.
- Produces a PowerShell `Install-EndpointAgentCanary.ps1 -MsiPath <path> -ReleaseManifest <path>` boundary that writes only fixed cache/provenance paths beneath the local ProgramData root.
- Contract: wrapper validates detached manifest and computed hash, stores fixed cache/provenance artifacts below ProgramData, then calls `msiexec`; it accepts no claims/tokens/credentials.

- [ ] **Step 1: Write failing provenance tests**

```python
def test_wrapper_requires_exact_msi_and_detached_manifest_inputs() -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    assert "[Parameter(Mandatory = $true)][string]$MsiPath" in source
    assert "[Parameter(Mandatory = $true)][string]$ReleaseManifest" in source
    assert "Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256" in source
    assert "msiexec.exe" in source

def test_wrapper_rejects_secret_inputs_and_uses_fixed_provenance_paths() -> None:
    source = WRAPPER.read_text(encoding="utf-8").lower()
    assert all(term not in source for term in ("claim", "token", "credential", "password"))
    assert "installer-cache" in source and "installer-provenance.json" in source
```

- [ ] **Step 2: Run focused test to verify failure**

Run: `python -m pytest tests/packaging/test_windows_canary_wrapper_contract.py -q`

Expected: collection fails because the wrapper and its static contract do not exist.

- [ ] **Step 3: Implement the reviewed PowerShell wrapper**

```powershell
$cacheRoot = 'C:\ProgramData\Endpoint Platform\Agent\installer-cache'
$provenancePath = Join-Path $cacheRoot 'installer-provenance.json'
$hash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne [string]$manifest.package_sha256) { throw 'MSI SHA-256 does not match release manifest.' }
Copy-Item -LiteralPath $MsiPath -Destination (Join-Path $cacheRoot 'EndpointAgent.msi') -Force
[IO.File]::WriteAllText($provenancePath, ($manifest | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
```

Validate both input files and every existing parent with `Get-Item -Force` and
the reparse-point attribute before copy. Require an exact release-manifest key
set and 64-character lower-case SHA-256. The wrapper creates a fixed cache
directory only below `C:\ProgramData\Endpoint Platform\Agent`, starts MSI
installation with the original MSI, waits for its exit code, then rechecks the
ProgramData DACL that the existing MSI custom action applies. It deletes no
pre-existing installer cache and passes no user-provided value to a service or
MSI property.

- [ ] **Step 4: Generate release manifest after WiX builds final bytes**

```powershell
$releaseManifestPath = Join-Path $releaseRoot "EndpointAgent-$Version-x64.release.json"
Write-Utf8NoBom $releaseManifestPath (@{
    schema_version = 'endpoint_windows_release_v1'; version = $Version
    source_revision = $sourceRevision
    initial_runtime_tree_sha256 = [string]$manifestPreview.artifact.tree_sha256
    package_sha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Compress)
```

Read the actual ProductCode from the built MSI inspection rather than inventing
one. Add the PowerShell wrapper with mandatory `-MsiPath`, `-ReleaseManifest`,
and fixed ProgramData root validation; verify/copy first, then invoke
`msiexec.exe /i` with the original MSI path. The wrapper must return nonzero on
any validation or install failure.

- [ ] **Step 5: Add static packaging security tests and run**

Run: `python -m pytest tests/packaging/test_windows_msi_contract.py tests/packaging/test_windows_canary_wrapper_contract.py -q`

Expected: PASS; tests assert detached manifest is written after `wix build`,
wrapper has no secret-bearing option/property, and cached provenance is fixed,
regular, and protected.

- [ ] **Step 6: Commit**

```powershell
git add packaging/windows/build-msi.ps1 packaging/windows/Install-EndpointAgentCanary.ps1 tests/packaging/test_windows_msi_contract.py tests/packaging/test_windows_canary_wrapper_contract.py
git commit -m "feat(packaging): retain Windows installer provenance"
```

## Task 4: Fail-closed collector and validator

**Files:**
- Modify: `tools/canary/Collect-WindowsAgentPreflight.ps1`
- Modify: `tools/canary/verify_installed_windows_agent.py`
- Modify: `tests/canary/test_verify_installed_windows_agent.py`
- Create: `tests/canary/test_collect_windows_agent_preflight_contract.py`

**Interfaces:**
- Consumes: `canary-status.json`, installer provenance/cache, selector, service facts, existing manifest agent identity.
- Produces: existing `windows_agent_preflight_v1` projection and `validate_preflight(..., require_completion: CompletionExpectation | None = None)`.
- Contract: preflight permits `completion_proof: null`; post-operation requires exactly one matching command id, diagnostic capability, and `succeeded` status.

- [ ] **Step 1: Write failing strict validator tests**

```python
def test_scm_auto_is_normalized_before_strict_validation() -> None:
    projection = _valid_projection(); projection["services"]["agent"]["start_mode"] = "Auto"
    assert validate_preflight(_normalize_projection(projection), _manifest())["status"] == "READY"

def test_post_operation_requires_exact_terminal_completion() -> None:
    expected = CompletionExpectation(command_id=COMMAND_ID, capability="context.diagnostic.collect")
    with pytest.raises(WindowsPreflightError, match="completion"):
        validate_preflight(_valid_projection(completion=None), _manifest(), require_completion=expected)
```

Also cover cache hash mismatch, safe-status unknown key, false TLS/fallback,
stale release mismatch, duplicate/nonmatching completion, and forbidden value
redaction.

- [ ] **Step 2: Run test to verify failure**

Run: `python -m pytest tests/canary/test_verify_installed_windows_agent.py tests/canary/test_collect_windows_agent_preflight_contract.py -q`

Expected: new completion and artifact tests fail before the collector/validator changes.

- [ ] **Step 3: Implement PowerShell evidence reads and canonicalization**

```powershell
function ConvertTo-CanonicalServiceStartMode {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -eq 'Auto') { return 'Automatic' }
    if ($Value -in @('Manual', 'Disabled', 'Boot', 'System', 'Automatic')) { return $Value }
    throw 'Windows service start mode is unsupported.'
}
```

Add `-RequireCompletion`, `-ExpectedCommandId`, and `-ExpectedCapability`
parameters as an all-or-nothing set. Validate data-root and fixed filenames for
regular non-reparse files before parsing JSON. Read only the allow-listed safe
status and provenance fields. Remove the hard-coded MSI and network defaults.
Never serialize file paths, command lines, identity contents, credentials, or
raw completion payloads.

- [ ] **Step 4: Implement Python structural validation and CLI mode**

```python
@dataclass(frozen=True, slots=True)
class CompletionExpectation:
    command_id: str
    capability: str = "context.diagnostic.collect"

def validate_preflight(projection, manifest, *, require_completion=None) -> dict[str, object]:
    _validate_completion(_mapping(projection["completion_proof"], name="completion"), require_completion)
    return {"status": "READY", "platform": "windows_amd64"}
```

Extend the CLI with optional paired `--require-completion-command-id` and
`--require-completion-capability` arguments. Require both or neither. Keep the
preflight result schema unchanged and convert all validation failures to exit
code `2`.

- [ ] **Step 5: Run tests and commit**

Run: `python -m pytest tests/canary/test_verify_installed_windows_agent.py tests/canary/test_collect_windows_agent_preflight_contract.py tests/packaging/test_windows_msi_contract.py -q`

Expected: PASS.

```powershell
git add tools/canary/Collect-WindowsAgentPreflight.ps1 tools/canary/verify_installed_windows_agent.py tests/canary/test_verify_installed_windows_agent.py tests/canary/test_collect_windows_agent_preflight_contract.py
git commit -m "fix(canary): collect truthful Windows evidence"
```

## Task 5: Documentation, full checks, staging release and evidence

**Files:**
- Modify: `packaging/windows/README.md`
- Modify: `docs/superpowers/specs/2026-08-25-windows-canary-evidence-closure-design.md` only if implementation reveals a contradicted requirement; otherwise leave immutable.
- Create: `docs/acceptance/windows-headless-diagnostic-canary-v1.md`

**Interfaces:**
- Consumes: the release manifest/wrapper, collector with completion mode, and the existing staging deployment procedure.
- Produces: reviewed operator runbook and a redacted acceptance record naming hashes/commit/revisions without secret values.

- [ ] **Step 1: Write documentation assertions and operator sequence**

```markdown
1. Build from a clean source revision; retain the MSI and adjacent `.release.json`.
2. Install only with `Install-EndpointAgentCanary.ps1` on the dedicated staging device.
3. Run normal preflight; abort on a nonzero validator result.
4. Create one fresh diagnostic operation, then run collector and validator with its command id.
5. Verify evidence hashes, retain encrypted off-device copy, and restore staging rollback flags.
```

Document that direct `msiexec` is not strict-canary eligible, no production
deployment occurs, and the operation must not be automatically retried.

- [ ] **Step 2: Run focused and full repository verification**

Run:

```powershell
python -m pytest pc_agent/tests/windows/test_canary_status.py pc_agent/tests/windows/test_completion_proof.py pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/transport/test_websocket_reconnect.py tests/canary/test_verify_installed_windows_agent.py tests/canary/test_collect_windows_agent_preflight_contract.py tests/packaging/test_windows_msi_contract.py tests/packaging/test_windows_canary_wrapper_contract.py -q
python scripts/verify_workspace.py
git diff --check
```

Expected: all commands exit `0`.

- [ ] **Step 3: Build and validate the new Windows release**

Run the documented `packaging/windows/build-msi.ps1` command from a clean
worktree, verify the final MSI SHA against its detached release manifest, then
inspect the generated MSI binding/inspection artifacts for the fixed accounts,
no secret-bearing properties, and expected source revision. Record only hashes
and revisions in acceptance evidence.

- [ ] **Step 4: Perform one staging canary and rollback**

On the dedicated Windows staging machine, invoke the reviewed wrapper, start
the normal `EndpointAgent` service, collect/validate preflight, create one new
device/ticket/operation through the staging services, and collect/validate
post-operation evidence using the exact command identifier. Package redacted
artifacts with checksums, make an encrypted off-device copy, verify it by a
read-back hash/listing, then restore the documented endpoint/helpdesk staging
flags and verify service health.

- [ ] **Step 5: Commit documentation and prepare review**

```powershell
git add packaging/windows/README.md docs/acceptance/windows-headless-diagnostic-canary-v1.md
git commit -m "docs(canary): record Windows staging acceptance"
git status --short
git diff --check
```

Expected: clean worktree and no whitespace errors. Create the Endpoint PR,
run its required CI, merge only after all checks are green, and update the
acceptance document with the deployed merge SHA and validated staging result.

## Plan self-review

- **Spec coverage:** installer provenance (Task 3); protected truthful runtime status and existing completion records (Tasks 1–2); `Auto` normalization and strict collector/validator split (Task 4); single staging operation, rollback, encrypted evidence and no production deployment (Task 5).
- **Placeholders:** no deferred implementation phrases or unnamed validations; tests, commands, fields and failure conditions are specified per task.
- **Interface consistency:** Tasks 2 and 4 consume the exact `CanaryStatusWriter`, `read_canary_status`, release-manifest and `CompletionExpectation` contracts defined by Tasks 1 and 3.
