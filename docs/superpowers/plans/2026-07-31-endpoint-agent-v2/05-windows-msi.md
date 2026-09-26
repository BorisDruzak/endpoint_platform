# Endpoint Agent V2 Implementation Plan — 05 Windows Msi

## Task 11: Define the Windows service and provisioning contract

**Files:**
- Create: `pc_agent/platform/windows/__init__.py`
- Create: `pc_agent/platform/windows/service.py`
- Create: `pc_agent/platform/windows/provision.py`
- Create: `pc_agent/platform/windows/acl.py`
- Create: `pc_agent/platform/windows/service_control.py`
- Create: `pc_agent/tests/windows/test_service_contract.py`
- Create: `pc_agent/tests/windows/test_provisioning_contract.py`
- Create: `docs/agent/WINDOWS_RUNTIME_DESIGN.md`

**Interfaces:**

Windows service executable modes:

```text
--windows-service
--verify
--print-safe-status
```

Provisioning command:

```text
endpoint-agent-provision.exe
```

It reads the one-time enrollment material from standard input or a protected file, never from a command-line property.

- [ ] **Step 1: Write service tests using injected SCM adapters**

Test install-independent service lifecycle:

- start;
- stop;
- shutdown;
- update exit;
- Gateway reconnect;
- no desktop/UI access.

- [ ] **Step 2: Write provisioning tests**

Provisioning:

- validates Endpoint HTTPS origin;
- validates CA;
- creates protected directories;
- writes one-time material atomically;
- starts service;
- deletes claim after permanent credential proof;
- never prints token.

- [ ] **Step 3: Implement pywin32 service entrypoint**

Run as `LocalService`.

- [ ] **Step 4: Implement ACL helpers**

Expected principals:

```text
SYSTEM
Administrators
NT SERVICE\EndpointAgent
NT SERVICE\EndpointAgentUpdater
```

Ordinary users receive no read access to the device credential.

- [ ] **Step 5: Run tests and commit**

---

## Task 12: Implement the privileged Windows updater

**Files:**
- Create: `pc_agent/platform/windows/updater_service.py`
- Create: `pc_agent/platform/windows/update_paths.py`
- Reuse/refactor: `pc_agent/launcher/installer.py`
- Create: `pc_agent/tests/windows/test_updater_service.py`
- Create: `pc_agent/tests/windows/test_windows_update_rollback.py`

**Interfaces:**
- Demand-start service name: `EndpointAgentUpdater`
- Fixed pending path:
  `C:\ProgramData\Endpoint Platform\Agent\updates\pending_update.json`
- Fixed install root:
  `C:\Program Files\Endpoint Platform\Agent`

- [ ] **Step 1: Write pending-file security tests**

Reject:

- symlink/reparse traversal;
- wrong owner/ACL;
- unknown fields;
- wrong artifact path root;
- hash/size mismatch;
- target version collision with different bytes;
- arbitrary service name;
- arbitrary executable path.

- [ ] **Step 2: Write update lifecycle tests**

```text
validate pending
stop EndpointAgent
extract to staging
run new version --verify
publish immutable version
switch current.json atomically
start EndpointAgent
await server-side startup confirmation
rollback after deadline or early crash
```

- [ ] **Step 3: Implement demand-start service**

It has no listening socket and no HTTP client.

- [ ] **Step 4: Restrict service start permissions**

Only administrators, SYSTEM, and the EndpointAgent service identity may start it.

- [ ] **Step 5: Run tests and commit**

---

## Task 13: Create the machine-wide Windows MSI

**Files:**
- Create: `packaging/windows/build-msi.ps1`
- Create: `packaging/windows/wix/Package.wxs`
- Create: `packaging/windows/wix/Directories.wxs`
- Create: `packaging/windows/wix/Components.wxs`
- Create: `packaging/windows/wix/Services.wxs`
- Create: `packaging/windows/wix/Upgrade.wxs`
- Create: `packaging/windows/README.md`
- Create: `tests/packaging/test_windows_msi_contract.py`
- Modify: Windows release build script to build the headless core, not inherited GUI agent

**Interfaces:**
- Produces one x64 MSI.
- Installs `EndpointAgent` and `EndpointAgentUpdater`.
- Does not embed enrollment material.

- [ ] **Step 1: Write static WiX contract tests**

Assert:

- stable UpgradeCode;
- machine-wide scope;
- x64 components;
- no secret properties;
- no campaign token property;
- no device token property;
- no custom action logs a secret;
- core service uses LocalService;
- updater uses LocalSystem and demand start;
- service recovery policy exists;
- ProgramData ACL is explicit;
- Program Files ACL remains non-user-writable.

- [ ] **Step 2: Build the headless Windows core**

Do not use the inherited GUI-oriented PyInstaller spec.

- [ ] **Step 3: Author MSI components**

MSI installs:

- launcher;
- initial immutable core version;
- service entrypoint;
- updater entrypoint;
- config template;
- public documentation;
- two services.

- [ ] **Step 4: Define upgrade behavior**

Major upgrade:

- preserves ProgramData identity and credential;
- upgrades launcher/services;
- preserves selected runtime unless the package explicitly includes an approved initial runtime transition;
- rolls back MSI transaction on service-install failure.

- [ ] **Step 5: Define uninstall behavior**

Default uninstall:

- removes binaries and services;
- preserves ProgramData enrollment identity for repair/reinstall;
- documents an explicit administrator purge command.

- [ ] **Step 6: Build MSI**

PowerShell:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64
```

- [ ] **Step 7: Inspect MSI**

Generate a file/service/component manifest and verify no secret values are present.

- [ ] **Step 8: Commit**

```powershell
git add packaging/windows tests/packaging pc_agent
git commit -m "build: add Windows endpoint agent MSI"
```

---

## Task 14: Implement Windows Device Context collectors and platform identity

**Files:**
- Create: `pc_agent/platform/windows/identity.py`
- Create: `pc_agent/platform/windows/network.py`
- Create: `pc_agent/platform/windows/storage.py`
- Create: `pc_agent/platform/windows/software.py`
- Create: `pc_agent/tests/windows/test_identity.py`
- Create: `pc_agent/tests/windows/test_context_profiles.py`
- Add sanitized golden fixtures

**Interfaces:**
- Produces the same `baseline_v1`, `health_v1`, `network_v1`, and `diagnostic_v1` contracts as ALT.

- [ ] **Step 1: Write golden profile tests**

Volatile fields remain outside baseline.

- [ ] **Step 2: Implement stable machine identity**

Use bounded Windows APIs and existing proven identity logic. Do not use hostname or IP as identity.

- [ ] **Step 3: Implement collectors**

Avoid unbounded WMI/PowerShell loops. Every external command is fixed, bounded, timed out, and output-limited.

- [ ] **Step 4: Run cross-platform schema tests**

- [ ] **Step 5: Commit**

---

## Task 15: Run the disposable Windows pilot

**Blockers:** `BLOCKER-WIN-BUILD-001`, `BLOCKER-WIN-PILOT-001`

**Files:**
- Create after testing: `docs/verification/WINDOWS_AGENT_MSI_PILOT.md`

- [ ] **Step 1: Snapshot the disposable Windows VM**

- [ ] **Step 2: Install MSI**

Verify:

- services;
- paths;
- ACL;
- no GUI;
- no console window;
- no embedded claim/token.

- [ ] **Step 3: Provision through a protected one-time claim**

Do not pass the claim in an MSI property or process command line.

- [ ] **Step 4: Verify Gateway WSS**

Require:

- enrollment;
- authenticated WSS;
- heartbeat;
- online presence;
- baseline;
- health;
- network.

- [ ] **Step 5: Reboot**

Verify service starts before user login and reconnects.

- [ ] **Step 6: Perform successful update**

Require healthy new-version Gateway confirmation.

- [ ] **Step 7: Perform failed update**

Use a deliberately invalid canary and prove selector/identity safety.

- [ ] **Step 8: Perform rollback**

Verify device identity and credential unchanged.

- [ ] **Step 9: Repair and uninstall MSI**

Verify documented state preservation and explicit purge.

- [ ] **Step 10: Commit sanitized evidence**

---
