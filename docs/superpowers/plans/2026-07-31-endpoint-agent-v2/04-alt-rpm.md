# Endpoint Agent V2 Implementation Plan — 04 Alt Rpm

## Task 8: Build and verify the new Linux headless artifact

**Files:**
- Modify: `pc_agent/pyinstaller_endpoint_core_linux.spec`
- Create: `tools/build_linux_agent.py`
- Create: `tests/build/test_linux_headless_artifact.py`
- Modify: release manifest generation

**Interfaces:**
- Produces immutable `linux_amd64` runtime artifact containing the new headless entrypoint.

- [ ] **Step 1: Write artifact-content tests**

Assert the built artifact:

- has the core executable;
- has no Qt libraries;
- has no GUI assets;
- has no `TicketApiClient`;
- contains context collectors and WSS transport;
- supports `--verify`.

- [ ] **Step 2: Build on Linux CI/worker**

```bash
python -m PyInstaller --noconfirm pc_agent/pyinstaller_endpoint_core_linux.spec
python tools/build_linux_agent.py --channel canary
```

- [ ] **Step 3: Run binary smoke**

```bash
dist/endpoint-agent/endpoint-agent --verify \
  --data-dir /tmp/endpoint-agent-verify-data \
  --install-root /tmp/endpoint-agent-verify-install
```

- [ ] **Step 4: Commit build tooling**

---

## Task 9: Migrate the accepted ALT pilot to the headless WSS core

**Files:**
- Modify: `deploy/agent/alt/endpoint-agent.service`
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`
- Create: `docs/verification/ALT_HEADLESS_WSS_CANARY.md`
- Extend deployment tests

**Interfaces:**
- systemd starts the stable launcher;
- selected release starts the new headless entrypoint;
- transport is `gateway_wss`.

- [ ] **Step 1: Verify rollback availability**

Before assigning the canary, verify the accepted immutable rollback release remains present on the controller and test agent.

- [ ] **Step 2: Run local and server preflight**

```text
full focused tests
artifact hash
release immutability
Gateway WSS health
database backup
test-agent service state
current selector
credential ownership/mode
```

- [ ] **Step 3: Assign one-device canary**

Only `test-agent-lin`.

- [ ] **Step 4: Verify new healthy WSS connection**

Require:

- authenticated session;
- heartbeat;
- baseline collection;
- health collection;
- network collection;
- update startup outcome `applied`;
- no request to Helpdesk endpoint;
- no HTTP-pull use unless the migration fallback was explicitly enabled for the test.

- [ ] **Step 5: Force a failed next release**

Prove automatic rollback to the accepted headless release, not merely to the old Helpdesk monolith.

- [ ] **Step 6: Disable migration fallback on the pilot**

Verify the agent remains functional through WSS only.

- [ ] **Step 7: Commit sanitized acceptance evidence**

No tokens, MACs, IP observations, CA paths, or raw context payloads.

---

## Task 10: Create the ALT RPM package

**Files:**
- Create: `packaging/alt/endpoint-agent.spec`
- Create: `packaging/alt/build-rpm.sh`
- Create: `packaging/alt/README.md`
- Create: `packaging/alt/SOURCES/endpoint-agent.tmpfiles`
- Create: `packaging/alt/SOURCES/endpoint-agent.logrotate`
- Create: `tests/packaging/test_alt_rpm_contract.py`

**Interfaces:**
- RPM installs program files and systemd units.
- Environment-specific enrollment claim, endpoint config, and CA are supplied separately.
- Existing device state survives RPM upgrade.

- [ ] **Step 1: Write package contract tests**

Assert:

- no secret in package;
- no production device credential;
- no one-time claim;
- no private key;
- service account is non-login;
- service starts only when required config/CA/credential or claim conditions are satisfied;
- uninstall does not silently delete identity by default.

- [ ] **Step 2: Author RPM spec**

Lifecycle:

```text
install:
  create fixed directories and units
  install launcher and initial version
  daemon-reload

upgrade:
  preserve /var/lib identity and credential
  preserve /etc config and CA
  install new launcher/system units only when package version requires it
  restart only after validation

remove:
  stop/disable service
  preserve state unless explicit purge procedure is run
```

- [ ] **Step 3: Build in clean ALT environment**

```bash
bash packaging/alt/build-rpm.sh
rpm -qpi output/endpoint-agent-*.rpm
rpm -qpl output/endpoint-agent-*.rpm
```

- [ ] **Step 4: Test install, upgrade, and uninstall on disposable ALT**

- [ ] **Step 5: Add external signing procedure**

Do not place the signing key in Git.

- [ ] **Step 6: Commit**

```bash
git add packaging/alt tests/packaging docs
git commit -m "build: package endpoint agent for ALT Linux"
```

---
