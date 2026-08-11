# ALT RPM Automatic Gateway Enrollment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make first ALT RPM installation enroll and start an Endpoint Gateway agent automatically while retaining the immutable update/rollback lifecycle.

**Architecture:** Deployment creates three root-only bootstrap files before `rpm -Uvh`. RPM `%pre` rejects unsafe files on first install, and `%post` invokes a fixed helper that delegates to the audited installer. A root-only systemd path/service pair detects the enrolled agent's proof, removes the one-time claim, switches the unit to Gateway mode, and restarts the unprivileged service.

**Tech Stack:** ALT RPM scriptlets, Bash, systemd, existing Endpoint enrollment/Gateway runtime, pytest.

## Global Constraints

- Gateway origin is exactly `https://endpoint.sosnadmin.local`; no IP, HTTP, TLS bypass, or Helpdesk fallback.
- Bootstrap files are `/etc/endpoint-agent/bootstrap/{installation-id,ca.crt,provisioning-claim}`, all root-owned `0600` regular files with no symlink parent.
- Claims are device-bound, short-lived, one-time server credentials; no claim or permanent credential may enter RPM payloads, logs, or update artifacts.
- Only first install consumes bootstrap input. Upgrade preserves `/opt/endpoint-agent`, permanent credential, and current selector without requiring a new claim.
- `endpoint-agent` remains unprivileged; finalizer and update worker are root-only.

---

### Task 1: Test and package the first-install bootstrap contract

**Files:**
- Modify: `pc_agent/build_alt_rpm_source.py`
- Modify: `deploy/agent/alt/rpm/endpoint-agent.spec`
- Modify: `pc_agent/tests/test_build_alt_rpm_source.py`
- Modify: `tests/deploy/test_alt_agent_rpm.py`

**Interfaces:**
- Consumes: fixed bootstrap inputs.
- Produces: archive assets plus `%pre` and `%post` behavior gated by RPM argument `$1 == 1`.

- [ ] **Step 1: Write the failing tests**

```python
def test_rpm_source_contains_enrollment_assets(...):
    assert ".../provision/rpm-auto-provision.sh" in names
    assert ".../provision/endpoint-agent-finalize.path" in names
    assert ".../provision/endpoint-agent-finalize.service" in names

def test_rpm_runs_provisioner_only_on_first_install():
    assert 'if [ "$1" -eq 1 ]; then' in spec
    assert '/usr/lib64/endpoint-agent/provision/rpm-auto-provision.sh' in spec
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest pc_agent/tests/test_build_alt_rpm_source.py tests/deploy/test_alt_agent_rpm.py -v --tb=short`

Expected: FAIL because the assets and scriptlet contract are absent.

- [ ] **Step 3: Implement the minimum contract**

Add the new assets to `_PROVISIONING_ASSETS`.  Add `%pre` validation of all three fixed files and all existing parent components: root owner, `0600`, regular file, no symlink.  Add `%post` first-install delegation to the fixed helper and return a failure after disabling any newly enabled service.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest pc_agent/tests/test_build_alt_rpm_source.py tests/deploy/test_alt_agent_rpm.py -v --tb=short`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add pc_agent/build_alt_rpm_source.py pc_agent/tests/test_build_alt_rpm_source.py deploy/agent/alt/rpm/endpoint-agent.spec tests/deploy/test_alt_agent_rpm.py`

Run: `git commit -m "build: require secure ALT RPM bootstrap inputs"`

### Task 2: Implement the root-only auto-provision helper

**Files:**
- Create: `deploy/agent/alt/rpm-auto-provision.sh`
- Modify: `tests/deploy/test_alt_agent_rpm.py`
- Modify: `deploy/agent/alt/rpm/README.md`
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`

**Interfaces:**
- Consumes: `/etc/endpoint-agent/bootstrap/{installation-id,ca.crt,provisioning-claim}`.
- Produces: a fixed invocation of `install-endpoint-agent.sh` and removal of only the staged claim after successful handoff.

- [ ] **Step 1: Write the failing helper test**

```python
def test_rpm_auto_provisioner_uses_fixed_endpoint_and_paths():
    helper = (ROOT / "deploy/agent/alt/rpm-auto-provision.sh").read_text()
    assert 'readonly ENDPOINT_URL=https://endpoint.sosnadmin.local' in helper
    assert 'readonly BOOTSTRAP_ROOT=/etc/endpoint-agent/bootstrap' in helper
    assert 'rm -f -- "$CLAIM_FILE"' in helper
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/deploy/test_alt_agent_rpm.py::test_rpm_auto_provisioner_uses_fixed_endpoint_and_paths -v --tb=short`

Expected: FAIL because the helper does not exist.

- [ ] **Step 3: Implement the helper**

```bash
readonly ENDPOINT_URL=https://endpoint.sosnadmin.local
readonly BOOTSTRAP_ROOT=/etc/endpoint-agent/bootstrap
readonly INSTALLATION_ID_FILE="$BOOTSTRAP_ROOT/installation-id"
readonly CA_FILE="$BOOTSTRAP_ROOT/ca.crt"
readonly CLAIM_FILE="$BOOTSTRAP_ROOT/provisioning-claim"
```

The helper revalidates paths, rejects an invalid installation ID, invokes the packaged installer with the fixed URL and release bundle, then removes only `CLAIM_FILE` after installer success. It never removes the installed handoff, because the finalizer owns that transition.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest tests/deploy/test_alt_agent_rpm.py -v --tb=short`

Run: `bash -n deploy/agent/alt/rpm-auto-provision.sh`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add deploy/agent/alt/rpm-auto-provision.sh deploy/agent/alt/rpm/README.md docs/runbooks/ALT_AGENT_INSTALL.md tests/deploy/test_alt_agent_rpm.py`

Run: `git commit -m "pc_agent: provision Gateway agent from ALT RPM"`

### Task 3: Finalize enrollment automatically under systemd

**Files:**
- Create: `deploy/agent/alt/endpoint-agent-finalize.path`
- Create: `deploy/agent/alt/endpoint-agent-finalize.service`
- Modify: `deploy/agent/alt/install-endpoint-agent.sh`
- Modify: `pc_agent/build_alt_rpm_source.py`
- Modify: `tests/deploy/test_alt_agent_package.py`
- Modify: `tests/deploy/test_alt_agent_finalizer_protocol.py`

**Interfaces:**
- Consumes: `/var/lib/endpoint-agent/claim-removal-request.json` after successful enrollment.
- Produces: Gateway-ready unit, removed claim/request, and an active restarted `endpoint-agent.service`.

- [ ] **Step 1: Write failing finalizer tests**

```python
def test_install_enables_and_starts_finalizer_path(...):
    assert 'endpoint-agent-finalize.path' in installer
    assert 'systemctl enable endpoint-agent-finalize.path' in installer

def test_finalizer_restarts_gateway_ready_service(...):
    assert 'systemctl restart endpoint-agent.service' in installer
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py -v --tb=short`

Expected: FAIL because finalizer units and restart behavior are absent.

- [ ] **Step 3: Implement the finalizer**

```ini
[Path]
PathExists=/var/lib/endpoint-agent/claim-removal-request.json
Unit=endpoint-agent-finalize.service
```

Create the corresponding root-only oneshot service with `ExecStart=/usr/lib64/endpoint-agent/provision/install-endpoint-agent.sh --finalize-handoff`. Stage/install/enable/start the path after the update path. Extend `finalize_handoff()` to daemon-reload, restart the agent, and require an active result while retaining existing proof and symlink checks.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py -v --tb=short`

Expected: PASS.

- [ ] **Step 5: Commit**

Run: `git add deploy/agent/alt/endpoint-agent-finalize.path deploy/agent/alt/endpoint-agent-finalize.service deploy/agent/alt/install-endpoint-agent.sh pc_agent/build_alt_rpm_source.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py`

Run: `git commit -m "pc_agent: finalize ALT Gateway enrollment automatically"`

### Task 4: Verify native ALT installation and upgrade

**Files:**
- Modify: `deploy/agent/alt/rpm/README.md`
- Test: native ALT RPM, Gateway audit, and targeted pytest suite.

**Interfaces:**
- Consumes: controller-issued test-host bootstrap files.
- Produces: active Gateway service, permanent credential, deleted claim, verified handshake, then an RPM upgrade without re-provisioning.

- [ ] **Step 1: Build and inspect the native RPM**

Run the established release-bundle and `build-rpm.sh` flow. Verify `rpm -K`, package payload/scriptlets, and `rpm -Uvh --test`.

- [ ] **Step 2: Install with a one-time claim**

Create only the three bootstrap files as `root:root` `0600`; run `rpm -Uvh`; verify:

```bash
systemctl is-active --quiet endpoint-agent.service
test -s /var/lib/endpoint-agent/device-credential
test ! -e /etc/endpoint-agent/provisioning-claim
test ! -e /var/lib/endpoint-agent/claim-removal-request.json
```

Confirm enrollment and Gateway handshake in server audit/logs without exposing secrets.

- [ ] **Step 3: Test upgrade preservation**

Install a subsequent RPM release with no bootstrap files. Confirm the service remains active and permanent credential/current selector are retained.

- [ ] **Step 4: Run regressions and commit**

Run: `python -m pytest pc_agent/tests/test_build_alt_rpm_source.py pc_agent/tests/test_linux_release_bundle.py pc_agent/tests/test_linux_packaging.py tests/deploy/test_alt_agent_rpm.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py -v --tb=short`

Run: `python -m compileall -q pc_agent/build_alt_rpm_source.py pc_agent/build_linux_release_bundle.py`

Run: `git diff --check`

Run: `git commit -m "docs: verify automatic ALT Gateway enrollment"`
