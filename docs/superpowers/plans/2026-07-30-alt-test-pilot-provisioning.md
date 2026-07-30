# ALT Test-Pilot Provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrol one verified ALT agent on `test-agent-lin` with a one-time hardware-bound claim, without changing `web_ovpn` or exposing a permanent credential.

**Architecture:** The Linux agent reads only systemd credentials at startup and invokes the existing claim exchange before normal work. An administrator-authenticated, test-host-only controller creates a short-lived scoped provisioning credential and campaign, issues the claim through the existing service route, and streams it directly to the root-only test-host handoff file. The bundle installer remains the sole root finalizer.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy/asyncpg, aiohttp, PyYAML, systemd credentials, OpenSSH, PyInstaller, Bash, pytest.

## Global Constraints

- The only live target is SSH alias `test-agent-lin` (`192.168.101.162`); do not alter `web_ovpn`, network configuration, or a production endpoint host.
- The gateway is exactly `https://endpoint.sosnadmin.local`; strict CA and hostname verification are mandatory.
- Claims, service credentials, campaign tokens, and device tokens never appear in Git, environment variables, command-line arguments, fixture literals, logs, evidence, or controller output.
- A claim is one-time, expires within 15 minutes, and is bound to one bounded install-session ID plus one normalized hardware fingerprint.
- The provisioning credential has exactly `provisioning.install-claims.issue`, is not an admin credential, and is revoked after the claim is delivered or an operation fails.
- The only persistent source claim is `/etc/endpoint-agent/provisioning-claim`, owned by `root:root` with mode `0600`; the permanent credential remains `/var/lib/endpoint-agent/device-credential`, owned by `endpoint-agent:endpoint-agent` with mode `0600`.
- `bootstrap_enrollment()` is invoked only through the systemd credentials directory, never from an environment-provided or caller-selected claim path.
- Commit each independently tested task. Build artifacts, token-bearing files, and unredacted logs are transient and never committed.

---

## File Structure

- `pc_agent/linux_enrollment_runtime.py`: parses the fixed installer configuration, loads the three systemd credentials, and returns safe bootstrap/fingerprint outcomes.
- `pc_agent/ws_agent.py`: invokes the Linux enrollment gate before normal `WSAgent` initialization and exposes a non-secret fingerprint-only CLI mode.
- `pc_agent/tests/test_linux_enrollment_runtime.py`: runtime configuration, startup ordering, restart, and no-secret-log tests.
- `deploy/agent/alt/default-config.yaml`, `deploy/agent/alt/install-endpoint-agent.sh`: carry the validated installation ID into the fixed runtime configuration.
- `endpoint_server/provisioning/admin_routes.py`: authenticated administrator lifecycle for a short-lived pilot provisioning credential; never returns a device credential.
- `endpoint_server/provisioning/pilot_service.py`: creates/revokes the fixed test-pilot service identity and appends redacted audit events.
- `tests/server/test_pilot_provisioning_admin_api.py`: scope, expiry, one-time secret response, revocation, and audit-redaction coverage.
- `tools/provision_alt_test_agent.py`: workstation operator controller for the one allowed test host.
- `tests/deploy/test_alt_test_pilot_controller.py`: pure controller validation, HTTPS client boundaries, SSH stdin claim delivery, and no-secret-output coverage.
- `docs/runbooks/ALT_AGENT_TEST_PILOT.md`: exact redacted operator procedure and rollback/finalization checks.
- `docs/runbooks/evidence/2026-07-30-alt-test-agent-pilot.md`: token-redacted live acceptance evidence, created only after success.

---

### Task 1: Fixed Linux enrollment runtime gate

**Files:**
- Create: `pc_agent/linux_enrollment_runtime.py`
- Create: `pc_agent/tests/test_linux_enrollment_runtime.py`
- Modify: `pc_agent/ws_agent.py`
- Modify: `deploy/agent/alt/default-config.yaml`
- Modify: `deploy/agent/alt/install-endpoint-agent.sh`
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`

**Interfaces:**
- Produces `load_linux_bootstrap_config(config_path: Path, credentials_dir: Path, *, uid: int, gid: int) -> BootstrapConfig`.
- Produces `async run_linux_enrollment_gate(...) -> EnrollmentOutcome` and `derive_linux_hardware_fingerprint() -> str`.
- `ws_agent.py --print-hardware-fingerprint` writes only one canonical `sha256:` value and exits before configuration, networking, or normal agent initialization.
- Installer accepts `--installation-id ID`, validates it with the same bounded printable-ASCII contract, and renders `provisioning.installation_id`.

- [ ] **Step 1: Write failing runtime tests**

```python
async def test_linux_gate_bootstraps_before_normal_agent_initialization(monkeypatch, tmp_path):
    calls: list[str] = []
    monkeypatch.setattr(runtime, "bootstrap_enrollment", fake_bootstrap(calls))
    outcome = await runtime.run_linux_enrollment_gate(
        config_path=tmp_path / "config.yaml",
        credentials_dir=tmp_path / "credentials",
        probe=lambda: {"machine_id": "fixture"},
        uid=1001,
        gid=1001,
    )
    assert outcome.status == "enrolled"
    assert calls == ["bootstrap"]

def test_fingerprint_cli_writes_only_canonical_value(capsys):
    assert main(["--print-hardware-fingerprint"]) == 0
    assert capsys.readouterr().out.startswith("sha256:")
```

- [ ] **Step 2: Run the focused tests to prove the missing runtime seam**

Run: `python -m pytest pc_agent/tests/test_linux_enrollment_runtime.py -q`

Expected: FAIL because the runtime module and fingerprint CLI do not exist.

- [ ] **Step 3: Implement the fixed-config runtime seam**

```python
async def run_linux_enrollment_gate(
    *, config_path: Path, credentials_dir: Path, probe: Callable[[], object], uid: int, gid: int
) -> EnrollmentOutcome:
    config = load_linux_bootstrap_config(config_path, credentials_dir, uid=uid, gid=gid)
    return await bootstrap_enrollment(credentials_dir, config, probe)
```

Use `yaml.safe_load`; require an object with exactly the fixed endpoint, CA,
installation ID, and credential-name fields. Refuse a non-HTTPS endpoint, a
noncanonical credentials directory, a claim name other than
`endpoint-enrollment-claim`, and any runtime path other than the fixed paths
in `BootstrapConfig`. In `ws_agent.main()`, invoke the gate only when all
three `ENDPOINT_AGENT_*` systemd paths are set; on `enrolled`,
`already_enrolled`, or `handoff_pending`, continue to `main_async`; on every
other outcome log the status name only and exit nonzero before `WSAgent()`.

- [ ] **Step 4: Render and validate the installation ID**

Add this fixed configuration field:

```yaml
provisioning:
  installation_id: "__INSTALLATION_ID__"
  systemd_claim_credential_name: "endpoint-enrollment-claim"
```

Add `--installation-id` to installer argument parsing and replace both
`__ENDPOINT_URL__` and `__INSTALLATION_ID__` in `render_config`. Extend dry-run
tests to reject an omitted, whitespace-padded, non-ASCII, or over-128-byte ID.

- [ ] **Step 5: Run runtime, bootstrap, and package tests**

Run: `python -m pytest pc_agent/tests/test_linux_enrollment_runtime.py pc_agent/tests/test_enrollment_bootstrap.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_bundle_install.py -q`

Expected: PASS with no raw claim, service credential, or device token in output.

- [ ] **Step 6: Commit**

```bash
git add pc_agent/linux_enrollment_runtime.py pc_agent/tests/test_linux_enrollment_runtime.py pc_agent/ws_agent.py deploy/agent/alt/default-config.yaml deploy/agent/alt/install-endpoint-agent.sh docs/runbooks/ALT_AGENT_INSTALL.md tests/deploy/
git commit -m "feat: run Linux claim enrollment before agent startup"
```

### Task 2: Administrator-controlled pilot service credential

**Files:**
- Create: `endpoint_server/provisioning/pilot_service.py`
- Create: `endpoint_server/provisioning/admin_routes.py`
- Modify: `endpoint_server/main.py`
- Create: `tests/server/test_pilot_provisioning_admin_api.py`

**Interfaces:**
- `POST /api/admin/provisioning/test-pilot/credentials` accepts only `{"install_session_id": "..."}` and returns one show-once `{credential_id, token, expires_at}`.
- `POST /api/admin/provisioning/test-pilot/credentials/{credential_id}/revoke` returns `204`.
- The service identity is `alt-test-pilot`, credential identifier is the validated installation ID, scope is exactly `provisioning.install-claims.issue`, and expiry is at most 15 minutes.

- [ ] **Step 1: Write failing administrator API tests**

```python
async def test_admin_pilot_credential_is_show_once_scoped_and_redacted(client, admin):
    response = await client.post(
        "/api/admin/provisioning/test-pilot/credentials",
        json={"install_session_id": "alt-test-agent-001"},
        cookies=admin.cookies,
    )
    assert response.status_code == 201
    assert response.json()["token"].startswith("svc_")
    assert stored_credential.scopes == ["provisioning.install-claims.issue"]
    assert response.json()["token"] not in repr(audit_event)

async def test_non_admin_cannot_create_or_revoke_pilot_credential(client):
    assert (await client.post("/api/admin/provisioning/test-pilot/credentials", json={})).status_code == 401
```

- [ ] **Step 2: Run the new API tests to verify they fail**

Run: `python -m pytest tests/server/test_pilot_provisioning_admin_api.py -q`

Expected: FAIL because the pilot credential route is absent.

- [ ] **Step 3: Implement the constrained service lifecycle**

```python
async def issue_test_pilot_credential(session: AsyncSession, *, settings: Settings, installation_id: str, actor_id: str, request_id: str) -> IssuedServiceCredential:
    client = await get_or_create_service_client(session, "alt-test-pilot", "ALT test pilot")
    return await create_service_credential(
        session, client=client, credential_identifier=installation_id,
        scopes=[PROVISIONING_INSTALL_CLAIMS_ISSUE_SCOPE], expires_at=utc_now() + timedelta(minutes=15),
        service_token_pepper=settings.service_token_pepper, actor_identifier=actor_id, request_id=request_id,
    )
```

Validate `installation_id` with `normalize_install_session_id`. Record only
credential UUID, client UUID, expiry, scope, and installation ID in audit
details. Never persist a raw token beyond the existing digest and never return
a permanent device credential. Revocation must be idempotent for an active
administrator and audit `provisioning_test_pilot_credential.revoked`.

- [ ] **Step 4: Register the router and prove the existing service claim route accepts only its scope**

```python
app.include_router(provisioning_admin_router)
```

Extend `tests/server/test_provisioning_claim_api.py` with an issued test-pilot
credential that receives a claim, while a credential with `devices.read` is
rejected. Verify a revoked pilot credential receives `401`.

- [ ] **Step 5: Run the server security tests**

Run: `python -m pytest tests/server/test_pilot_provisioning_admin_api.py tests/server/test_provisioning_claim_api.py tests/server/test_service_auth.py tests/server/test_enrollment_admin_api.py -q`

Expected: PASS; the test output and audit representations contain no raw service token, claim, campaign bearer, or device token.

- [ ] **Step 6: Commit**

```bash
git add endpoint_server/provisioning/pilot_service.py endpoint_server/provisioning/admin_routes.py endpoint_server/main.py tests/server/test_pilot_provisioning_admin_api.py tests/server/test_provisioning_claim_api.py
git commit -m "feat: issue constrained ALT pilot credentials"
```

### Task 3: Test-host-only provisioning controller

**Files:**
- Create: `tools/provision_alt_test_agent.py`
- Create: `tests/deploy/test_alt_test_pilot_controller.py`
- Create: `docs/runbooks/ALT_AGENT_TEST_PILOT.md`

**Interfaces:**
- `python tools/provision_alt_test_agent.py --bundle DIRECTORY --ca-file FILE --installation-id ID --admin-username USER`.
- No flag accepts a claim, service token, campaign bearer, device credential, password, target host, or endpoint.
- `PilotResult(installation_id: str, fingerprint: str, campaign_id: UUID, claim_expires_at: datetime)` has `repr=False` for secret-bearing intermediates and is emitted only as redacted JSON.

- [ ] **Step 1: Write failing controller tests with injected subprocess and HTTPS clients**

```python
def test_controller_refuses_any_host_except_test_agent_lin(tmp_path):
    with pytest.raises(ValueError, match="test-agent-lin"):
        validate_pilot_target("192.168.100.19")

def test_claim_delivery_writes_bytes_only_to_root_handoff_stdin(fake_ssh):
    deliver_claim(fake_ssh, claim="secret-marker")
    assert fake_ssh.argv[-1] == "sudo install -o root -g root -m 0600 /dev/stdin /etc/endpoint-agent/provisioning-claim"
    assert "secret-marker" not in fake_ssh.rendered_log
```

- [ ] **Step 2: Run the focused controller tests to prove they fail**

Run: `python -m pytest tests/deploy/test_alt_test_pilot_controller.py -q`

Expected: FAIL because the controller does not exist.

- [ ] **Step 3: Implement local validation and safe remote staging**

```python
TEST_HOST = "test-agent-lin"
ENDPOINT_ORIGIN = "https://endpoint.sosnadmin.local"

def deliver_claim(ssh: CommandRunner, *, claim: str) -> None:
    ssh.run_stdin(
        [TEST_HOST, "sudo", "install", "-o", "root", "-g", "root", "-m", "0600", "/dev/stdin", "/etc/endpoint-agent/provisioning-claim"],
        claim.encode("ascii"),
    )
```

Validate the local bundle with its existing `manifest.json`, parse the local CA
as a trust anchor, copy the bundle and CA to the fixed remote `/root/input/`
paths with root-owned modes, and run the staged bundle's
`pc_agent/pc_agent --print-hardware-fingerprint` command over SSH. Reject any
noncanonical fingerprint or output containing more than one line.

- [ ] **Step 4: Implement the strict HTTPS credential/claim sequence**

Use `getpass.getpass` for the administrator password; never place it in a
subprocess argument, environment variable, or file. Build a strict SSL context
from `--ca-file`, log in at `/api/admin/session`, create a one-use Linux
campaign restricted to `192.168.101.0/24`, create the pilot service credential,
then call `/api/v1/provisioning/install-claims` with the service bearer.
Discard the unused campaign bearer response immediately. Stream the claim to
the handoff file, revoke the service credential, revoke the admin session, and
print only installation ID, fingerprint, campaign UUID, and expiry. In every
failure path, revoke any created service credential and campaign before logging
the redacted failure category.

- [ ] **Step 5: Write the operator runbook**

Document the exact command shape, expected non-secret output, required
administrator TTY prompt, dry-run/install/finalizer sequence, and the rule that
the controller must be run only from the primary Endpoint Platform worktree.
Include no real identifier, token, claim, certificate private material, or
password.

- [ ] **Step 6: Run controller and contract checks**

Run: `python -m pytest tests/deploy/test_alt_test_pilot_controller.py tests/deploy/test_alt_agent_bundle_install.py tests/contracts/test_contract_models.py tests/sdk/test_provisioning_client.py -q`

Expected: PASS with no credential marker in captured output.

- [ ] **Step 7: Commit**

```bash
git add tools/provision_alt_test_agent.py tests/deploy/test_alt_test_pilot_controller.py docs/runbooks/ALT_AGENT_TEST_PILOT.md
git commit -m "feat: add constrained ALT test pilot controller"
```

### Task 4: Build, deploy, and accept the dedicated test pilot

**Files:**
- Modify: `PLANS.md`
- Create: `docs/runbooks/evidence/2026-07-30-alt-test-agent-pilot.md`

**Interfaces:**
- Release bundle version follows `alt-test-pilot-YYYYMMDD-HHMM` and the manifest records the committed source revision.
- Evidence contains only release version/digest, migration revision, installation ID, device UUID, modes/owners, service state, baseline/Gateway status, and redacted log line counts.

- [ ] **Step 1: Re-run the complete local gate before the live action**

Run: `python -m pytest tests/contracts tests/server tests/deploy/test_alt_agent_bundle_install.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py tests/deploy/test_alt_test_pilot_controller.py pc_agent/tests/test_linux_release_bundle.py pc_agent/tests/test_enrollment_bootstrap.py pc_agent/tests/test_linux_enrollment_runtime.py -q`

Expected: PASS, apart from documented skips; stop if a new failure occurs.

- [ ] **Step 2: Build and attest a transient Linux bundle**

Run on the isolated Linux build/test environment:

```bash
./pc_agent/venv/bin/python -m pc_agent.build_linux_release_bundle \
  --build --version alt-test-pilot-20260730-01 --output /tmp/endpoint-agent-releases
sha256sum /tmp/endpoint-agent-releases/endpoint-agent-alt-test-pilot-20260730-01/manifest.json
```

Record only the version, source revision, and manifest SHA-256. Inspect the
manifest path list and verify it contains exactly `launcher`, `pc_agent/`, and
`manifest.json`; do not archive credentials with it.

- [ ] **Step 3: Recheck the test host before mutation**

Run: `ssh test-agent-lin 'hostname; . /etc/os-release; printf "%s %s\\n" "$ID" "$VERSION_ID"; df -h /; systemctl is-active endpoint-agent.service || true'`

Expected: `test-agent-lin`, ALT Linux, adequate free disk, and no active prior
pilot service. Stop if the identity or target differs.

- [ ] **Step 4: Stage the claim and execute installer dry-run then install**

Run the controller from the primary worktree using the transient bundle, CA,
bounded installation ID, and administrator username. On the test host run:

```bash
sudo bash deploy/agent/alt/install-endpoint-agent.sh \
  --endpoint https://endpoint.sosnadmin.local \
  --installation-id alt-test-agent-001 \
  --ca-file /root/input/sosnadmin-local-ca.crt \
  --handoff-file /etc/endpoint-agent/provisioning-claim \
  --agent-bundle /root/input/endpoint-agent-alt-test-pilot-20260730-01 --dry-run
```

Repeat without `--dry-run` only after the dry run succeeds. Capture only exit
codes, owner/mode metadata, and manifest digest.

- [ ] **Step 5: Verify enrollment and finalize the claim**

Verify `endpoint-agent.service` is active, the permanent credential is a
regular `0600 endpoint-agent:endpoint-agent` file, and the request file matches
the fixed schema without displaying its contents. Execute
`sudo bash deploy/agent/alt/install-endpoint-agent.sh --finalize-handoff` and
verify only the root claim source plus request are removed. Restart the service
and prove the same device UUID remains registered.

- [ ] **Step 6: Verify bounded baseline/Gateway and rollback readiness**

Inspect token-redacted journal status and the Endpoint Platform device record.
Trigger only the reviewed baseline/health/network collection profile, verify
the gateway response, and run the installer once more with the same manifest to
prove idempotence. Do not schedule a production rollout. Record the immutable
prior selection and the installer rollback result only if a controlled second
bundle test is explicitly approved.

- [ ] **Step 7: Record evidence and update handoff state**

Write the redacted evidence document and move `PLANS.md` from installation
pending to pilot accepted only if every prior step passed. Include the deployed
server release `42de4d53f0d1`, Alembic revision
`0010_session_last_seen_index`, and the bundle manifest digest. Do not include
claims, credentials, passwords, raw logs, or certificate contents.

- [ ] **Step 8: Commit**

```bash
git add PLANS.md docs/runbooks/evidence/2026-07-30-alt-test-agent-pilot.md
git commit -m "docs: record ALT test agent pilot acceptance"
```

## Self-Review

- Runtime invocation, installation ID rendering, service credential lifecycle,
  operator claim delivery, and live finalization are each covered by one task.
- Every secret-bearing value has one show-once/process-memory boundary and no
  plan command places it in an argument or environment variable.
- Task 4 depends only on artifacts and interfaces established by Tasks 1-3.
- `web_ovpn` is absent from all implementation and deployment steps.
