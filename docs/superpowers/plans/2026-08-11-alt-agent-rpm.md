# ALT Agent RPM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Build and validate an offline, unprovisioned RPM for the Endpoint Platform agent on ALT Linux 11.4 x86_64.

**Architecture:** A Python staging tool produces a source archive containing an existing manifest-attested Linux release bundle and provisioning assets. An RPM spec consumes that archive and installs it only under \`/usr/lib/endpoint-agent\`; provisioning remains an explicit operator action through the existing installer, which alone writes \`/opt/endpoint-agent\` and starts the service.

**Tech Stack:** Python 3.12, PyInstaller, RPM 4.13/rpmbuild, Bash, pytest, ALT Linux 11.4 x86_64.

## Global Constraints

- Build the final RPM natively on ALT Linux 11.4 x86_64.
- Never place CA files, endpoint URLs, enrollment claims, tokens, credentials, or rendered agent configuration in an RPM payload.
- RPM installation, upgrade, and removal must not start, stop, enable, disable, or restart a service.
- Preserve \`/opt/endpoint-agent\`, \`/etc/endpoint-agent\`, \`/var/lib/endpoint-agent\`, and \`/var/log/endpoint-agent\` across package removal and upgrade.
- The existing \`install-endpoint-agent.sh\` remains the sole privileged provisioning path.

---

### Task 1: Synchronize the package branch and stage RPM sources

**Files:**

- Modify: \`docs/superpowers/specs/2026-08-11-alt-agent-rpm-design.md\`
- Create: \`pc_agent/build_alt_rpm_source.py\`
- Test: \`pc_agent/tests/test_build_alt_rpm_source.py\`

**Interfaces:**

- Consumes: the release-bundle contract from \`pc_agent.build_linux_release_bundle.assemble_bundle(source, output, version, revision)\`.
- Produces: \`python -m pc_agent.build_alt_rpm_source --source PATH --version VERSION --revision REVISION --output PATH\`, printing a \`.tar.gz\` source archive path.

- [ ] **Step 1: Merge the current \`main\` branch into \`codex/alt-agent-package\`.**

Run: \`git merge main\`

Expected: latest agent installer is available; resolve only packaging-related conflicts.

- [ ] **Step 2: Write a failing behavior test for source staging.**

Create a literal fixture directory with \`launcher\`, \`pc_agent/pc_agent\`, and \`manifest.json\`. Invoke \`build_source_archive(...)\`, open its tarball, and assert it contains exactly the fixture release bundle plus \`packaging/endpoint-agent.spec\`, the provisioning assets, update helper, and ALT installation documentation. The test must fail if an asset is omitted or an unexpected payload member is added.

- [ ] **Step 3: Verify the test fails because the staging tool is absent.**

Run: \`python -m pytest pc_agent/tests/test_build_alt_rpm_source.py -v\`

Expected: import failure for \`pc_agent.build_alt_rpm_source\`.

- [ ] **Step 4: Implement the minimum staging tool.**

Implement \`build_source_archive(source: Path, version: str, revision: str, output: Path) -> Path\`. Reuse release-bundle validation rules, reject symlinks and unexpected entries, copy the release bundle and RPM assets into \`endpoint-agent-<version>/\`, record the revision in a JSON manifest, and create deterministic gzip tar output.

- [ ] **Step 5: Verify green and commit.**

Run: \`python -m pytest pc_agent/tests/test_build_alt_rpm_source.py -v\`

Then:

\`\`\`bash
git add pc_agent/build_alt_rpm_source.py pc_agent/tests/test_build_alt_rpm_source.py docs/superpowers/specs/2026-08-11-alt-agent-rpm-design.md
git commit -m "feat: stage ALT agent RPM source"
\`\`\`

---

### Task 2: Add the RPM spec and build wrapper

**Files:**

- Create: \`deploy/agent/alt/rpm/endpoint-agent.spec\`
- Create: \`deploy/agent/alt/rpm/build-rpm.sh\`
- Create: \`deploy/agent/alt/rpm/README.md\`
- Test: \`tests/deploy/test_alt_agent_rpm.py\`

**Interfaces:**

- Consumes: the source archive produced by \`pc_agent.build_alt_rpm_source\`.
- Produces: \`endpoint-agent-<version>-<release>.x86_64.rpm\`.

- [ ] **Step 1: Write the failing RPM contract test.**

Use a staged literal fixture to assert RPM source contents and package metadata. Assert that the spec owns release files only below \`/usr/lib/endpoint-agent\` and docs below \`/usr/share/doc/endpoint-agent\`; it must not package secrets or rendered configuration. Parse scriptlet bodies and assert they contain no \`systemctl\`, \`service\`, \`enable\`, \`disable\`, \`start\`, \`stop\`, or \`restart\` invocation.

- [ ] **Step 2: Verify red.**

Run: \`python -m pytest tests/deploy/test_alt_agent_rpm.py -v\`

Expected: failure because the spec and wrapper are absent.

- [ ] **Step 3: Implement package metadata and build command.**

The spec installs the release bundle, installer, unit templates, update helper, default configuration template, and documentation below \`%{_libdir}/endpoint-agent\` and \`%{_datadir}/doc/endpoint-agent\`. Its only scriptlet behavior is creation of the locked \`endpoint-agent\` account and persistent directories. It never controls services.

The shell wrapper must accept bounded \`--version\`, \`--release\`, \`--source\`, and \`--output\` values; it invokes the staging tool and \`rpmbuild -ba\` with isolated top/source/build directories.

- [ ] **Step 4: Verify green and commit.**

Run: \`python -m pytest tests/deploy/test_alt_agent_rpm.py pc_agent/tests/test_build_alt_rpm_source.py -v\`

Then:

\`\`\`bash
git add deploy/agent/alt/rpm tests/deploy/test_alt_agent_rpm.py
git commit -m "feat: package ALT agent as RPM"
\`\`\`

---

### Task 3: Build and test the RPM on ALT Linux

**Files:**

- Modify: \`deploy/agent/alt/rpm/README.md\`
- Test: \`tests/deploy/test_alt_agent_rpm.py\`

**Interfaces:**

- Consumes: a source checkout and RPM build dependencies on \`osn-admin@192.168.101.56\`.
- Produces: a native ALT Linux RPM with a recorded, non-provisioning lifecycle verification.

- [ ] **Step 1: Install the build dependency on the test host.**

Run: \`sudo apt-get update && sudo apt-get install -y rpm-build\`.

Expected: \`rpmbuild --version\` exits zero.

- [ ] **Step 2: Copy the isolated package branch to a temporary remote build directory and build.**

Create an isolated Python virtual environment, install project requirements and PyInstaller, then run:

\`\`\`bash
bash deploy/agent/alt/rpm/build-rpm.sh --version 0.1.0 --release 1 --output /tmp/endpoint-agent-rpm-out
\`\`\`

Expected: exactly one \`endpoint-agent-0.1.0-1.x86_64.rpm\` output file.

- [ ] **Step 3: Validate the artifact without altering a service.**

Run \`rpm -K\`, \`rpm -qlp\`, \`rpm -qp --scripts\`, and \`rpm -Uvh --test\` against the artifact. Assert no payload path is below \`/opt/endpoint-agent\`, \`/etc/endpoint-agent\`, \`/var/lib/endpoint-agent\`, or \`/var/log/endpoint-agent\`; assert scriptlets contain no service-control command.

- [ ] **Step 4: Run a controlled lifecycle test.**

Install with \`sudo rpm -Uvh\`, query with \`rpm -q endpoint-agent\`, assert the release bundle is at \`/usr/lib/endpoint-agent\`, and assert \`endpoint-agent.service\` is not active. Before removal, make sentinel files in the four preserved operator directories. Remove with \`sudo rpm -e endpoint-agent\`, then assert every sentinel remains and no service was started.

- [ ] **Step 5: Record exact build and verification commands, then commit.**

Update the README with the commands from the successful test, then commit:

\`\`\`bash
git add deploy/agent/alt/rpm/README.md tests/deploy/test_alt_agent_rpm.py
git commit -m "test: validate ALT agent RPM lifecycle"
\`\`\`

---

### Task 4: Verify the repository state

**Files:**

- Verify: \`pc_agent/tests/test_build_alt_rpm_source.py\`
- Verify: \`pc_agent/tests/test_linux_packaging.py\`
- Verify: \`tests/deploy/test_alt_agent_rpm.py\`

- [ ] **Step 1: Run focused tests.**

Run: \`python -m pytest pc_agent/tests/test_build_alt_rpm_source.py pc_agent/tests/test_linux_packaging.py tests/deploy/test_alt_agent_rpm.py -v --tb=short\`

Expected: all selected tests pass.

- [ ] **Step 2: Run the workspace guard.**

Run: \`python scripts/verify_workspace.py\`

Expected: exit code zero.

- [ ] **Step 3: Review the exact diff.**

Run: \`git diff main...HEAD --check && git status --short\`

Expected: no whitespace errors and no uncommitted files.

