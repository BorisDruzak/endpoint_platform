# Foundation execution pins implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline, with TDD and
> one final independent review before signing a new full Setup.

**Goal:** Allow unchanged, authenticated Foundation images to start without
mistaking Windows loader ChangeTime for a file substitution.

**Spec and evidence:** Setup170 on101.27 applied/native0;187 failed/native21
at restore-staged-companions with change_time for EndpointAgentTray.exe, then
recovered automatically with observer107 and fresh183.629second proof. Public
Tray bytes match the exact signed170 release. The existing execution guard in
staged_candidate_payload.py, commit07afaef7bdf9fcd6a37d70e94d3d6d9cf6f977c4,
already handles Windows image-load timestamp changes by comparing actual
retained-handle security and attributes. This is the project precedent.

**Architecture:** Share that metadata identity in durable_state. Opt in only
the accepted-native companion execution scope; ordinary Foundation reads and
all native/private/selection authority remain strict. Retain all deny-write and
deny-delete handles through launch and post-check. Compare exact owner/group/
DACL and file attributes, namespace, path/handle identity and expected bytes.
On timestamp-only drift, perform a fresh direct hash under the same pin and
require metadata/identity to remain stable across that read. Never rebaseline
a changed ACL, attribute, selector, grant or private capture. Reject accidental
execution inside a cached immutable-Foundation read scope before yielding.

**Approaches:** Engineering choice is reuse of the existing execution proof.
Ignoring ChangeTime without replacement would lose metadata evidence; keeping
only a later retry preserves avoidable native21 failures. Neither meets the
requested reliable full update. No new product or deployment flow is proposed.

**Tech stack:** Existing CPython3.12.14, pywin32 311, PyInstaller6.22.3; no new
dependency, migration, GPO, service access or remote support mechanism.

## Global constraints

- Preserve original169/170 jobs, attempts and native21 histories.
- No new SSH writes, MSI replay or service restart on187; scoped107 exception
  is complete. Native updates remain Console assignments.
- Keep fleet3 disabled/max2 and Windows download165 until clean canaries.
- Future immutable full171 must be rebuilt; never overwrite signed170/107.
- Distinguish an exact automatic recovered failure from APPLIED/native0.

## Tasks

- [x] Add RED tests for the accepted-native call opting into execution proof,
  real harmless SetFileTime drift, shared dependency drift, unchanged deny-write/
  delete barriers, DACL/attribute/identity/byte changes and cached-read rejection.
  Extract the existing metadata helper without changing Core self-check behavior.
  Implement the narrow Foundation scope and run the related Windows/native tests.
- [ ] Review the complete change, resolve findings, commit, rebuild/sign full171
  and verify actual archives. Publish candidate only, run Console canaries with
  no workstation preparation, require native0/private/fresh180second proof and
  active UserSensor. Only then qualify exact sources and proceed to max2 waves.

## Execution ledger

Root cause class reproduced locally: FILE_WRITE_ATTRIBUTES/SetFileTime can change
native ChangeTime under an existing deny-data-write/delete pin while file ID,
size, write/birth times, attributes and bytes remain unchanged. Ordinary reads,
minimal onefile execution and guarded signed-Tray execution (including an
isolated LUA interactive-token task) did not independently reproduce the VM's
specific writer. Do not claim last-access policy, GPO, PyInstaller or antivirus
as its confirmed origin. Local fixture tasks were uniquely created and removed;
no Endpoint task, process, agent state or policy was changed by those fixtures.


Implementation review found and regression-tested two important timing cases:
metadata must be captured before initial hashing and revalidated before yielding;
continued timestamp-only drift during the final fresh hash must not restore the
old false positive. Both tests failed before correction and now pass. The shared
execution identity still rejects changed owner/group/DACL/attributes and every
byte/identity/read failure. Independent reviewer found no remaining blocker.
Eight direct Windows suites passed308tests; broader packaging/native/bootstrap/
recovery checks passed338tests with1skip. Source fix d5cfb0daa61aff14f4cd4e9685c716a78300e1c3.
GitNexus baseline was consulted earlier; its tools are currently unavailable.
This narrow native-local change was verified against current source/tests and
introduces no external HTTP contract. Context7 was consulted for the pinned
pywin32 311/PyInstaller6.22.3 environment and existing APIs. No171 build,
publication, workstation preparation or fleet action yet.
