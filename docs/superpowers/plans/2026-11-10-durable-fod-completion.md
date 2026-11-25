# Durable Windows OpenSSH servicing completion

The accepted native OpenSSH design and the user's automatic Windows rollout
remain the scope. Actual188 servicing exceeded540 seconds; the caller killed
PowerShell while CBS continued and successfully committed after about15 minutes.
Policy16 is paused on187. Original188 servicing evidence remains unknown to its
caller and must not be promoted from installed files alone.

## Global constraints

- No arbitrary capability, source, script, path, command or remote execution API.
- Preserve old independent Support until fully verified activation succeeds.
- Preserve keys, identity, grants, original native outcomes and historical media.
- No timeout kills a servicing witness. Observer108's40minute observation bound
  already keeps waiting and must remain immutable.
- No Add replay for an existing servicing receipt. Missing or invalid durable
  proof remains recovery_required, including old v1 receipts.
- Preserve existing service settings and exact firewall ownership/conflict checks.
- Tests never install real operator capabilities or mutate real services/rules.

### Task 1: durable fixed servicing worker and observation

Modify support_access_os.py, provision.py and their focused Windows tests.
Keep the existing fixed PowerShell servicing transaction, but persist a protected
operation-bound baseline before Add and an atomic protected completion proof
after Add and exact firewall/service boundary checks. Persist nonce/capabilities
and enough correlation to reject another operation's proof. The baseline must
record original service/rule before ANY mutation, including reservation creation;
completion binds its digest. Record owned reservation state separately. Only the fixed local
private root derived by WindowsFOD may hold these files.

Remove killing timeouts from the servicing process and its outer Support
installer. Read-only queries retain finite timeouts. Caller/process loss must
not kill the PowerShell witness: it can finish cleanup and durable proof alone.
Re-entry for a v2 servicing receipt may adopt only that operation's complete
protected proof, apply existing result classification/OS-signature verification,
and never relaunch Add. Missing/partial/mismatched proof stays held. Legacy v1
unknown remains held. Use no broad replay or new CLI command surface.

Use the existing activation/operation serialization or extend it where needed
to prevent concurrent launch/adoption/uninstall racing an orphan worker. Retain
unknown evidence at uninstall instead of deleting a worker's state.

Write meaningful RED then GREEN tests for caller loss followed by durable
completion, re-entry without duplicate Add, missing/malformed/mismatched proof,
foreign firewall conflict, reboot and failure classifications, and non-killing
outer wait. Exercise the fixed production PowerShell under actualPS5.1 with all
native commands replaced and AST isolation maintained. Run focused tests then
Windows suite once. Do not bump versions, build, publish or touch real state.

### Task 2: live evidence and explicit old-operation recovery

Controller collects exact188 DISM/CBS session evidence and original preflight
baseline without changing original receipt. A separately reviewed explicit
reconciliation is permitted only with unique operation/session correlation,
final servicing result, no pending state, verified signed OS closure and exact
service/firewall boundary proof. Keep separate reconciliation receipt and never
call it an untouched-source qualification. If evidence is insufficient keep hold.

### Task 3: immutable189 build, qualification and rollout

After reviewed code and tests, bump189/Support1.1.4, bind exact committed source,
build/sign/publish candidate, qualify real source177 and186 and187 as needed.
Require genuine user telemetry/native0/180seconds, actual strict SSH and reserve
access with Core/updater stopped/restored. Missing-FoD path needs actual accepted
proof, not merely tests. Resume all_active/max2 only after gates pass; promote
same candidate row through canonical publisher; verify served bytes. Offline177
reconnects use the dynamic policy while source qualification remains valid.
