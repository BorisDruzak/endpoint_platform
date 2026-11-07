# Committed Windows installation lifecycle

The user requested a built-in uninstall notification, clear server removal state
and subsequent installation/reconnection. Preserve current retained-identity
reinstall behavior; a full identity wipe remains fresh enrollment with normal
identity-conflict review. No hostname/IP/fingerprint credential reconstruction.
The user explicitly selected preserving the card/history for ordinary reinstall.

## Cause and native cleanup

The176 UserSensor observation was caused by the operator's extra purge deleting
`SOFTWARE\Endpoint Platform\Agent\BrowserPolicy` while leaving the owned Chrome/
Yandex policy values. The archived markers existed after ordinary MSI uninstall.
Restoring only those proven markers changed policy ERROR/POLICY_CONFLICT to
APPLIED and the same UserSensor process began producing accepted samples. No
runtime binary, account, browser GPO or IPC access rule was changed.

The new immutable Windows release will integrate existing
`BrowserPolicyApplicator.relinquish` into authenticated ordinary native0 finish.
The onefile installer host embeds the pinned extension ID; it cannot depend on
the already-removed onedir browser service. Foreign, changed, unowned or malformed
values are preserved, with a separate bounded cleanup result. Never fabricate a
missing ownership marker during uninstall. Never clear native recovery evidence
to obtain this cleanup. Upgrade, compound/staged reverse, runtime retirement,
read-only finalization, rollback, reboot and UNKNOWN are not ordinary removals.

## Native facts and protected delivery

Known-native0 `finish`, after uninstall absence verification, durably records its
ordinary removal event before retiring the fence. Networking happens only as a
bounded independent delivery; exceptions never manufacture an unknown native
result or strand the native owner. Support cleanup/native result/browser cleanup/
notification delivery are separate facts. Known Support cleanup68 still means
native removal committed, with a warning.

`installation_lifecycle.py` owns only pure native journal/receipt validation and
owned cleanup. `installation_notification.py` depends on those facts in one
direction and owns HTTPS, Setup coordination and the bounded notification Job.
The offline updater/native bridge never imports notification code or the
network-capable model stack. Pure canonical wire validation is checked against
the shared contracts; notification/server boundaries retain those models. The
notification Job remains bounded to20seconds plus5seconds for descendant reap,
after actual native helper exit, owner cleanup and installer mutex release.
The shared native argument/owner dispatcher lives in `installer_native_entry.py`;
the service launcher imports that offline leaf while the packaged installer host
retains the separate notification entry. `support_bootstrap.py` holds the unchanged
bootstrap ACL/link checks shared with Support, preventing a local identity read
from importing the Support network/runtime module. This behavior-preserving source
extraction still requires new177 packaged byte/source qualification; prior reports
that Support source was unchanged describe earlier checkpoints.

A protected per-device outbox records source-bound native facts, stable event ID,
generation UUID, monotonic sequence and predecessor event. Event IDs derive from
the genuine protected native transaction, not caller-chosen identity. Delivery is
strict HTTPS to the fixed Endpoint origin/CA and reads the still-retained protected
device credential; receipts never contain its raw bearer. No service, SSH key or
background agent remains solely to notify the server. A later signed Setup retries
pending events in causal order before reporting its new installation. Offline
full purge without retained authenticated authority cannot guarantee delivery;
record that limitation rather than guess an old identity or claim success.

An accepted real install/repair queues `installed`; first fresh enrollment binds
its native fact only after durable enrollment. Standard retained-identity repair
reuses the Device UUID and token; an already-valid rerun without native work is
not a new native event. No delayed removal may overwrite a later installed state.
Missing/corrupt existing generation state fails closed; do not silently reset an
established server stream. Ordinary native upgrades may report installed but
never removed.

## Wire and server

Contract module: `endpoint_contracts/installation_lifecycle.py`.

`POST /agent/v1/installation-events` uses existing DeviceBearer authority.
Event schema`endpoint_installation_event_v1`: device_id, event_id, generation_id,
sequence1..2147483647, previous_event_id (NULL only for1), action installed/removed,
aware occurred_at, native proof (version, canonical product_code, source_revision,
msi_sha256, actual exit_code0), cleanup (support complete/incomplete/not_applicable;
browser complete/external_preserved/conflict/failed/not_applicable). Strict bounded
fields, no raw exceptions/secrets. The provider checks the exact registered
Windows MSI/version/source, not only a caller version string.

Ack schema`endpoint_installation_event_ack_v1`: device_id, event_id, generation_id,
sequence, state installed/removed, received_at. Identical retry returns the stored
ack. Changed payload under the same event ID, wrong generation/predecessor or
sequence gaps return409 without projection mutation. Server receive order and the
causal stream, not client time, determine state. Event and per-device projection
are additive migration0048; legacy devices remain unknown until a real receipt.

Do not reuse or clear Device.retired_at, credential revocation or admin authority.
Lock/revalidate device credential authority before event/projection/audit commit.
Manual revoke/retirement continues to win. Presence/hello never turns removed
into installed. An unexpected authenticated connection while removed is visible
as conflicting evidence. Removed cards stay visible with history and native/
cleanup details, and are excluded from new automatic work/command dispatch.
Manual queue/history entries are preserved rather than falsely completed.

For a full wipe, canonical enrollment review may explicitly bind
`previous_device_id` on approval, after validating a matching prior enrollment
fingerprint and genuine prior removed state. This is a historical relation only,
never credential merge, automatic approval or retirement/revocation override.
Existing approval requests without that optional field remain compatible.

Ordinary reinstall must also rebind the independently removed Support component
without overriding manual refusal. Native lifecycle authority may permit one
device-bound rebind only after the corresponding removed->installed chain and
matching source/revision/generation. Manual Support revoke/reset/policy change
invalidates that authority. Preserve manual settings and disabled state. A new
bounded automatic access intent is permitted only for a previously automatic
grant with no later manual policy mutation, current enabled installation defaults
and the new genuine install event; retries never renew it. Existing runtime1.0.1
health/domain/key-role/expiry gates remain. No global rebind exception or guessed
Windows account is permitted.

The native rebind ticket is one-use, source-credential/device and Support revision/
generation bound, created only by the genuine ordinary removed->installed stream
and expires after a bounded setup window. A prior explicit admin Support revoke
cannot be converted into an installer reset. Component unregister alone does not
grant access; manual policy changes cancel the native authority. Native rebind
without automatic-access eligibility preserves the manual principal/keys and
keeps access disabled. Automatic eligibility requires the last access authority
to be an automatic installation grant with no subsequent manual policy mutation;
operator SSH attestation alone is not such a mutation.

If unregister failed offline, a nonrevoked manually disabled Support row may
receive a disabled-only native rebind only when its current-revision
`support_access.policy_changed` audit explicitly contains boolean `enabled=False`.
Missing/older/ambiguous audit fields do not authorize rebind. The unchanged source
credential, Device, revision/generation, causal removed->installed chain and
single-use expiry checks remain mandatory. Configured administrator and operator
keys remain intact, access stays disabled, and this manual-disable proof never
creates automatic-access intent or renewal. Revoke/reset or a later policy
revision still wins.

## Product and scope

Console distinguishes installed+online, installed+offline, removed and legacy
unknown; shows immutable event history and cleanup/delivery facts. Existing API
consumers and historical acceptance remain compatible. Publish the agent provider
contract at its canonical source. The existing canonical privileged Uninstall
wrapper receives the hook; a new general ARP elevation broker is out of scope.

Provider and new177 Windows media require separate code/test/source freezes,
signatures and actual120 acceptance; never rewrite176. Keep ALT156 unchanged.
Root owns production deployment, signing, registration and live operations.
Retain source qualification, publication, enrollment campaign and fleet promotion
as distinct gates; no automatic expansion of authority is implied by a build.

Trusted candidate registration is distinct from primary download publication.
The canonical publisher's `--candidate-only` requires the inspected MSI manifest,
ProductCode and expected valid Setup/MSI publisher, registers immutable release
proof, and sets server-owned `download_published=False`. Existing releases retain
the defaultTrue visibility. Active installer catalog queries exclude hidden
candidates, preserving176 as the primary download; exact native proof validation
and authenticated diagnostic download may use a trusted nonretired candidate.
The visibility flag is not part of the immutable sidecar or native event.

Candidate registration still transactionally includes the trusted version in the
same default AUTO campaign by default, preserving CIDRs, expiry, quota, use and
history. It creates no new campaign, fleet target or device assignment. The existing
`--without-auto-enrollment` remains an explicit diagnostic exclusion. Ordinary
canonical publication of the exact same candidate promotes visibility one-way in
the same transaction as campaign inclusion; failed campaign validation rolls back
promotion. Retries never downgrade visibility or mutate immutable release proof.
Creation and promotion produce bounded audit events.

Deployment rollback before any candidate registration retains the existing safe
boundary. After hidden candidates exist, restoring an older server without the
catalog filter can expose them: retain filtering or explicitly retire affected
candidates under operator authority before such a rollback. Do not blindly remove
publication state or rewrite historical signed release bytes.

## Acceptance

1. Repeat corrected clean176 to prove the original cause without binary changes:
   no orphan browser policies, native0, active genuine user samples and independent
   domain SSH through stopped Core/updater/observer, then fresh samples on restore.
2. Unit/authenticated API/PostgreSQL tests for native/cleanup gates, exact source,
   replay/drop-response/ordering, revocation races, legacy compatibility and scoped
   Support rebind/manual priority. Browser policy foreign values remain intact.
3. Independently review provider/native/contract diff and packaged dependency
   closure. Build a new signed immutable177 with reviewed source binding.
4. Deploy verified provider before177, then native upgrade/ordinary removal/
   retained-identity reinstall and fresh clean installation on120. Verify server
   removed state, same-card repair, actual native facts/receipts and no false
   removal from silence/upgrade. Repeat real user telemetry and stopped-runtime
   SSH, restoring original state. Confirm history/private authority/other PCs and
   campaign bounds. Test offline notification as pending, not false server success.
