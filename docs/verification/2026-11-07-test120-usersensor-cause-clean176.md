# UserSensor cause and corrected clean176 acceptance on test120

Result: corrected clean installation, genuine user telemetry and independent
administrator SSH passed on192.168.101.120. This uses immutable176 artifacts;
it does not qualify a new native source or implement lifecycle reporting by itself.
Times are UTC on2026-11-06 (local operator date2026-11-07, UTC+5).

## Cause and correction

The earlier clean176 failure was introduced by the operator's additional purge,
not a defective UserSensor executable. After ordinary native uninstall, the
archived registry export still contained the exact Chrome/Yandex ownership markers
under `HKLM\SOFTWARE\Endpoint Platform\Agent\BrowserPolicy`. The subsequent purge
removed those markers while leaving their browser-policy values. The strict
BrowserPolicyApplicator correctly reported `POLICY_CONFLICT`; policy never became
current, so the activity ingress rejected samples as `SENSOR_NOT_READY`.

Restoring only the two verified archived markers at21:00:23.621556, followed by
ordinary Core reconnection, produced policy `APPLIED`, activity `ACTIVE` and genuine
accepted samples. UserSensor PID6260 and Support PID9680 were unchanged. No policy
ownership check, user identity, credential, IPC ACL or executable was weakened.
UserSensor is MSI-bound; it is not individually Authenticode-signed.

## Corrected empty baseline and installation

The canonical privileged native Uninstall completed0 at21:12:11.478721. Only after
known native completion and absence of services/fence, the existing owned-policy
applicator generated an expected-value cleanup plan. Exact owned browser values
were removed before their ownership markers at21:15:41.274319; foreign state was
preserved. Protected residual archives remained outside all active product roots.

At21:16:37.893159 the baseline proved zero managed services/tasks, no product
registration, four active product/observer roots absent, no old identity/Support
state/native fence, and no orphaned owned browser entries. Domain secure channel
remained valid; existing OS SSH PID3564 was retained.

The unchanged signed176 Setup ran once as SYSTEM21:23:22.436954–21:28:06.518943,
exit0, durable `COMPLETED/SERVICE/SERVICE_RUNNING`. Full purge intentionally created
a new registration. The hardware duplicate request was manually approved after
exact prior fingerprint/campaign/source verification. New device:
`4231a496-1ab5-4318-b558-2d2e954b5f03` (`DESKTOP-9ST5HO2`). Old06143264 card and
history were retained, with audited legacy retirement/credential revocation.
This manual legacy cleanup is distinct from future ordinary reinstall semantics.

Actual accepted UserSensor samples advanced21:31:01.320535 to21:32:01.366077,
policy `APPLIED`, activity `ACTIVE`, listener `READY`, ordinary domain user session2
active. No manual companion launch or sensor restart was used.

## Independent access and restoration

Automatic installation authorization enabled Support1.0.1 revision2 without a
manual policy write, expiry2026-11-07T05:27:46.758883Z. Actual pinned SSH through
the Endpoint gateway authenticated existing `SOSNADM\admin-2`, SID ending7188,
with administrator membership. No account/password was created.

Core and updater were stopped and the official setup observer disabled. Two
actual SSH probes97.320345 seconds apart succeeded while they remained stopped.
Support stayed PID11380, automatic startup, exact signed176 SHA
`224cbee71d3bc5f1151cc21491f36e7ba09eb87dfef9a10b082569243a61667e`.
Independent Support status refreshed21:34:17.782511 with tunnel connected.

Core and observer were restored21:34:36.319001; updater's original Manual/Stopped
state was preserved. Genuine user samples resumed21:35:31.504763 and21:36:31.544359
under `APPLIED/ACTIVE`. The settled one-shot installation task was removed after
exact action/result ownership checks. No other PCs, gateway configuration or
immutable176 media were changed by this acceptance test.

Local detailed evidence: `.superpowers/sdd/2026-11-07-usersensor-cause/clean/`
contains baseline, native result, policy/sample series, both reserve SSH probes
and restoration receipts. Earlier failed-clean evidence remains historical and
must not be described as a passing user-telemetry test.
