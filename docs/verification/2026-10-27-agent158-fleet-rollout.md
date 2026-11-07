# Agent158 release and fleet verification

The qualified existing-device release is **3.2.158** on Windows and ALT Linux, with
immutable runtime source `9423d9c27ea6b2d6c544c1bcdc1edb7cc9d15421`.
The [canonical release record](../releases/current-agent-release.json) contains
artifact paths, digests, source restrictions and the separate enrollment default.
Historical 156 qualification and delivery evidence remain in
[its release record](../releases/agent-3.2.156.json).

## Delivered and independently verified

Six production Windows devices completed signed full Setup 158. Each has actual
native Foundation and MSI-origin Core 158, the exact runtime/MSI binding, preserved
private-four content/file IDs/security metadata, a current authenticated device
probe, and independent fresh WSS/APPLIED/sensor-health/power acceptance after at
least 180 seconds. The first production canary was independently accepted before
the five-node batch; no more than two native installations ran concurrently.
The batch performed one native attempt per device and no automatic retries.

The existing ALT singleton has native RPMs and selected Core 158. Root independently
checked all 98 runtime file hashes, the selected source, current private-file
permissions and unchanged agent/CUPS/SSSD process identities. The singleton's
historical pre-158 private-four raw baseline is unavailable: do not claim that
current-state checks establish continuity across that earlier transition or
qualify unrestricted fleet OTA.

These checks establish native/runtime installation acceptance. Real-user SSO,
WorkTime notifications and broad server-feature acceptance remain separate.

## Why three Windows machines had stayed149

The computer GPO registered its task after boot. The boot trigger had already
passed, and the periodic fallback was seven hours. Scheduler evidence showed
registration/update events without an action run; Setup had not started.

The first controlled launch then reproduced a second defect: a parameter named
PowerShell's reserved `$input` became empty inside authorization copying. The
bootstrap stopped before native installation. Eight tests extracted the actual
PowerShell functions, reproduced the original failure and passed after renaming
the path variable. The fixed, separately versioned and signed bootstrap preserves
the original failure and script. A registration trigger with a two-minute delay
now starts the same guarded delivery after GPP registration or update.

The corrected policy was read back on both controllers with matched AD/GPT
machine version 2. Its seven-computer scope, link order and all prior eight policies
and four shares remain unchanged. On two clients, actual scheduler registration
triggers ran the fixed bootstrap and completed successfully without manual task
registration or an operator starting Setup. All three were independently accepted
at 156 before their subsequent 158 upgrade.

## Remaining source and reachability limits

- The original problem PC has a protected configured origin and no previous
  selector. Separate exact-profile qualification is in preparation; it remains 156
  until that gate and its actual installation succeed. Preserve its configured
  origin and historical recovery evidence.
- A legacy device has native Foundation 63 plus ZIP Core 79. It slept across policy
  publication and resumed later; its computer-policy cache had not refreshed.
  Fresh authenticated WSS is now confirmed. The historical enabled bridge's
  retained proof does not establish coverage of this exact hybrid source. Do not
  force the149/156/158 qualified cohort driver onto it or claim a new policy was
  already applied.
- Another device's actual signed 158 preflight returns `PROVENANCE_CONFLICT` for
  its legacy 81 source. Exact retained 79 compatibility does not authorize 81 or
  arbitrary old media.
- Four historical Linux addresses did not answer bounded ICMP/SSH probes.
  Nonresponse does not establish power-off. At the fifth historical address,
  current DHCP/ARP, VM configuration/interfaces and protected enrollment identity
  identify a different agent; do not install by historical IP alone.

The five old Linux 156 assignments remain distinct from 158 acceptance. Historical
VM snapshot identities are not additional physical rollout targets. No stale
records, protected previous versions or inactive recovery history were erased.

## Build and verification evidence

All 225 immutable Windows source-binding entries match the integrated runtime
after LF normalization. The selective integration includes the agent and its
optional companion contract; it does not merge the separate SSO/WorkTime server
branch. Missing companion routes return empty replies and retry without ending
the main WSS connection. Linux kit builder metadata and README were checked
against the actual signed 158 archive, including exact RPM/runtime digests.

- Windows complete agent suite: 2811 passed, 86 skipped.
- ALT complete agent suite: 2381 passed, 516 skipped.
- Selective integration review: 141 focused runtime/binding tests passed;
  ALT packaging review 57 passed / 4 skipped; root's packaging/runtime subset 69 passed.
- Full PostgreSQL integration CI for
  `2ca38733e99b8412f694285446a4371929902e66`:
  [run40464299306](https://github.com/BorisDruzak/endpoint_platform/actions/runs/40464299306),
  5134 passed / 913 skipped / 0 failures. Downloaded source and JUnit artifacts match.
- Earlier full candidate CI for
  `668e7bc30898ef24bdbe0a22ccb92a6ed8be366d`:
  [run40459347035](https://github.com/BorisDruzak/endpoint_platform/actions/runs/40459347035),
  5256 passed / 918 skipped. That broader source includes a separately committed
  emergency-session clock fix; this rollout neither merges nor deploys its server.
- Actual public ALT download bytes and both OpenPGP archive/manifest signatures
  were checked against the pinned publisher. Windows Setup/MSI and administrative
  scripts have valid timestamped signatures. Windows public new-enrollment
  default remains 156 because campaign 158 permissions were not expanded.

Operator-only evidence, containing no plaintext credentials in its receipts:
`C:/Temp/endpoint158-fleet-rollout-20261027`,
`C:/Temp/endpoint156-readonly-diagnosis-20261027`,
`C:/Temp/endpoint158-offline-cohort-diagnosis-20261027`,
`C:/endpoint-platform-wix-build/fleet158-windows156-20261027-vm123`, and
`C:/endpoint-platform-wix-build/fleet158-origin-present156-20261027-vm123`.
The origin-present VM case preserves four private files through genuine 67 compensation and
normal 158 retry; its previous 149/native versus previous-absent/unit distinction
is explicit and does not substitute for the original PC's exact native gate.
