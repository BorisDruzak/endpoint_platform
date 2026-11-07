# Recover current Windows power monitoring after System log rollover

The user requested repairing101.27's DEGRADED power source, restoring101.187's
UserSensor, and distributing a permanent agent fix through Endpoint with canaries
and bounded fleet waves. The user delegated Core-versus-full-Setup selection.

## Evidence and scope

101.27's System.evtx is20MiB, retains records from01Nov onward and contains no
Kernel-Boot27. Windows booted21Oct. Its power checkpoint contains coverage only,
reset_count1/loss_count0. All other10 connected Windows sources are READY.
101.187 had a running sensor in disconnected WTS2. Reconnecting the same test
session to console restored accepted samples, retaining PID10180. No sensor code
change is justified for that symptom. No reboot of101.27 is authorized.

## Approaches

1. Increase System maximum256MiB: authorized environmental mitigation; cannot
   reconstruct a lost boot boundary or guarantee indefinite retention.
2. Full native release: unnecessary Foundation/MSI changes for a Python reader
   defect; preserve immutable158 native artifacts and their acceptance evidence.
3. Core patch: selected implementation recommendation. Keep Foundation158, publish
   a new immutable Windows Core after regression tests, then Endpoint canaries
   101.27/101.187 before wider Windows waves. Do not replace163 bridge bytes.

## Reader behavior

Keep Kernel-Boot27 as primary evidence and preserve all existing classifications.
Only when its retained record is absent, query the public read-only WMI
Win32_OperatingSystem.LastBootUpTime property inside the existing killable native
worker. Normalize strict DMTF datetime to UTC; unavailable, wildcard, malformed or
future results leave the source degraded. Never estimate boot time from heartbeat
or generate an OS_STARTED event from WMI, uptime,6005 or service restart.

Use verified current-boot time only for current notifications and retained native
records at/after that boot. Earlier records remain unattributed/loss-accounted.
Preserve reset/loss counters and make recovery coverage explicit; READY describes
current collection, not continuous historical coverage. Namespace fallback record
identity using the bounded record anchor to avoid reused EventRecordID collisions.
Keep worker input/output bounds, timeout and cancellation guarantees unchanged.

No server event schema, external HTTP contract, credentials, GPO, employee binding,
browser exception or Linux artifact changes. No blanket READY rewrite on server.

## Acceptance

Regression must reproduce missing Boot27 after rollover, recover current READY
without synthetic startup, retain loss/reset diagnostics, reject invalid/future
WMI and old-boot attribution, and handle reused native record numbers safely.
Run focused power/runtime tests and the applicable suite. Build from an exact
committed revision, verify immutable ZIP/runtime provenance, deliver through
canonical Endpoint rollout, and independently confirm selection, WSS, health,
fresh UserSensor/activity and stable observation on both canaries before waves.

Public API reference:
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
