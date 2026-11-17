# Linux 179 native canary: installed, support startup failed

Status: **not qualified or promoted**. The exact 179 RPM transaction succeeded;
the independent SSH channel has not passed acceptance. Linux primary remains 156.

The tested source is `23e2b037f12f5b72474cc18401bd981403362381`.
Actual ALT RPM 4.13 verified both native signatures; staging's independent native
verifier checked the complete payload/source/Setup bindings. The immutable kit
and external manifest were signed by the existing publisher
`BC24B8EE43DBB05A748E11A4343B5DA748370631` and independently verified.
The staging source row is `dea922ff-4084-471e-b914-d3b9f0be92e0`, registered at
2026-11-08T11:09:21.925314Z. See the matching candidate record for exact hashes.

The source verification gate was completed by the actual built-RPM test: one
additional pass. The reconciled 179 POSIX result is therefore **207 passed across
split runs**, not one wholly green command. The earlier three harness environment
failures and their narrow successful reruns remain in the source-gate receipt.

## Native outcome and identity

VM 107, product UUID `db12fb5c-3732-487f-911f-80e31f79b29b`, retained staging and
device `29a8bed4-2894-40f7-89fb-07b3c7f633fe` throughout this checkpoint. Its
existing KDE session, domain configuration and ordinary SSH were preserved.

The first outer Setup invocation returned 21 **before native invocation**. There
was no operation journal or retained RPM cache; installed 156 and its Core PID
1061 were unchanged. Its receipt remains retained. This is not a native RPM 21.

A second invocation of the identical retained executor ran from 11:17:44.834192Z
to 11:18:27.568054Z. Operation
`4d9f47ec-9a71-478e-b44b-dd14216b1af7` has **native exit 0**, exact Core/Sensor
`3.2.179-alt6`, and `settled=true`. Its outer process returned 21 while bootstrap
was pending. The installed automatic retry reconciler subsequently completed
bootstrap and Support registration without replaying RPM. At 11:24:37Z the
journal's sequence and acknowledged sequence were both 1; bootstrap and
registration were complete. Staging accepted the corresponding immutable
`installed` event in generation `03d2c75c-186c-4586-9532-08f1160c6b7a`.

All four original private files retained their exact SHA256, owner, group, mode
and size: device credential, enrollment identity, configuration and CA. A root-only
on-host backup remains retained; no private contents were exported. `rpm -V` for
both installed packages returned 0 with empty output. Core PID 494365 had zero
restarts. Fresh accepted UserSensor samples, Activity and an open WSS session
were verified at 11:23Z; the activity listener reported `READY`.

## SSH startup finding

Automatic access granted revision 2, generation 1, for the selected existing
`root` UID 0, expiring at **2026-11-08T19:18:32.175239Z**. The independent parent
service ran, but its SSH master repeatedly exited 255 before a forwarding receipt.
No successful administrator connection is claimed.

Timing probes showed that an enabled HTTPS policy can arrive before the exporter
and broker publish its gateway key. The client launched its master once; the
eight-second acknowledgement wait did not restart a master that had already
exited. The later `tunnel_failed` status masked the effective policy and broker
authorization. A subsequent healthy local-readiness status restarted the same
race. Strict SSH diagnostics before authorization returned public-key denial.
The identical pinned key authenticated successfully in a measured authorized
window, remained alive for three seconds, and created its expected root-owned
0600 control socket. Diagnostic processes were terminated afterwards.

Support-only diagnostic restarts did not qualify unattended startup. A distinct
180 candidate will retry initial dead masters within a bounded activation window
and the original BOOTTIME deadline. Configured authority, expiry, revocation,
host verification and positive forward acknowledgement must remain unchanged.
Existing signed 179 media and all failed receipts stay immutable. Native rollback,
ordinary/offline removal and reinstall, clean registration linkage, two actual
root SSH commands with Core/updater stopped, and final stability remain pending.
