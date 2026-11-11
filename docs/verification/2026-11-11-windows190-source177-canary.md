# Direct Windows 177 to 190 production canary

Production assigned signed Setup 190 to A2-MUNSLU-S1 (192.168.101.146) at
11:59:47Z. Its WSS session closed at 12:00:44Z. Assignment
`f539f978-95b8-444a-8bac-8a885c651c64` remained assigned at 12:19Z with
no native start or attempt ID.

Production assigned the same release to connected C1-ARHIT-S7
(192.168.101.138) at 12:04:28Z, starting from Core/Foundation 3.2.177
and observer 1.0.7. Assignment `d195ec80-cdb5-496c-a6ea-1dbd7cf3f169`
reached APPLIED at 12:16:51Z. Native exit was 0. The proof matched the
immutable MSI digest and recorded all four private materials preserved,
six samples over 182.684 seconds, stable services and companions, live
WSS and one UserSensor. Observer 1.0.8 confirmed ready Core/Foundation 190.
The same device identity received installed lifecycle event
`54abf0ca-52f0-5a93-96da-b4915e946b25`. An explicit post-install inventory
collection completed at 12:11:29Z with Windows x86_64 and no warnings.
UserSensor and activity data continued after APPLIED.

At 12:20:15Z the separate Support service still reported 1.0.1. The old
grant had expired, and the tunnel was disconnected. The server receives
the running service report. The new helper's local install result is stored
in `%ProgramData%\Endpoint Platform\Installer\support-install-result.json`.
SMB did not respond from the operator workstation or production Endpoint.
The cause of the incomplete Support transition is unresolved. No source 177
qualification or promotion was recorded. The Windows enrollment download
remains 177, and enabled policy 17 still targets 189.

An independent fleet preview found .120 eligible for 190 despite Core 190
already occupying the target staging slot on Foundation 189. The signed
native updater requires that slot to be vacant. Commit
`07f1bf283f1e2134880d71ca25ae0ca0f42ec938` blocks this split-source case
in the fleet evaluator while preserving already-current results and future
admission. The regression failed before the fix and passed afterward.
Python suite: 4232 passed, 441 skipped. Console: 122 unit tests and 17
browser tests passed, with typecheck and build successful. Contract and
offline Alembic checks passed. The reviewed provider archive changes only
the fleet evaluator. It has not been deployed. Production had about 505 MiB
available, below the 10 GiB gate for a provider upgrade.
