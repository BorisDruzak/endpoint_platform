# Full Setup165 and persistent Windows update workflow

The user explicitly requests a new full signed Setup containing the Core164
power-context fix, persistent automatic updates for current and later-connected
agents with two concurrent chains, repository rules and a repeatable web process.
Release number165 is an implementation choice: Core/Foundation/native Setup agree;
Linux media remain separate. No reboot, GPO or manual workstation preparation.

## Approach

Reuse the existing canonical full-Setup controller, exact-source qualification,
audited fleet policy and scheduler. A second updater or static device list would
duplicate ownership and omit future connections. Core-only164 delivery is already
accepted but does not satisfy the requested native release. Extend the existing
Console flow rather than introduce another release screen or build service.

## Workflow

Signed immutable build/publication remains the controlled release procedure.
In Console show numbered steps: choose a published exact full Setup; test on a
selected device; qualify its real accepted result; preview coverage/choose two
chains; save persistent all-active policy; monitor actual results and pause.
Use one selected target throughout canary and policy. Qualification must call
the existing proof validator through the same authenticated, CSRF-protected,
audited and transactionally revalidated admin boundary. Never fabricate proof
or allow browser fields to assert qualification. Changing target invalidates
preview/qualification assumptions. Keep read-only roles and draft conflict handling.

The all-active scheduler re-evaluates future registrations/reconnections. Preserve
native recovery ownership, no automatic MSI replay, exact compatible source gates,
global max_parallel2 and stop-on-failure. Unsupported historical sources remain
visible with reasons rather than being silently treated as updated. Qualification
expiry remains visible; no permanent source-trust bypass is added.

## Acceptance

Build165 from exact committed source, pin initial runtime files/toolchain/artifact
binding, sign MSI and EXE with the existing trusted publisher and timestamp, verify
actual served bytes, publish to the single default AUTO enrollment campaign.
Native canary101.120 from Core164/Foundation158 must reach165/165 through Endpoint,
with native0, private identity continuity, stable services/companions, fresh WSS,
power and active-user telemetry during180-second observation. Qualify that exact
EXE/source in Console, enable all-active/max2 there, follow current assignments
and prove later-device scheduling in server tests. Promote the Windows download
after acceptance while preserving historical Windows and unchanged Linux records.
Yandex browser acceptance remains user-deferred. An inactive user's missing sensor
does not justify manual login or fabricated telemetry.

GitNexus was consulted first: indexed endpoint main50cb0ffd does not contain the
unpublished SetupFleetPolicy branch. Its missing symbol is not an absent runtime
dependency; verify this branch's routes/policy/controller/tests directly. React
is pinned19.3.0 and its matching Context7 documentation was consulted.
