# Windows Setup progress and automatic156 enrollment

The user explicitly requested automatic156 installation without campaign overlap
and a visible progress window explaining waits and failures.

Change only the existing `test` campaign mode from manual to auto. Preserve its
192.168.101.0/24 scope,156 release allowlist, expiry and quota. Validate every host
in that subnet with the deployed canonical selector, under a transaction lock,
and append an operator audit event. Do not add156 to the overlapping old campaigns.

Use a native Windows progress window and a thread-safe bounded progress model.
Keep installer work on its original main thread; the UI owns a dedicated Windows
message-pump thread. Show preflight, MSI, enrollment, manual approval/review,
provisioning, connection verification and the final result. Use an indeterminate
indicator within a stage; never invent native MSI percentages. A running native
installation cannot be closed or killed from this window. Enable Close after the
terminal result. Quiet, preflight and authenticated recovery paths remain headless.

Map bounded internal reasons to Russian explanations and corrective actions.
Preserve WAITING_APPROVAL on timeout and show connection failures without exposing
server responses, claims, capabilities, credential contents or authorization data.
Emit progress when state changes, not every polling tick. Progress logging stays
in the protected Installer directory and cannot change install results.

Reuse the signed156 MSI and exact Core payload for an installer-only revision,
`3.2.156+setup.1`, with a distinct filename, hash and release registry entry.
Keep the historical156 and158 artifacts immutable and the qualified runtime158
record intact. Separate Setup release identity from payload version explicitly
in the builder. The new Setup requests release `3.2.156+setup.1`, installs156,
and is admitted only by the same AUTO campaign after qualification.

Alternatives considered: rebuilding the whole agent would change unaffected
runtime bytes and require unrelated ALT release qualification; replacing156
would violate immutable release identities. Adding Qt or Tcl/Tk solely for this
window would enlarge the privileged bootstrap. Native controls fit the existing
ctypes/Win32 installer and avoid another bundled GUI runtime.

Verification: RED/GREEN tests for callbacks, timeout reasons, unknown reason
redaction, quiet behavior and UI lifecycle; packaging identity/signature guards;
native UI inspection; signed artifact preflight and domain Windows acceptance.
Never present a simulation or preflight as a fresh native install.
