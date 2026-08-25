# Windows Canary Evidence Closure Design

**Status:** approved design, awaiting document review
**Scope:** Endpoint Platform only; Helpdesk consumes the resulting evidence and is not changed by this design.

## Goal

Make the installed Windows agent produce a truthful, validator-ready, redacted
preflight projection for one headless diagnostic canary. The projection must be
derived from protected local state, not collector defaults. A later collection
after the operation must also identify the bounded completion record for that
operation.

The change closes the observed gap where the current collector reports Windows
Service Control Manager's `Auto` value verbatim while the validator requires
`Automatic`, and emits placeholders for the MSI hash, transport state,
capability, and completion proof.

## Non-goals

- Do not change Helpdesk routes, credentials, databases, deployment topology,
  or production systems.
- Do not put claims, tokens, enrollment identity, command arguments, raw tool
  results, endpoint URLs, or command lines into the projection.
- Do not treat a locally generated self-hash embedded in the MSI as evidence of
  the MSI's own bytes; that construction is circular and is rejected.

## Evidence model

### Detached installer provenance

The Windows release build emits a detached, versioned release manifest next to
the MSI. It records the package version, product identity, source revision,
initial runtime tree hash, and SHA-256 of the finished MSI. The MSI is built
first; the release manifest is generated only after its final bytes exist.

The reviewed Windows installation wrapper accepts the MSI and its detached
manifest, verifies that the MSI's computed SHA-256 equals the manifest value,
and then:

1. copies the exact MSI bytes to a protected Program Files execution cache;
2. invokes the normal MSI install path from that cache; and
3. after MSI ACL setup, writes the same verified bytes and a small provenance
   record to the protected ProgramData evidence cache.

The wrapper fails before installation if the input, manifest schema, hash,
cache target, or DACL/reparse checks are invalid. The execution cache and the
ProgramData evidence cache/provenance records are regular non-reparse files.
They are readable only by the reviewed
machine/service principals already allowed for the agent data root. A direct
`msiexec` installation remains possible for ordinary product installation, but
it is deliberately ineligible for this strict canary until installed through
the reviewed wrapper.

The preflight collector recomputes the cache hash, compares it to the detached
provenance record and the expected canary release manifest, and cross-checks
version and product identity against the installed agent selector/registration.
It reports only `version`, `sha256`, and `owned_files`; never the installer
path, original source path, or a user-controlled filename.

### Runtime safe status

The Windows agent owns one fixed, protected JSON status file below its data
root. Its schema is `endpoint_windows_canary_status_v1` and contains only:

- release identity: version and source revision;
- transport facts: strict-TLS verification, hostname verification, redirect
  absence, gateway WebSocket state, and HTTP-fallback state;
- the exact allowed capability `context.diagnostic.collect`; and
- the most recent bounded completion-proof record, if one exists.

All transport booleans are written from the agent's actual verified connection
state. Unknown, stale, failed, or fallback states are recorded as non-ready;
they are never inferred as successful merely because the service is running.
The status writer uses atomic replacement and validates the fixed path and
parent against reparse points. The record is bounded and redacted: it retains
only the configured hostname (not a full origin, path, certificate material,
authentication information, tool payload, or raw diagnostic output) so the
collector can bind the proof to the approved staging FQDN.

The agent reuses the existing protected `command-completions.jsonl` mechanism
for completion records. The safe status exposes at most the selected record's
existing fields: command identifier, capability, status, duration,
result-item count, and timestamp. It does not duplicate or expand that
evidence format.

## Collector and validator behaviour

`Collect-WindowsAgentPreflight.ps1` becomes a read-only collector. It rejects
missing, malformed, reparse-point, unprotected, or schema-incompatible
artifacts rather than emitting placeholders.

- Service startup values are normalized at the collector boundary. The Windows
  SCM value `Auto` maps to canonical `Automatic`; all other values retain a
  documented canonical spelling.
- MSI facts come exclusively from the protected installer cache/provenance
  pair and installed identity cross-checks.
- Network and capability facts come exclusively from the safe-status file.
- The collector preserves the current projection shape so the strict Python
  validator remains the single readiness decision point.

The validator keeps the pre-operation distinction explicit: a valid preflight
requires protected status and verified transport/capability facts, but does
not require a completion record that cannot exist before an operation runs.
It validates any present completion record structurally.

The post-operation collection adds `-RequireCompletion` with the expected
command identifier and capability. In that mode it fails unless exactly one
matching completion record is present and has terminal success status. This
separates readiness evidence from result evidence and prevents a prior,
unrelated completion from satisfying the canary.

## Integration flow

1. Build the MSI from a clean endpoint source revision and generate its
   detached release manifest after the MSI hash is known.
2. Install the package with the reviewed wrapper on the dedicated Windows
   staging device. The wrapper verifies and retains the exact MSI bytes.
3. Start the agent normally. It writes only truthful safe status based on its
   verified Endpoint transport state.
4. Run strict preflight collection and validation before scheduling the
   diagnostic. Failure is a hard stop.
5. Schedule exactly one diagnostic operation through the already deployed
   staging control plane.
6. Run post-operation collection with `-RequireCompletion` for that operation.
   Package the redacted evidence, hashes, and rollback proof under the existing
   evidence-retention controls.
7. Restore the staging controls to their disabled/legacy state after the
   package is complete.

## Failure handling and security invariants

- No collector path follows symlinks, junctions, or other reparse points.
- A missing cache, provenance record, safe status, protected completion file,
  or required ACL is `NOT READY`, never a default-ready value.
- Every source of evidence has fixed schema and bounded fields; unknown keys
  are rejected by the validator.
- The agent does not acquire Helpdesk data or credentials. Helpdesk receives
  only the redacted projection and existing operation evidence.
- A failed canary does not retry the diagnostic automatically. Investigation
  may collect read-only evidence, then the operator restores the documented
  staging rollback configuration.

## Verification

The implementation must add tests before production code for:

1. canonical service-start normalization, including `Auto` to `Automatic`;
2. rejection of placeholder, missing, unsafe, malformed, stale, and reparse
   evidence artifacts;
3. detached manifest/hash/cache provenance agreement and selector/registration
   identity mismatch rejection;
4. safe-status atomic serialization, redaction, size bounds, and runtime
   connection-state transitions;
5. preflight acceptance without completion and post-operation rejection unless
   the exact terminal completion record matches; and
6. MSI build and installation-wrapper contracts showing no secret-bearing
   property, command line, or artifact is introduced.

The release gate then builds a new Windows MSI, installs it only on the
dedicated staging device, performs one fresh diagnostic operation, verifies
the immutable evidence package and rollback, and preserves an encrypted
off-device copy. No production deployment is part of this design.

## Compatibility and migration

This is an additive Windows evidence contract. Existing installations continue
to run, but strict canary eligibility begins only after installation through
the reviewed wrapper and creation of the protected safe-status artifact. No
database migration or API version change is required.
