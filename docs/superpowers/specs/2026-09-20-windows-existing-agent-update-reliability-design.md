# Windows Existing-Agent Update Reliability Design

## Goal

Existing Windows agents must advance through the signed public Setup EXE and
through the authenticated online-update control plane without losing machine
identity, provenance, diagnostics, or the ability to recover from a failed
handoff. A successful update is reported only after the executable that
started proves the exact requested version through a Gateway WSS handshake.

## Decisions

1. A valid installed machine is no longer an unconditional Setup no-op. Setup
   reads its embedded public installer version and the protected selector. It
   invokes the embedded MSI only when that package is strictly newer, preserves
   ProgramData and enrollment identity, waits for `EndpointAgent`, and records
   `UPDATED`. Equal or older packages remain `ALREADY_INSTALLED`.
2. A pending handoff is retryable without a service-recovery loop. The running
   agent asks the fixed updater service to start again at later polling
   intervals; an already-running updater is benign. An unreadable or invalid
   pending request is quarantined by LocalSystem from the active path so a bad
   local file cannot block later recommendations.
3. Every Windows ZIP contains an immutable `endpoint-update-manifest.json`
   with schema version, agent version, source revision, and hashes for every
   runtime file. The updater validates it before publishing, validates that
   `pc_agent.exe --print-version` equals the recommendation, and writes a
   provenance selector. The startup proof also binds the executable's compiled
   agent version rather than trusting selector text alone.
4. ZIP extraction is bounded to a 512 MiB compressed input, 10,000 entries,
   2 GiB extracted bytes, and no reparse/symlink/path traversal members.
5. A rollout automatically becomes `completed` atomically with its final
   target report. This leaves no active-looking rollout whose targets are all
   terminal. The updater startup window is increased to ten minutes; a timeout
   remains a safe rollback, never a false success.

## Compatibility

The first upgrade from legacy agents accepts their version-only selector and
legacy updater. The new runtime accepts that selector solely for this bridge.
All online updates applied by the hardened updater write the schema-1
provenance selector. No enrollment credentials, campaign data, or claims are
part of the ZIP or update manifest.

## Acceptance

- Setup upgrades an existing 3.2.47-style valid installation without
  provisioning a second identity.
- Invalid pending state does not prevent a later update check or cause an
  uncontrolled SCM failure loop.
- Mismatched binary/version, malformed package manifest, archive oversize,
  too many members, and oversized extraction are rejected before selector
  replacement.
- Two online updates in sequence retain a source revision, emit fresh canary
  evidence, and end as `applied`; a repeat recommendation for the current
  version is idle.
- A final report completes the associated rollout transactionally.
- The signed Windows artifacts and live existing test agent are validated only
  after automated tests and release checks pass.
