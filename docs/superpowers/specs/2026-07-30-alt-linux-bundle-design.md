# ALT Linux Agent Bundle Design

## Decision

The ALT installer will consume the existing Linux release shape, not a new
one-file agent. A release bundle contains a launcher executable and one
versioned `pc_agent` onedir payload. The launcher remains the service entry
point and owns the existing update/rollback semantics.

## Bundle contract

An offline release directory has exactly these logical inputs:

```
launcher
pc_agent/
  pc_agent
  _internal/...
manifest.json
```

`manifest.json` declares a bounded release version, the source revision, and
SHA-256 digests for every regular payload file. It contains no endpoint URL,
CA, claim, device credential, or user-specific configuration. The final bundle
contains no symlinks. The builder copies ordinary source files directly and
dereferences only a PyInstaller onedir symlink that resolves to a regular file
inside the source `pc_agent/` tree; the copied destination is an ordinary file
at the same logical path. Top-level, dangling, directory, cyclic, and
out-of-tree symlinks remain rejected, as do unexpected paths. The installer
verifies the manifest, file digests, executable bits, and required `launcher`
/ `pc_agent` leaves before making any host change.

## Build and install flow

1. Build launcher and agent with the existing Linux PyInstaller specs in an
   isolated Linux test environment. This is necessary because the Windows
   workstation cannot produce the target Linux binary.
2. Assemble and validate the immutable bundle locally, writing only a
   transient artifact outside Git. Record version, source revision, manifest
   digest, and bundle digest as acceptance evidence.
3. The ALT installer stages the verified bundle beneath a root-owned staging
   directory, then atomically installs `launcher` and the versioned payload
   under `/opt/endpoint-agent`. It writes `current.json` only after every
   payload file is durable.
4. The systemd unit starts the launcher with the existing root/data paths and
   continues to expose only the config, CA, and one-time claim through
   `LoadCredential`.
5. If verification or activation fails, the installer restores the complete
   previously validated bundle and prior `current.json`; it never leaves a
   partially selected version.

## Safety boundaries

- The build never consumes a claim, permanent token, CA, or production
  configuration.
- A release bundle is not a credential container and cannot be committed.
- The web provisioning controller remains the only source of a one-time
  claim; the installer merely consumes the fixed root-owned handoff file.
- The browser-facing web service remains unprivileged.
- Installation first occurs only on `test-agent-lin`; production remains
  outside this work until the test acceptance gate passes.

## Verification

Tests cover manifest traversal, unsafe source-symlink rejection, safe in-tree
PyInstaller-link normalization, final-bundle symlink absence, digest mismatch,
incomplete payload rejection, atomic selection, and rollback. A test-host run verifies
the real Linux PyInstaller output, first-boot enrollment, handoff finalization,
service restart identity persistence, baseline collection, update, and
rollback. Logs and acceptance evidence are scanned for claim and permanent
credential leakage.
