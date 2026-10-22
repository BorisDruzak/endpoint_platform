# Signed ALT distribution

Publish immutable version directories under
`/var/lib/endpoint-platform/distribution/alt/` using
`endpoint-alt-distribution.nginx.conf` inside the existing HTTPS server. Keep the
existing network ACL, certificates, API and WebSocket locations. Test Nginx
before reload; retain the prior site config and release pointer for rollback.
No application route, SDK or OTA contract changes for this static download path.

Only publish public kit archives, detached archive/manifest signatures, manifest,
checksums, public RPM key and operator guide. All directories must be root-owned
0755, files root-owned 0644 and regular (no symlinks). Never copy the signer home,
environment CA, claims, device state, credentials or private acceptance evidence.
Do not replace files in an existing version directory with different bytes.

Revision `3.2.127-2` is the signed counterpart of the qualified 3.2.127 runtime.
Verify the full publisher fingerprint independently:
`BC24B8EE43DBB05A748E11A4343B5DA748370631`.
Follow `packaging/alt/pilot/README.ru.md` for client verification and installation.
Validate canonical HTTPS GET/HEAD with the environment CA, download hashes and
detached signatures, rejected writes and disabled directory listing after
publication. A fleet rollout still requires an explicit target group, unique
enrollment and its environment configuration; publishing does not enroll hosts.

The dedicated operator GnuPG key and encrypted recovery export stay outside Git
and build hosts. Its passphrase is protected for the operator's Windows account
with DPAPI. Recovery requires separately preserving that account's DPAPI access
and the protected keystore; do not publish those files with the kit. Key rotation
requires a new fingerprint, pinned public key and new immutable kit revision.
