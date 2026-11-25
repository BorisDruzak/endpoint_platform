# Existing Linux publisher signing input restored

The signing blocker reported at the
[staging provider checkpoint](2026-11-07-linux178-staging-provider.md) was resolved
on 8 November without changing the existing key, passphrase store or trust.
Linux native acceptance remains a separate unfinished gate.

## Cause and verified repair

The original operator script created the pinned key through a PowerShell native
pipeline: a randomly generated phrase was protected as UTF8 bytes with Windows
DPAPI, while `$rpmPhrase | gpg --passphrase-fd 0` supplied CRLF to MSYS GPG.
The original creation commands were recovered read-only from the compressed
archived session, not from a new phrase supplied by the user.

The new helper supplied those same protected bytes with LF only. For this key,
MSYS GPG retained the CR as part of the first input line. An evidence-based CRLF
probe immediately produced a detached signature which verified with the original
full fingerprint `BC24B8EE43DBB05A748E11A4343B5DA748370631`.

The helper now writes the protected phrase bytes, byte 13 and byte 10 directly to
GPG stdin. It keeps `--batch --pinentry-mode loopback --passphrase-fd 0`, checks
the immutable input digest before and after signing, requires the pinned full
fingerprint on verification, and clears credential buffers. The phrase is never
placed in arguments, environment, an unprotected file or logs. Private key and
DPAPI files were not rewritten or copied to a VM.

This CRLF compatibility applies to this existing key's creation protocol. It is
not a general instruction to alter phrases for unrelated GPG keys.

## Native and kit proof

Both final Core 178 and UserSensor 178 RPMs were signed through public-only native
formatting workers. Four operator signatures were verified with the pinned full
fingerprint; actual ALT RPM 4.13 then accepted both header and header+payload
RSA/SHA256 signatures on each RPM. Formatting exit 0 is not an installation result.

The exact signed pair was independently inspected by the canonical strict native
verifier on staging Ubuntu RPM 4.18. The closed payload/source manifests, common
frozen manifest, source revision and Setup-to-Core binding matched. The new kit
was assembled from those verified inputs, and both archive and external manifest
were signed and checked again on staging with an isolated public keyring.

The actual privileged source publisher registered the immutable 156 and 178 sources
on staging using its mandatory real native verifier and appended audit events.
It created no workstation installation facts, primary promotion or fleet grant.
Exact package, archive and signature hashes are in the
[candidate record](../releases/linux-3.2.178-native-candidate.json).

## Next compatibility gate

Before invoking RPM, read-only inspection found that VM 107's retained Core 156
uses the exact root-owned canonical `staging.conf` drop-in. Setup 178 refuses all
drop-ins, so this selected staging source is not qualified. No native transaction
was attempted, and no native failure/success result is inferred from this check.

The correction belongs in a distinct 179 candidate. It must recognize only the
approved Core staging file, bind its bytes, filesystem identity and permissions
to the approved operation, and preserve every other foreign-unit refusal. Both
initially active and inactive configuration must remain checked through native
preparation and recovery. Existing 178 signed bytes and its staging source row
remain immutable. Windows 177 and the Linux 156 primary are unchanged.

The sealed 179 source correction and its current evidence are recorded in
[the source gate](2026-11-08-linux179-staging-source.md).
