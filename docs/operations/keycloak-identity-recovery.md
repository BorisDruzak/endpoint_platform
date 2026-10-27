# Keycloak pilot identity recovery

`tools/keycloak/recover_pilot_identity.py` handles the fixed synthetic pilot and
the verified original Keycloak 26.8.1 backup. The command defaults to a plan.
It does not reset credentials, reenrol OTP, modify AD, or offer a public database
switch command. Production application SSO activation is a separate gate.

## Evidence boundaries

1. `--prepare-candidate` verifies the pinned dump/configuration and current
   physical permissions/capacity, creates a fresh forensic backup through the
   canonical backup script, and restores into an exclusive database owned by
   `keycloak` with PUBLIC access revoked. It preserves all previous databases,
   including the PostgreSQL-owned metadata-only audit clone. It records all 101
   table multisets and structural schema/ACL hashes and stops before any JVM or
   Admin API call. A successful restore is not a private qualification.
2. Read-only identity evidence verifies the original stable subject, unique AD
   GUID, federation, creation time and exact original OTP full-row digest against
   the verified restored snapshot. Hashes are computed on the database server;
   secret credential columns are never emitted.
3. `--qualify-private-candidate` operates only on that restored candidate. It
   applies the reviewed retention/MSAD guards before any pilot user API, checks
   audience/basic scope parity, proves one real LoA1 browser cookie and one fresh
   master token valid before and rejected after session revocation, and stops its
   owned process. Post-stop SQL must show zero online/offline/authentication
   sessions, the original subject/OTP unchanged and fresh realm revocation bounds.
4. Original/current and final data drift remain **UNREVIEWED**. The result is
   `QualifiedUnreviewedDriftHold`, `switch_ready=false`; it never authorizes
   public promotion. A later semantic review must explain every exact row change,
   preserve newer public audit history in forensic dumps/databases, and distinguish
   that retained newer history from the restored candidate's older canonical
   history. Hash-only differences cannot be approved as a blanket table waiver.

## Private execution closure

The failed v7 attempt modified `keycloak_recovery_20261027_55f72537`
(OID20856). The next independently reviewed fresh prepare restored
`keycloak_recovery_20261027_2190f3d5` (OID22159) with all101 original row
multisets/schema/ACL/sequences and original subject/OTP exact. Run7 then accepted
real initial and SSO browser callbacks but failed at
`purge_restored_sessions_master_last`, before `session-provenance-before.json`.
Its old `UnclassifiedRefusal` does not identify the actual failing guard.
Independent reconciliation confirmed the owned JVM stopped and private ports
free; public services and the original subject/OTP stayed unchanged.

Both candidates are now modified forensic databases: OID20856 changed seven
tables and OID22159 changed eight. Preserve both full101 snapshots, their
immutable Stage1 evidence, all executors/work trees and every journal. Neither
candidate is pristine or eligible for another qualification attempt. Preparation
metadata was independently accepted; purge/revocation, semantic review and
promotion remain incomplete. Do not rerun the historical v8 command against
OID22159.

The next source profile uses `/root/keycloak-identity-recovery-20261027-executor-v9`
and `/var/lib/keycloak-recovery-v9`. It is source-only until its complete closure
and a new uniquely prepared candidate are independently reviewed. Installation
must create the executor exclusively (root0700), write exact verified recovery
and pinned helper buffers (root0600), and verify the physical ancestor chain and
hashes. Existing v1-v8 executors and work roots are never overwritten, resumed or
repaired. Canonical process checks compare prepared/current systemd metadata
exactly and separately bind unchanged `/proc` creation ticks, unique Java
ancestry/UID/executable and protected process groups. Creation time and systemd
exec time are different events and have no tolerance comparison.

Before another full qualification, the proposed bounded master-token diagnostic
must receive a separate source/runtime review. It performs one master login,
the boolean-only token witness, unchanged constructor and 45-second lifetime
checks, one realm-list GET and one SID-bound read-only inventory, followed by
owned cleanup. It has no browser, AD, user-identity API or purge path. Necessary
internal read-only original-identity/OTP comparisons remain runtime preconditions.
A successful probe would not prove revocation or promotion readiness. See
[keycloak-recovery-purge-diagnostics.md](keycloak-recovery-purge-diagnostics.md).

Any future candidate has its own physical data/home/temp directories and local
cache under the new v9 root. The previous `/var/lib/keycloak-recovery` directory,
retained v4-v8 trees and all prior journals remain unchanged. Matching candidate
processes in any historical root refuse a new attempt; retained inactive files
are not repaired or resumed.
All three group-traversable directories (common root, candidate and TLS) use one
exclusive creation primitive: create 0700 relative to a protected parent FD,
open without following links, validate root ownership/inode, then set group and
exact 0750 through that FD and validate again. Existing paths are refused;
there is no repair/chmod of prior history. Process umask stays 077.

Immutable Stage1 evidence remains at
`/var/backups/keycloak-recovery/<candidate>`. Before creating an attempt, the
helper requires its complete 101-table baseline/OID and original OTP unchanged,
old/new candidate work paths absent, the new common root absent and no matching
private process. Every qualification writes only to a fresh exclusive sibling
`/var/backups/keycloak-recovery/<candidate>-qualification-<16hex>`, mode 0700.
Context/restore/identity reads always use Stage1 evidence, never the new output
journal. Existing `qualification-begin.json`/failure files are not reset.

Its distribution is freshly extracted from the retained official archive at
`/root/keycloak-input/keycloak-26.8.1.tar.gz`, pinned SHA256
`4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8`.
The optimized build runs only in this private tree, in a network namespace with
an empty environment and a 1024 MiB heap. Runtime heap is 768 MiB with explicit
private Java home/temp properties. Live `/opt/keycloak` is not copied or built.
The historical candidate-specific v8 build recipe SHA256 for `2190f3d5` was
`d7f14b6e2481692ef26ab3b7b58cc976e506186fa4020b6c7e9eb3934998b2e5`.
That historical recipe is consumed evidence, not a reusable runtime approval.
Any future probe or qualification must independently pin its new candidate/OID,
recipe and exact executor source before execution.
All outgoing provider/client/listener configuration is checked before session
APIs; only the fixed read-only LDAPS pilot scope is permitted.

Private listeners are HTTP 127.0.0.1:8089, management 127.0.0.1:9009 and
HTTPS 127.0.0.1:8449. The parent owns the strictly local SSH 18449→8449 tunnel and
normal corporate-CA/hostname verification for `sso.sosnadmin.local`. The browser
uses the fixed trusted 18449 authority, intercepts all three registered callbacks
before application requests, and denies other HTTP/WebSocket egress. No TLS
validation bypass, public proxy change or application binding is required.

Native `ss` may render Java sockets as `[::ffff:127.0.0.1]:<port>`, including
both sides of local PostgreSQL connections. One strict numeric endpoint parser
accepts only literal 127.0.0.1 or IPv4-mapped IPv6 whose embedded address is
exactly 127.0.0.1. It checks the exact listener/peer port (and bounded numeric
source port), rejecting ::1, wildcard, other 127 addresses/IPs, names, zones,
ambiguous syntax and duplicate listeners. Accepted listeners are normalized to
the existing canonical 127.0.0.1 fields in the 35-field proof. PID/UID/group/exe,
all three owned sockets, exact PostgreSQL client-port/OID sets, TLS, no-UDP and
Nginx exposure guards remain required. The mapped grammar was observed on the
canonical service; stopped prior candidate sockets were not reconstructed, so
their exact formatting is not retrospectively asserted. A source-pinned pure
parser check against existing canonical sockets is a separate native preflight,
with no bind, JVM launch or configuration change.

The private runtime alone selects Narayana's supported `MBeanProcessId` using
`-Dcom.arjuna.ats.internal.arjuna.utils.processImplementation=com.arjuna.ats.internal.arjuna.utils.MBeanProcessId`.
The pinned chain is Keycloak 26.8.1 → Quarkus 3.40.1 → Narayana 7.3.4.Final.
Its [property](https://github.com/jbosstm/narayana/blob/7.3.4.Final/ArjunaCore/arjuna/classes/com/arjuna/ats/arjuna/common/CoreEnvironmentBean.java)
selects the [local RuntimeMXBean process-ID implementation](https://github.com/jbosstm/narayana/blob/7.3.4.Final/ArjunaCore/arjuna/classes/com/arjuna/ats/internal/arjuna/utils/MBeanProcessId.java).
Before this runtime profile can be qualified, an independently reviewed native
library-only probe must verify class selection, actual numeric PID compatibility
and absence of added sockets on the pinned Java/JARs, in its own network namespace.
That gate does not start Keycloak or access a database/configuration/secrets.
The flag is absent from canonical production configuration and private build
options. It changes process-ID selection only: transactions and the exact3TCP/
zeroUDP guards remain enabled. No stopped candidate's previous socket is
retrospectively attributed to this mechanism.

The isolated library-only v3 gate passed on the pinned archive/JARs and Java.
Final safe receipt:
`C:/Temp/endpoint-sso-browser-20261027/recovery-plan/narayana-native-pid-probe/native-v3-final-safe-receipt.json`,
SHA256 `b92554f29e20ac5bdb346315cc3a85051a1d0865dfa260896782345b08995154`.
It binds the accepted transport receipt SHA256
`2dacde912b02efda44a70649fc7338604809373b7b19c70684f1f2f01010be57`
and reviewed source freeze
`7b9b2679ce00ebba23d00fd82ca0f3869d83d576af4a9ea1bda59c7ef4b810d4`.
Two fresh JVMs in a private network namespace with only loopback, sharing the
host PID namespace, proved: default `SocketProcessId` added one owned loopback
TCP listener from a zero-socket baseline, with UDP remaining zero; `MBeanProcessId`
matched its OS PID and kept both TCP/UDP counts zero. All owned probe PIDs/groups
were absent afterward, canonical services were unchanged and older failed-probe
evidence was preserved. This qualifies the library mechanism only. Private
Keycloak/cookie/token/identity qualification, semantic drift review and public
promotion remain separate gates; previous candidate socket attribution remains
unestablished.

## Memory-only RPC and cleanup

The reviewed parent bridge owns the AD-only password pipe and trusted local
browser source/temp ACL. It must not reuse legacy acceptance credential loaders,
read the original OTP seed, submit OTP, enrol, or collect unrelated Helpdesk keys.
The minimal LoA1 profile aborts on any OTP or enrollment prompt. Existing-OTP
support in a reusable browser helper is future/out-of-scope capability.

The bounded server JSON-line RPC is `browser_start`, `browser_positive`,
`purge_held`, `browser_negative`, `browser_close`, followed by the 17-field
`qualification_complete` result. All four authentication-sensitive events carry
the exact 35-field runtime proof: actual PID/group/start identity, private sockets,
JDBC database/OID/ports, archive/build/configuration closure, TLS checks and a UTC
timestamp collected after slow checks. These initial proofs are audit context.
For each of the four sensitive events, the parent sends exactly one
`runtime_proof_challenge` with that `event_op` and a fresh 64-hex nonce. Only
after receiving it does the server recompute the actual 35-field proof and
return `runtime_proof_response` echoing the exact event and nonce. Replays,
duplicates, wrong events, malformed/oversized lines and deadline failures abort.
The existing normal event reply follows; the server also rechecks actual runtime
binding on every normal reply. The whole server RPC has one 180 s deadline.

The parent starts a 15 s monotonic budget **before writing the challenge** and
keeps that same budget through collection, round trip, TLS/AD/Node checks and
the next sensitive action. Receipt never resets it. Freshness follows from the
causal nonce exchange; Windows/Linux UTC timestamps are not compared. The
positive UTC field is audit-only, with no epoch relabeling, clock calibration,
rate/offset assumption or OS clock change. Passwords, tokens,
authorization URLs/codes/state, cookie values, raw errors and DOM/traces are
never RPC output or evidence. Safe cookie hashes bind the same browser context.

The final master token is acquired immediately before purge, has at least 45 s
remaining, is positively authenticated, and must receive 401 within 30 s while
remaining cryptographically unexpired with a 5 s margin. Master logout is last;
no credential submission may turn the stale-cookie negative into a fresh login.

EOF, invalid replies, cancellation and startup failure stop only verified owned
private process groups. Neither canonical MainPID/JVM nor their groups may be
signaled. Unknown remote exit/cleanup is **HOLD**, never proof of termination or
permission for a blind retry. Reconcile the private process/DB/OID and journal
first. Keep original/current/candidate databases and all sanitized receipts;
there is no automatic drop or overwrite of a failed candidate.
Failure evidence retains the triggering operation before cleanup and records
cleanup phase separately. Only fixed exception-class names and explicitly
whitelisted refusal codes may enter that journal; arbitrary exception arguments,
HTTP bodies or strings are excluded. A failed cleanup still requires HOLD.
Network refusals collect both owned TCP and UDP snapshots before asserting either
condition, then keep distinct fixed refusal codes. An exclusive root-0600
`private-runtime-network-refusal.json` records only source SHA, PID/start identity,
TCP/UDP counts, at most 64 numeric ports per list, a truncation boolean and fixed
endpoint-class counts. No raw addresses, process arguments or log lines are saved.
Passing proofs never write this refusal receipt. A failed receipt write refuses
the proof and stops the owned runtime; it does not waive the socket policy.
Static AST coverage requires every fixed refusal reachable through startup,
runtime proof, canonical/process helpers and the trusted runner to retain its
exact safe diagnostic, including `ProcessIdentityUnavailable`. This changes
diagnostic coverage only; runtime guards are not relaxed. The prior run's
`UnclassifiedRefusal` remains unknown and is not retroactively diagnosed from
checks performed after its private process stopped.

This document describes the reviewed workflow boundary, not a claim that live
private qualification or public promotion has completed.
