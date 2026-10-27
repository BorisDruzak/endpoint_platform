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

After independent source review, install the exact reviewed buffers exclusively
under `/root/keycloak-identity-recovery-20261027-executor` (root, mode 0700), with
`recover_pilot_identity.py` and the pinned `pilot_acceptance.py` root, mode 0600. Verify
the complete physical ancestor chain and hashes before execution; never execute
root source from an ordinary-user/PostgreSQL-writable staging directory. Preserve
all prior source snapshots, forensic backups and failed-run receipts.

The server command has no secrets in argv:

```sh
/usr/bin/python3 -I -u /root/keycloak-identity-recovery-20261027-executor/recover_pilot_identity.py \
  --qualify-private-candidate keycloak_recovery_20261027_55f72537 \
  --pilot-helper /root/keycloak-identity-recovery-20261027-executor/pilot_acceptance.py \
  --pilot-helper-sha256 7df5688f2c4de83cec4047c1788e56a8ccf1b84bd7297102545bea7bfa0a1cd8
```

The candidate has its own physical data/home/temp directories and local cache.
Its distribution is freshly extracted from the retained official archive at
`/root/keycloak-input/keycloak-26.8.1.tar.gz`, pinned SHA256
`4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8`.
The optimized build runs only in this private tree, in a network namespace with
an empty environment and a 1024 MiB heap. Runtime heap is 768 MiB with explicit
private Java home/temp properties. Live `/opt/keycloak` is not copied or built.
All outgoing provider/client/listener configuration is checked before session
APIs; only the fixed read-only LDAPS pilot scope is permitted.

Private listeners are HTTP 127.0.0.1:8089, management 127.0.0.1:9009 and
HTTPS 127.0.0.1:8449. The parent owns the strictly local SSH 18449→8449 tunnel and
normal corporate-CA/hostname verification for `sso.sosnadmin.local`. The browser
uses the fixed trusted 18449 authority, intercepts all three registered callbacks
before application requests, and denies other HTTP/WebSocket egress. No TLS
validation bypass, public proxy change or application binding is required.

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
timestamp collected after slow checks. Both sides reject stale or changed proof;
the server rechecks the actual binding on every reply. Passwords, tokens,
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

This document describes the reviewed workflow boundary, not a claim that live
private qualification or public promotion has completed.
