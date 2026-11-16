# Endpoint Platform Plan

## Agent and server stability (2026-11-14)

Source and acceptance order originate in the stability audit in the operator
checkout. Development branch is `codex/endpoint-agent-server-stability`, based
on Windows 205 release checkout `c9a46030`. Production server source is pinned
separately at `5bdb4a6f319628dff135919a2b6f7e819b8f4b22`. See the
[STAB-14 baseline](docs/verification/2026-11-14-stability-release-baseline.md)
for source parity, package identity, dependencies and pending release evidence.

Current: production source captured, recovery regression verified on both bases.
STAB-14 server candidate `bcf31dc22217` passed the full isolated Linux,
Windows and Console gates, the 0051 to 0053 migration rehearsal and
the packaged API smoke check. Two archive builds matched byte for byte.
Production remains on 0051. Its release volume had 7.79 GiB free against
the 10 GiB gate, and the volume group had 27.0 GiB unallocated. On the
separate signed Windows Setup 3.2.236 source `57a86985b8be`, the full
Windows gate passed and both installer hashes and signatures were verified.
The GitHub Actions receipt and publication remain open.
A later exact-source check on `bc5c779cd30b` reproduced the server
archive and verified an archive-origin start on schema 0054. Windows
passed 2903 tests and Console passed 125. The Linux gate found nine
test fixtures using the current Device model on earlier schemas and
one outdated updater import allowlist. After correcting the test
fixtures and allowlist, exact source `286cbc082d63` passed the full
isolated Linux and Windows workflow tasks and the Console tests.
The 0051 to 0054 rehearsal preserved the Activity rows and the
legacy device's unknown profile state. The two server archives
matched byte for byte, and the packaged API and Console served
from the new archive. A later exact-source trial of `3d98f465f5d7`
passed Linux, Windows and Console with a new byte-identical server
archive. The 0051 to 0054 migration preserved a synthetic native Setup
hold and an unrequested Core owner. The archived provider cancelled the
paused Core rollout through the authenticated API, replayed the same
receipt, and preserved the separate Setup hold. Production release-space
preflight returned exit 2 with 7,786,672,128 bytes free. The later exact-source
candidate `f0bd839ab4a3` passed 5304 Linux, 2903 Windows and 125 Console tests.
Two server archives matched. The packaged API and worker ran on schema 0054.
The worker emitted the release-volume warning and completed the next job.
The 0051 migration and archived Core cancellation repeated with the separate
Setup hold preserved. The production gate returned 2 with 7,608,045,568
bytes free. GitHub Actions and publication remain open.
Candidate `fcad03de9ce5` passed 5319 Linux tests and two subtests,
2904 Windows tests from a CRLF checkout, and 125 Console tests. Its test
checks native launch ordering through the PowerShell AST for both LF and
CRLF. Two archives matched. The 0051-to-0054 rehearsal preserved the
Setup hold. The archived API repeated the Core cancellation check and
the archived worker logged the release-space warning and kept running.
Production had 7,578,681,344 bytes free and the release preflight exited 2.
GitHub Actions has no receipt for this SHA.
Candidate `28eade8c4c80` passed the complete local Windows workflow
task from a clean CRLF checkout on Python 3.12.16. The JUnit records
2,912 passes and four skips. Console passed 125 tests, the two server
archives matched, and all 333 files were verified. The full Linux
run recovered schema 0051 to 0054 and passed 5,318 tests and two subtests,
with one WSS reconnect test failure and 722 skips. Its heartbeat had
only reached a client-side statement callback when the test launched
the replacement. The regression now holds the instance row so the
heartbeat owns the session before replacement starts. The changed test
passed 20 independent PostgreSQL runs and the reconnect and delivery
suite passed 32 tests with one skip.
Exact source `761dae0b58c0` then passed the full local Linux and Windows
workflow tasks and all 125 Console tests. The Linux pass recorded 5,319
tests and two subtests, and Windows recorded 2,912 tests. The 0051 to 0054
rehearsal retained the synthetic Setup and Core owners and Activity data.
Two server archives matched and each of the 333 payload files matched
the previous candidate. The archived API served health and Console assets,
and the archived worker warned on release-space pressure and completed
`rebuild_daily`. Staging kept the same service PIDs and start times;
the isolated environment was removed. Hosted CI and production release
remain open. Production release-space preflight returned 2 at 7,551,926,272
free bytes.
The follow-up production storage inventory found 27 GiB unallocated in the
existing guest volume group. An 8 GiB allocation passed the LVM test mode.
The [storage preflight](docs/verification/2026-11-14-stability-release-baseline.md#резерв-места-для-следующего-выпуска-на-vm115)
records the active rollback dependencies and the filesystem checks needed
after a real expansion.
STAB-01 source: WSS bounded FIFO and separate command task, fixed worker
process with capability budgets, deadline admission and owned process-tree
cleanup. HTTP pull remains sequential. Windows source fault injection covers
timeout, cancellation and oversized reply. Installed ALT 3.2.205-alt7
terminated a stopped health worker at budget expiry while the same WSS
session continued sending heartbeat. The next collection completed.
An explicit service stop with a paused worker left no live worker and
completed in 30 ms. On the next WSS session the Core sent the interrupted
command's unknown outcome once and cleared its durable outbox on ACK.
While a frozen ALT health worker was paused, the same WSS session applied
a fresh Console policy and persisted cancellation of a second queued
command. The canceled command never ran after resuming the first worker.
On isolated Windows 10 VM143, a lab harness running as LocalService launched
the frozen Core worker, verified a typed result, bounded a suspended worker
to 2 seconds, canceled a second worker and ran a succeeding command.
On installed Windows 3.2.207, Gateway accepted heartbeat during a
suspended health worker and received one failed result after its
45-second budget. Subsequent commands completed in the same WSS
session. SCM stopped the service and a second suspended worker in
798 ms. After restart, Gateway persisted one failure for the interrupted
command and the exact ACK drained the local outbox. During another
Windows health worker stall, Gateway sent a test command and cancel.
The agent persisted canceled with no result before the worker exited,
and retained that state after the worker timed out. In a separate
Windows run, a Console-assigned policy was applied and acknowledged
on the same WSS session while the worker remained suspended. The
original collection succeeded after resuming the worker.
The [native DNS receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#системное-ожидание-dns-в-установленном-alt-core-stab-01)
adds a real resolver stall on installed ALT 3.2.205-alt7. Three typed
dns.resolve requests reached a loopback resolver that withheld answers.
Gateway recorded a single failed result for each after 10.042–10.045 s
from the delivery ACK. In the third run the same WSS session accepted
heartbeat during the stalled call and then completed a healthy DNS request.
Stopping the service during another resolver wait took 22.318 ms and reaped
the owned worker. After restart PostgreSQL accepted one failed result and
the local outbox emptied on ACK. The original resolver and Gateway were
restored. The
[Windows native wait receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#ожидание-wmi-и-диспетчера-печати-в-windows-stab-01)
covers installed Setup 3.2.237 on the isolated Windows 10 clone. While
Spooler or Winmgmt was suspended, the same WSS session accepted heartbeat
between each delivery ACK and result. The printer probe exited before
Spooler resumed, with one typed failure; inventory returned partial
`probe_unavailable` while WMI was held. After resuming both services,
printer and full inventory reads succeeded. SCM stopped the agent during
another real printer call in 579.518 ms and the child was gone. A fresh WSS
session delivered one failed result and the SQLite outbox cleared.
The temporary VM, disk, media and provider database were removed.
STAB-03 source: bounded Windows Core cancellation,
suspended launch into an owned Job, confirmed tree teardown and updater
stop proof. On isolated VM143, SCM stopped the frozen launcher under
LocalService with a hung fixture and its descendant in 10.106 s and 10.086 s.
The second start launched one fixture, and the unrelated process survived.
On the same VM the frozen 3.2.205 Core ran as LocalService through the
same coordinator. SCM stopped the suspended Core in 10.092 s and the
restarted, responsive Core in 1.587 s.
Three updater and rollback tests verified that an unproven stop preserves
the selector. A publisher-signed 3.2.206 Setup passed read-only preflight
from 3.2.192 on VM143 and started one MSI-selected LocalService Core
during native trial. Without a Gateway, Setup stopped the trial Core
before restoring the 3.2.192 selector, returned native 67 and restarted
the source service with unchanged private-file hashes. The same Setup
then accepted a fresh WSS trial on the isolated VM142 Gateway, returned
native 0 and preserved the four fixture files. Installed SCM stopped
suspended and responsive Core in 10.121 s and 0.534 s. The installed
Core-only updater preserved the selector when SCM returned 1053, but
escaped without a terminal report. Source now normalizes the pywin32
stop exception to the existing recovery path. VM143 verified that the
corrected frozen updater under SCM leaves the selector in place,
writes the matching failed outcome and clears the prepared transition.
Signed laboratory Setup 3.2.207 installed from 3.2.192 with native 0,
fresh WSS and matching fixture hashes. Its MSI-installed updater
repeated the SCM 1053 fault: the selector stayed at 3.2.207, the
exact operation recorded failure and both transition files cleared.
STAB-04 source: durable ALT stop receipt,
systemd recovery after helper exit, timeout and SIGKILL, and selected Core
startup with pending present. VM107 isolated systemd fault injection passed
before/after synthetic selector publication, including manual stop/disable
and stale-boot receipt.
The isolated ALT 11.4 VM142 installed a lab-signed headless 3.2.205 RPM
built from the exact committed source. Its installed path unit rejected
an unauthorized pending update with the same Core PID and selector.
Offline remove/reinstall and reboot preserved the selector and fixture
identity, CA and config. A fresh loopback Gateway accepted the exact
lab-signed RPM through source-bound manual approval and first-boot claim
exchange in the installed service. It completed all five context profiles and
verified the request once. After claim removal and reboot, the same device
sent a heartbeat in a new WSS session with identical retained files.
VM142 exercised the installed updater with a service-local launcher and
lab trust overlay. A signed 3.2.206 candidate applied and rolled back through
the path unit. SIGKILL, a shortened systemd timeout and VM power loss after
Core stop passed pre-selector recovery and single-entry operation replay.
After post-selector power loss, replay retained the selected and previous
selectors and candidate executable in place and recorded one outcome.
A separate Gateway canary drove actual download, durable handoff and one
applied report. A combined canary recovered after power loss at selector commit.
The frozen Core retried the same report key after the server committed the
result and exited before sending HTTP 200. The original applied report
remained the only database row for that operation. The power-loss and
report replay scenarios used the lab trust overlay. The intact installed
watcher later completed the Gateway path with the pinned publisher under
STAB-11.
STAB-05 source: durable operation journal before the watched pending rename;
fault injection before/after publication preserved outcome reporting. VM142
confirmed live watcher handoff, post-selector power-loss replay and applied
report delivery after reconnect for a real Gateway assignment.
STAB-06: serialized WSS ownership publication per device. Both reconnect permutations
and heartbeat lock ordering verified on PostgreSQL 16. STAB-07: bounded
notice/close with observable cleanup stages and concurrent server shutdown.
The real WSS ASGI route now has a regression for blocking the old socket's
notice and close. The replacement received `gateway_hello` while the old
notice was blocked. Both timeouts were recorded, and the old route's exit
left the replacement as the sole local and durable owner. The test rejected
an injected serial-cleanup implementation on handshake ordering. The
combined route, limits and reconnect suites passed 36 tests on Ubuntu
with disposable PostgreSQL 16 and 33 on Windows. One SQLite case on
Ubuntu and four PostgreSQL-only cases on Windows were skipped.
STAB-08 source: per-job execution deadlines and PostgreSQL lock/statement
budgets, bounded rollback, redacted attempt/last-success/lag logging and
conservative commit uncertainty. PostgreSQL row-lock regression verified.
Backlog age reports scheduled worker lag. For operation expiry the same log
also reports the time past the oldest active deadline, including rows held by
another transaction, verified on disposable PostgreSQL 16.15. Setup
preparation reports the age of the oldest active chain across stage changes.
Activity rollups record the first dirty transition in additive migration
0053 and report unknown while a dirty row has no enqueue timestamp.
Migration and concurrent rollup tests passed on disposable PostgreSQL 16.15.
Context scheduling reports the greatest delay among newly queued collections
after commit, using the existing eligibility pass and no additional queries.
Enrollment delivery cleanup reports time past the oldest eligible expiry,
including expired envelopes still locked by another transaction.
Operation evidence cleanup reports the oldest expired unpinned payload.
Module step cleanup reports the oldest overdue copy in its committed batch
using its existing bounded read.
Context payload and collection cleanup report the oldest deadline exceeded
in each committed batch, using the existing reads and preserving the current
retention predicates.
Snapshot retention reports overdue age for committed deletions under
time-based policies. Count-based baseline and inventory have no deadline.
Security and power retention measure overdue age from the rows actually
deleted by each committed batch.
Activity retention measures the oldest deadline among deleted detail, daily
rollups and cursors, using the current calendar and timestamp cutoffs.
Setup fleet scheduling measures the longest wait among device evaluations
committed during a worker tick. Lock contention without a sample is unknown.
Worktime request generation measures the time since the oldest prior scan in
the committed batch. A first scan has no earlier cursor. Worktime retention
reports overdue age from deleted records under the configured personnel policy.
Periodic payload cleanup, context collection scheduling and snapshot retention
advance from their scheduled deadlines. A batch finishing within the interval
no longer skips the following tick.
The standard `python -m endpoint_server.worker` entry point on source
`9ff07d0f7f72d053233c04a19bc75c392aeb70e9` completed 15 jobs during a
two-minute isolated Windows process run with PostgreSQL 16.15 at migration
0053. A locked expired security event produced `lock_timeout` in 3.022 s
with zero commits. Power, analytics and Context jobs committed in the
same tick. After unlock, the next minute's tick deleted the same event
and reported 361.792 s of data backlog age. The hourly snapshot job is
covered by the accelerated regression. On the Ubuntu 24.04.3 staging host,
an isolated user systemd unit ran the standard entry point for source
`e44016670afd9163f3fc0ca6fe64f3147bbe6af5` against PostgreSQL 16.15 at
migration 0053. The server source archive SHA-256 was
`6c57a87cac6a845aea7bef143b88606635abda66cd2a58cce4143eb0fe6bd609`.
With default intervals, 15 jobs completed. The locked security row
produced `lock_timeout` in 3.005 s with zero commits. Power, analytics
and Context committed that tick. The next minute's tick deleted the row
after unlock and reported 361.779 s of backlog age. Both transient units
and their temporary database were removed. The staging worker kept
the same PID and start time. Production deployment remains open.
When PostgreSQL has confirmed a commit, a later session cleanup failure
now reports that batch and its measured backlog. The worker logs
`session_cleanup_error`, stops the batch sequence and preserves the
last fully successful attempt. Unconfirmed commits keep the separate
`commit_outcome_unknown` outcome. On disposable PostgreSQL 16 an
independent connection verified that exactly one row was committed under
an injected session exit fault. The log reported one batch and a
67.500-second data backlog. The health suite passed 24 tests on Linux
and 23 on Windows with the PostgreSQL-only case skipped.
The worker now logs each attempt before opening its database session.
Start and completion share the same job name and UTC attempt time, so an
interruption can be identified even when no completion is emitted.
On isolated Ubuntu a worker waiting for an occupied PostgreSQL pool was
killed. Its start line was captured and no result line appeared for that
attempt. The health suite passed 25 tests on Linux and 24 on Windows, where
the PostgreSQL-only case was skipped.
STAB-09 source: explicit Core transfer total/connect/idle
timeouts with matching recovery-supervisor budget. On Windows the published
Core 3.2.163 ZIP (22,905,610 bytes) passed loopback HTTPS download in 22.875 s
with the normal 20 s control request timeout. SHA-256 and the CRCs of all
123 archive entries matched. The HTTPS regression with a synthetic ZIP
verified the configured 15 s idle cutoff and removal of the partial file.
The combined transfer, recovery and supervisor run passed 84 tests with one
POSIX-only skip. The
[installed Windows canary](docs/verification/2026-11-14-agent-release-qualification-matrix.md#медленная-https-загрузка-windows-core-stab-09)
used the signed 22,268,756-byte Core 3.2.238 ZIP. The running 3.2.237
agent disconnected after 14.999 s of inactivity and removed the partial
file. Its regular retry downloaded the full ZIP in 26.947 s with the same
process and no Range request. Gateway confirmed one applied result and a
new WSS session on the same device. Foundation and four private files
matched the source. The disposable VM and its provider resources were removed.
STAB-10 source: streaming ALT archive limits, pre-stop
staging/state capacity checks and bounded extraction. ALT VM107 passed 48
installer tests and the isolated systemd recovery harness, including preflight
rejection with the same Core PID and selector. The 180-second unit budget
covers the full invocation. The [VM142 lab receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#ресурсы-распаковки-alt-core-ota-stab-10)
records representative archive timing and preflight rejection under four real
filesystem limits. The lab launcher uses a test publisher key.
STAB-11 source: pinned publisher signature and exact archive/source
authorization from root-owned local state,
private retained bytes and a pending-request recheck before selector commit.
ALT VM107 verified OpenPGP acceptance with an ephemeral test key and rejected
missing, changed and mismatched authorizations. The
[VM142 publisher receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#приёмка-stab-11-со-штатной-подписью)
records positive acceptance of the exact 3.2.206 archive by the unmodified
RPM launcher with the pinned publisher, successful rollback, and fresh WSS
for both versions on the same device. This was an isolated local pending.
An installed ALT headless RPM now carries the pinned publisher public key and
requires GnuPG. The lab-signed alt6 exposed a stale revision in the selector
on same-agent-version upgrade. On VM142, alt7 refreshed that selector, passed
the release manifest check, preserved enrollment state and reconnected to
the loopback Gateway. Its installed watcher rejected a foreign-signed
authorization before stopping Core. The
[Gateway delivery receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#доставка-через-gateway-со-штатной-подписью-stab-11)
adds one real assignment to the intact RPM watcher with this same pinned key.
Core requested and downloaded the exact archive via HTTPS, reconnected by
WSS as 3.2.206 and delivered one applied report 5.517 seconds after requesting
the update. The local return to 3.2.205 restored the selector byte-for-byte
and preserved the enrollment and credential files. The Gateway kept the
completed rollout and its original report. The native rollback generated a
new WSS session and received HTTP 404 when attempting to report against that
settled operation. The temporary authorization and test download were removed.
STAB-12 source: the Windows Setup observer starts read-only preflight in an
owned process job, bounds stdout during capture and stops on stderr. Windows
PowerShell 5.1 verified repeated timeouts, output overflow and child cleanup
against a synthetic console application. Running the exact signed 1.0.12
observer preflight functions against the signed VM143 Setup returned the
expected in-progress result. The installed 1.0.12 task ran as SYSTEM,
sent hello and received no assignment from the isolated Gateway after
temporarily setting aside the settled pointer for the old lab identity.
The pointer was restored byte-for-byte.
The [VM143 timeout receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#очистка-дерева-read-only-preflight-stab-12)
records the signed 1.0.12 functions running as SYSTEM under Windows PowerShell
5.1. The stock 180-second deadline reaped the synthetic process tree in
180.043 seconds. Six short failure cases reaped their trees, and the next
healthy preflight succeeded with the Agent service PID intact.
STAB-13 first change: accepted Windows Core selection retires the exact
operation ZIP after its durable acceptance record, with path, ACL, identity,
size and digest checks. The Setup observer retires the verified download for
its settled assignment while keeping the Setup journal and native cache.
Low space is reported before download. The server worker logs free and total
artifact volume bytes at startup and every 15 minutes. Windows Core terminal
failure and rollback retire their exact verified ZIP after server ACK.
Before Windows Core staging, a bounded pass under the update mutex retires
older ZIP runtime trees with exact provenance and inventory. Selected,
previous, pending and current native recovery versions are reserved. Trees
with MSI, retained-runtime or ambiguous ownership are kept. The server
inventory CLI cross-checks artifact names against four release catalogs.
Before admitting a different Setup assignment, a bounded pass retires older
downloads with a matching terminal journal, device identity and native-start
receipt. Windows Core uses an attempt-specific staging file and publishes its
ZIP only after the scheduled ACK and a lifecycle recheck under the update
mutex. Failure before pending publication retires the unreferenced ZIP.
A visible pending record retains its ZIP across a failed final flush.
Before disk admission, an exclusive online-transfer file lock and the update
mutex allow bounded retirement of abandoned staging and HTTP temporary files
from the lock-aware writer. Windows source tests cover a real subprocess exit
without cleanup and a concurrent check during an active transfer. The ordinary
check now also reclaims this scratch space when the server has no recommendation.
Both paths use the transfer lock and update mutex. NTFS subprocess tests cover
idle and assigned checks, active transfers, and preservation of historical ZIPs
and hardlinked files. Installed Core 3.2.241 on Foundation 3.2.239 reclaimed
both scratch files left by a killed lock-owning test writer on the next
regular check. Gateway returned HTTP 204 and the agent kept its PID and WSS
session. The two unclassified control files retained their hashes. The
[native receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#очистка-прерванной-загрузки-core-32241-без-нового-назначения)
records both disposable VM attempts and their cleanup.
An unconsumed, durable publication record allows recovery to retire the exact
attempt ZIP left between ZIP promotion and pending publication. Recovery
validates the digest and preserves changed bytes or active handoffs.
Terminal Core cache cleanup now records the exact archive identity when
Windows denies sharing or locking. The ordinary idle update check retries
under the update mutex with a bounded byte budget, validates the archive
digest and completes the directory flush before retiring the receipt.
This applies after local acceptance and after the acknowledged failure or
rollback. Six Windows regressions used a live NTFS handle without delete
sharing and distinguished unchanged files, changed bytes and interruption
after unlink. The wider Windows recovery suite passed 414 tests with one
skip. Installed lab Setup 3.2.239 and its native updater applied the signed
Core 3.2.240 through the regular HTTPS path on Windows 10 VM136. While an
independent handle denied delete sharing, the exact archive and deferred
retirement record remained visible after acceptance. The next idle retry
removed both 6.61 seconds after release of the handle. The same device
accepted Core 3.2.240 on Foundation 3.2.239 and retained all four private
files. The native run covers successful acceptance; failure and rollback
remain source-tested. VM136 and its isolated provider state were removed.
Historical Core caches, scratch files from writers without the lock and archives tied to
quarantined handoff records remain open, along with server deployment releases
and retirement of catalog artifacts. The server archive ships both storage
inventory commands. The deployment report measures release directories and
free volume space, classifies the current/rollback/explicit pins, and
preserves unclassified entries for operator review. Read-only production
inventory resolved current and rollback, measured 104 release directories and
reported nine unclassified entries and 8,418,435,072 bytes free on the release
volume. No retirement was performed.
The next production observation found five directories with direct references.
The release-commit marker names `5c3eb383e776`. Support Exporter runs from
`ed643cddf0f5`, and API, worker and Exporter map dependencies from
`ce46fd47a3a9`. The inventory now surfaces these live references in addition
to current and rollback. It reported no inaccessible PIDs in that pass.
The inventory also tracks on-disk dependencies between release directories
and protects those reachable from current, rollback, staged, process or pin
roots. The production pass found 21 directories with such links. Active,
rollback, staged and Support Exporter directories directly link their venv to
`ce46fd47a3a9`; all protected dependency targets were present.
Remaining directories still need review of deployment, restore and audit
records before any retirement.
The [first restore comparison](docs/verification/2026-11-15-server-release-restore-inventory.md)
matched all archive entries for two historical deployments against production
and verified independent scratch extraction from workstation copies. Both
deployed trees add a shared venv link. The two archive copies are retained
under root-owned `/var/backups/endpoint-platform-release-archives`. GNU tar
scratch restores on Linux passed exact payload, uid/gid, mode and POSIX ACL
checks. Production accepted recent DIRPOST and Proxmox health on the current
server. The two pilot release trees account for 6.4 MiB on disk versus a
2.16 GiB gap to the release threshold. The next review targets the larger
historical trees and exact recovery of their private virtual environments.
The inventory of 82 larger trees is evidence for prioritization. Retirement
and projected reclaim still require per-tree verification.
The first full deployment backup, `b9976195cf68`, preserved its private venv
and matched all 5,796 paths after isolated extraction. The protected archive
occupies 30.1 MiB versus 111.5 MiB for the source. The 81.4 MiB difference
is potential savings. The deployed tree remains in place.
The next [restore check](docs/verification/2026-11-15-server-release-restore-inventory.md#копии-d3459936a251-и-b9976195cf68-вне-серверного-тома)
verified all 5,682 paths of `d3459936a251`, including its private venv.
Both verified deployment archives now have SHA-256-checked workstation
copies outside the server volume. The deployed trees remain in place.
The [batch restore check](docs/verification/2026-11-15-server-release-restore-inventory.md#партия-копий-для-проверки-места)
verified 19 additional private-venv trees and rechecked both earlier copies.
The 21 trees occupy 2,374,709,248 bytes against an observed shortfall of
2,365,140,992 bytes. They are still deployed. Storage and reference checks
must be repeated before any retirement.
On 16 November the standalone restore of `b9976195cf68` started the
archived API and worker from its private venv and migrated a separate
PostgreSQL to its own 0044 schema. The worker rebuilt an Activity rollup,
and the API served health and the exact Console assets. All 21 off-volume
copies were rehashed. The measured archive set exceeds the current
space shortfall by only 1,892,352 bytes before any retirement.
The deployment runbook now checks the actual release volume before preparing
or extracting a release. The check works without selectors and exits 2 below
10 GiB. On production it reported 8,384,782,336 bytes available and exited 2.
A later inventory found 7,978,934,272 bytes free. Ten additional private-venv
trees were restored in tmpfs and copied off-volume with verified hashes.
All 31 archived trees retain their measured allocation and lack references
from deployment selectors, running processes and other recognized releases.
Their combined 3,424,309,248 bytes yield a projected 665,825,280 bytes of
headroom over the threshold. Production still has the same deployed trees.
The ext4 root volume group has 27 GiB of unallocated capacity.
At 13:51 UTC, ten more private-venv trees were restored in scratch tmpfs
and copied off-volume with verified hashes. The latest inventory found no
deployment references to any of the 41 archived trees. Their combined
allocation of 4,402,864,128 bytes gives a projected 1,244,151,808 bytes of
headroom over the release threshold. The deployed trees remain in place.
The deployed worker now reports `release_disk` at startup and at the
existing 15-minute interval. It shares the deploy gate's 10 GiB threshold
and reports the artifact volume separately. The archived worker on Ubuntu
and PostgreSQL 16.15 warned on a separate tmpfs with 2,605,330,432 free
bytes; the CLI exited 2 and the next maintenance job succeeded.
Production deployment of the warning remains open.
STAB-02 foundation: local SQLite records a command ID, device, payload digest,
and start before execution, then commits completion and outbox together.
Interrupted starts recover as unknown outcomes. Negotiated WSS sessions
bind the result ACK to the sent command and sequence. The Gateway accepts
same-instance reconnect results under the original deadline and acknowledges
late results for cleanup without applying them. An upgrade header gates the
new hello feature for legacy Gateway parsers. Cancel fences queued work;
started work retains its observed or uncertain outcome. Before executing,
negotiated agents request a start decision. Gateway grants it after committing
running status or sends command_cancel for expired or terminal commands.
Operator cancellation remains scoped to the existing undelivered operation
contract. Installed Windows 3.2.207 replayed an identical session collection
result after loss of its post-commit ACK. PostgreSQL retained one result,
and the outbox cleared after ACK delivery. Installed Windows 3.2.207
also completed a health command on the exact pre-journal Gateway
baseline with a separate database at migration 0051. Installed Windows
3.2.192 completed the same profile against the journal-enabled Gateway
on VM142. Each combination produced one successful result.
The SQLite schema marker remains compatible with Core rollback. A separate
start reservation distinguishes interruption before local execution from an
uncertain executed command. Legacy running rows remain uncertain. The Windows
process-exit trial confirmed both outcomes and prevented replay. Over real
TLS and PostgreSQL, both reconnects produced one result and drained the outbox.
Lab Core 3.2.238 brings the start reservation into the signed 3.2.237
Windows baseline and requires Foundation 3.2.237. The archive verifier
checked all 119 files. Cold extraction ran `--print-version` and verified
the Authenticode signature and RFC 3161 timestamp. Source tests passed
310 cases with eight skips. A stock Windows 10 guest installed Setup
3.2.237 and received Core 3.2.238 through the regular HTTPS updater.
The same device reconnected with unchanged private files and the
installed EXE matched the signed ZIP. Holding the start grant across
a service restart produced one before-start failure and no snapshot.
Holding the result ACK after an actual collection and restarting the
service replayed the same result without a second snapshot. The ACK
drained the SQLite outbox. A separate abrupt power cut after the
installed Core started its owned command worker preserved one
`AGENT_COMMAND_OUTCOME_UNKNOWN` result. The same device reconnected
on the exact signed 3.2.238 and the ACK drained the outbox. The
Gateway recorded one command frame, one result and no snapshot for
that request.
STAB-16 service recovery: Ubuntu 24.04 and Debian 12 package configuration
routes restart through the distribution helper. An enabled failed service
recovers, a manually stopped service stays stopped, and masks are respected.
Both rendered templates passed the service-state matrix. Linux Core freeze
embeds its clean Git revision, and DEB packaging checks the frozen executable
against the requested source and version. New Ubuntu and Debian packages
carry the source revision and Python/PyInstaller versions in their control
metadata alongside the version and SHA-256 in APT Packages. A Debian 12 LXC
rehearsal built the exact source under umask 077 and verified active upgrade,
failed enabled restart, offline reinstall, rollback and container restart. See
the qualification matrix for the temporary systemd override and remaining
installed package acceptance. Isolated Debian 12 VM137 repeated the package
lifecycle through locally signed APT with the stock service sandbox and
received authenticated hello and heartbeat at a local TLS peer after reboot.
Forced VM power-off between unpack and configure recovered with dpkg configure
and preserved identity. The real loopback Gateway then accepted the exact DEB
through request, administrator approval and first-boot claim. PostgreSQL
proved one device and registration, four accepted context profiles, and a
fresh heartbeat in the new WSS session after VM reboot. A second run used the
canonical verification endpoint to reach completed exactly once. A forced VM
stop inside postinst preserved half-configured state, and rerunning dpkg
configure restored the package and fresh Gateway heartbeat on the same device.
A separate power-off froze dpkg while a runtime file was being unpacked.
Exact same-version reinstall recovered the half-installed package and passed
dpkg integrity and identity checks. Gateway persisted a new heartbeat in
the post-reinstall session with the original device ID.
The worker removed the expired retry envelope and wrote the periodic cleanup
audit event. Linux first-boot bootstrap now sends the existing delivery
acknowledgment after verifying the credential and identity files and
persisting the claim-removal request. A loopback TLS run against the actual
Endpoint API and PostgreSQL 16.15 returned 201 then 204, removed the one
envelope and recorded one acknowledgment audit event. A failed ACK leaves
the verified enrollment usable and allows server expiry cleanup.
Debian LXC 127 built the exact 1481bae4 source and verified the DEB through
a signed local APT repository. The frozen enrollment-only process received
one 204 after the credential files were verified. The systemd service then
sent one authenticated hello and a heartbeat to the loopback TLS peer.
The persistent unit hit the known 226/NAMESPACE restriction and required
a temporary LXC namespace override. The original package was restored and
the container stopped. The same DEB then enrolled through the actual
Gateway on a network-isolated Debian 12 VM with the stock systemd profile.
Gateway returned 201/204 once, and PostgreSQL retained one delivery audit
and no retry envelope. The installed unit sent a heartbeat on initial startup and after
reboot on the same device with the original credentials, origin and CA.
The temporary Debian VM, disk and three test ISOs were removed. A separate
Ubuntu 24.04.5 VM installed the signed Noble DEB from the same source and
confirmed 201/204 and one enrollment audit through the real Gateway.
Its stock unit opened a new WSS session after reboot with the same device,
credentials, origin and CA. The Ubuntu VM, disk and test media were removed.
The identical signed Bookworm DEB passed on isolated nested Proxmox VE 8.4.0.
The real Gateway returned 201/204, retained one registration and cleared its
retry envelope. The stock systemd unit sent a heartbeat and `health_v1` in a
new WSS session after reboot, with the same identity, credentials, origin and
CA. The temporary Proxmox VM, disk and payload ISO were removed. Production
publication remains open.
Ubuntu VM138 built the exact Core in an isolated dependency path and exercised
upgrade, failed-service repair, manual stop, masking, rollback, offline
reinstall, and reboot with a local TLS peer. One rollback startup failed in
PyInstaller and recovered on the next systemd attempt. The two exact binaries
reproduced the loader error when the executable path was replaced after
loading the archive index. An operator-stopped rollback and upgrade both
started on the first attempt. The incoming DEB preinst now fences starts
before unpack, confirms the old process stopped, and records whether to
resume it. On Ubuntu VM138, the fence stopped a legacy active 3.2.192
service, rejected starts in the unpacked state and persisted across reboot.
Configure removed it and the 3.2.205 Core sent a fresh heartbeat.
Debian VM137 accepted a locally signed DEB built from the exact commit with
the new hooks. A power cut during postinst preserved the resume record.
Configure retry cleared it and restored fresh Gateway heartbeat on the
existing completed enrollment. Ubuntu VM138 reinstalled an exact-source DEB
through locally signed APT. A forced stop during unpack preserved the fence
across reboot, and exact reinstall restored a first-attempt heartbeat to the
local TLS peer. A separate Ubuntu loopback Gateway and fresh PostgreSQL
accepted the exact build through a completed enrollment and persisted all
five context profiles and a fresh heartbeat after reboot. The first automatic
baseline was granted to the temporary bootstrap service and its running
journal entry stayed in the temporary SQLite database when that service
stopped. The DEB provisioner now opts into an enrollment-only Core mode so the
installed service opens the first WSS session. On Ubuntu VM138, the exact
rebuilt Core exited from bootstrap with zero Gateway sessions or context
collections. The installed service completed the automatic baseline on
the first session, and enrollment verification reached completed without
an administrator collection.
Nested PVE 8.4 VM139 used a separately signed lab APT to install 3.2.195
and upgrade to the exact 3.2.205 from the enrollment-only change.
The loopback Gateway accepted health with trusted API status and available
storage, and recorded fresh WSS after nested hypervisor reboot. Locally signed
APT passed guarded rollback to 3.2.195, forward upgrade, same-version recovery
of a failed enabled service, and offline remove and reinstall. Forced power
loss during unpack and postinst preserved the respective start fence and
resume record. Exact package reinstall and configure resumed the respective
transactions with clean dpkg verification and fresh Gateway heartbeats on
the original device. On a dedicated three-node nested cluster, four fresh
Gateway health snapshots distinguished a missing member with quorum, quorum
loss, and full recovery. Production signing and publication remain open.
STAB-17 source: metadata renewal verifies the pinned signer and all signed index
and DEB hashes before changing the signed dates. The expiry check covers Ubuntu
noble and Debian bookworm and warns with three days remaining. Ordinary APT
accepted both renewed test indexes and downloaded identical fixture DEBs.
The daily timer is enabled on the OpenVPN pilot. Its first run verified both live
signatures. An isolated failure test produced error-priority journal entries
for both suites and exit 1. Ordinary APT accepted both live suites with the
existing CA and signed-by keyring in a temporary lists directory. Production
publisher ownership, alert delivery to the publisher and live renewal remain open.
On 16 November Agent 2 exposed the pilot service result, last completion and
timer state, and reported an isolated unit failure. The Zabbix 7.0 template
monitors all three values. Central import and delivery verification remain open.
The [STAB-17 rehearsal](docs/verification/2026-11-16-stab17-apt-renewal-rehearsal.md)
verified the signatures and SHA-256 chain for both live indexes and all eight
published DEBs. The scheduled pilot check exited 0. Ordinary APT accepted
both live suites over HTTPS and identified the expected candidates. Copies of
those exact repositories were renewed under an isolated rehearsal signer.
APT accepted both renewed copies and downloaded the candidates with their
original hashes. The temporary copies and key were removed. The publisher
CLI now supports scheduled verification and renewal at three days or less.
With GnuPG and APT 2.8.4, both copied channels skipped fresh metadata, signed
when due and skipped an immediate retry. Package and index hashes matched.
The publication CLI now verifies the exact pre-renewal InRelease hash, the
pinned signature and all published package hashes before installing the signed
date-only renewal. APT accepted both renewed copies. The stale-hash attempts
left the target indexes unchanged. Publisher user-unit templates now prepare
signed date-only renewals from a read-only mirror into a separate output
directory keyed by the original InRelease hash. Both exact package sets
passed a real GnuPG and APT rehearsal including an unchanged retry.
On 16 November both live indexes entered the warning interval and
ordinary APT still downloaded both expected packages. The prior
signing key was absent from inspected keyrings. The operator authorized
a replacement, and a protected local signer prepared date-only
candidates for both channels. APT accepted old and new indexes with
the dual public keyring. Preparation and publication both support an
explicit successor fingerprint. A separate GnuPG and APT rehearsal
covered Noble and Bookworm with only the successor's private key
available during preparation. APT downloaded the original DEB bytes
from both revisions with the dual public keyring. If a prepared index
expires before publication, the publisher now prepares a new candidate
for the unchanged source and preserves the previous file. Real APT
rejected expired candidates and accepted the replacements for Noble and
Bookworm with identical DEB hashes. The per-channel publisher environment
now selects the successor for scheduled preparation. The Noble and Bookworm
systemd timers signed both copies with only the new private key available.
APT verified the downloads. Publication still requires the explicit successor.
An isolated Zabbix 7.0.21 imported the exact template twice and received
three active samples from Agent 2. It recorded problem and recovery events
for check failure, an inactive timer and a stale completion timestamp. A
host- and tag-filtered action delivered problem and recovery to a loopback
webhook. Central import, the real publisher's alert receipt, client trust
transition and live publication remain open. All seven checked clients
still pin the prior key. The expiry monitor now accepts a separate pinned
fingerprint per suite through its optional systemd environment file. Real
GnuPG and curl tests verified both switch orders, common-pin fallback and
rejection of the other key in a shared keyring. The live indexes still
verified under the prior key and returned the three-day warning during
the read-only check. Nginx logs for a fourteen-day window identified eight
recurring consumers, including the Noble PostgreSQL host dirpost.
One request from the OPNsense address remains unattributed. Native APT
on all eight hosts accepted their live HTTPS source. With scratch lists
and a dual keyring it accepted both pinned Release revisions and resolved
the same candidate. The old keyring rejected the successor on all eight.
Permanent source, keyring and CA hashes matched before and after the probe.
The OpenVPN pilot now uses the dual public keyring in the configured
Signed-By path. Its installed APT accepted the live HTTPS index and the
successor-signed fixture and downloaded the same DEB. The remaining
consumers and live metadata publication remain open.
Release evidence requires an exact-source CI receipt before publication.
STAB-15: the [release qualification matrix](docs/verification/2026-11-14-agent-release-qualification-matrix.md)
records installed canary evidence by OS, exact source and signed artifact.
Windows Server 2012 R2 recovered from a power cut during removal of Setup 3.2.218
and accepted Setup 3.2.222 with the original device identity and fresh UserSensor.
Setup 3.2.223 delivered both original installation events automatically on
reconnect after offline rollback and reboot, before an interactive sign-in.
On Windows Server 2012 R2, Setup 3.2.225 delivered the original events and
automatically reinstalled and rebound Support after a separate offline remove
and reinstall from 3.2.222. Pinned independent SSH passed with Core and updater
stopped and Setup Observer disabled. The remaining platform and source
combinations are open.
On the same VM, the exact 3.2.225 artifact restored a missing Core service
registration while offline. The original MSI registration and four private
files survived repair and reboot, and Core returned to WSS on the same
device. Native event 9 remained pending after reconnect. Signed Setup
3.2.226 then passed the upgrade from 3.2.225 and an offline same-version
repair. The protected notification task survived an offline reboot
and delivered the exact repair event once after reconnect. Gateway
accepted it under the same device credential and event generation,
and the task retired without another MSI operation. This run covers
the Windows Server 2012 R2 profile without an interactive sign-in.
On Windows 10 build 19045 VM143, the same Setup 3.2.226 upgraded
MSI 3.2.192 with native exit 0 and one accepted installation event.
An isolated lab identity was established before the source baseline.
All four identity files matched after upgrade and reboot. Gateway
received WSS from the same device after reboot and completed five new
context collections. The same signed 3.2.226 media restored a missing
Core service registration while offline on VM143. The native event
survived an offline reboot. Gateway acknowledged it once after reconnect,
and the retry task retired without another MSI operation. A separate
offline remove/reinstall of 3.2.226 preserved the original events through
reboot, delivered them in order and registered Support 1.1.9 for the
first time with access disabled. In a second cycle, default-disabled
Support without a recorded authority decision did not get a rebind
ticket. The lifecycle events were acknowledged and the Support retry
stayed pending. A separate run recorded an explicit disable before
native removal. Gateway acknowledged the next original event pair
and consumed one rebind for the install event. Support advanced from
generation 2 to 3 with access disabled. Core and Support were fresh
and the retry task retired without another MSI operation. A temporary
lab policy confirmed UUID-pinned SSH on VM143 while Core and updater
were stopped and Setup Observer was disabled. The policy was disabled,
the broker port closed, the temporary principal and key removed,
and Core returned to WSS. Ordinary console sign-in as a temporary
standard user started the installed UserSensor and Tray. Gateway
acknowledged the device-scoped Activity policy, accepted content-free
ACTIVE observations and showed a fresh UserSensor on the original device.
On the isolated Windows 10 VM145 clone, signed Setup 3.2.226
rolled back offline to 3.2.192. The original MSI registration, byte-exact
Core selector and four identity files were restored. The same lab device
returned to WSS after reconnect. Setup reported 21/MSI_EVIDENCE_FAILED
after the verified native rollback. The owner trace isolates the failing
phase to `restore-staged-companions`. The retained recovery task had result
60, and two native lifecycle events stayed pending without a delivery task.
The [rollback receipt](docs/verification/2026-11-14-agent-release-qualification-matrix.md#офлайн-откат-setup-3226--32192-на-windows-10)
records the stopped diagnostic snapshot. The helper's Windows event showed
error 109 during the initial owner request. At the trial deadline the owner
pump revokes its session. Rollback settles on a separate owner session, and
companion restoration was still using the revoked trial session. The Setup
wrapper now opens a fresh cleanup session for the same transaction after a
verified rollback. Direct and scheduled rollback regressions first failed
against the original wrapper, then passed along with the accepted path.
The nine targeted Windows test modules passed (363 tests). Signed Setup
3.2.227 qualified offline rollback on VM145 from the exact Windows 10
3.2.192 source with exit 67. The MSI registration, selector and four
identity files were restored; Gateway accepted WSS and both exact native
events in order after reconnect. The delivery task retired without
another MSI operation. On a separate VM145 run, a hard stop interrupted
the native removal transaction for the same 3.2.192 source. The original
MSI fence survived; the startup recovery task created a replace-foundation
plan and reached accepted on 3.2.227 with exit 0. Gateway acknowledged
one install event, all four identity files matched, and chkdsk returned 0.
A clean reboot confirmed fresh same-device WSS and the same event ID.
The power-cut and accepted snapshots are available alongside the 226
failure and 227 rollback. A separate offline same-version 3.2.227 repair
restored the missing Core service with exit 10 and preserved its MSI
registration and four identity files. The native repair event survived an
offline reboot, reached Gateway once on reconnect and retired the retry
task without another MSI operation. A separate offline uninstall and
reinstall of the same signed 3.2.227 on VM145 returned 0 and 10. The exact
removed and installed events survived an offline reboot and Gateway
acknowledged them in order. Support 1.1.9 registered for the first time
with access disabled and the four identity files matched. A standard
console sign-in on VM145 launched the exact 3.2.227 UserSensor and Tray
after reboot. Gateway acknowledged the device-scoped Activity policy and
accepted fresh UserSensor and content-free ACTIVE observations. The
temporary account and profile were removed. A separate VM145 run verified
UUID-pinned independent Support 1.1.9 SSH with Core and updater stopped
and Setup Observer disabled. Console accepted operator attestation.
The lease and broker port were closed, test credentials removed and
baseline service states restored. Clean Windows 10 build 19045 Setup 3.2.227
on VM146 lacked the Authenticode publisher root. Its late trust check returned
21 and left the msi-starting fence. The source fix checks trust before writing
the cache or fence. The updated wrapper returned 64 on clean VM147 without
creating either. Trusted, unchanged signed 3.2.227 then installed with exit 0
and one completed AUTO enrollment on VM147. Reboot preserved its identity and
fresh WSS on the same card. The temporary campaign and credential were revoked,
the lab Gateway restored and VM147 removed. VM146 retains the original fence.
Signed Setup 3.2.228 rejected the untrusted image on a fresh Windows 10 VM
with exit 21 before creating a cache, transaction, services or agent data.
After provisioning the approved publisher root, the same EXE installed with
exit 0 and one completed AUTO enrollment. Reboot preserved the four identity
files and fresh WSS on the same card. The candidate remains limited to the lab.
The temporary campaign and credential were revoked, the lab Gateway restored
and VM147 removed. The original signed 3.2.227 recovered the existing VM146
transaction after publisher trust was established. It returned 0 with a
protected completion at sequence 6, one enrollment and fresh WSS after reboot
with four matching identity files. The recovery omitted the installed fact.
The source fix queues one fact under the original transaction and starts
delivery after authenticated standalone recovery. Both evidence snapshots
are retained with VM146 stopped and isolated and its credential revoked.
Signed 3.2.229 includes the lifecycle fix and passed 373 source tests.
The isolated VM147 native power cut retained its original reconciling fence
with the expected MSI ProductCode absent and seven zero-filled payload files.
Both retained MSI copies match the signed artifact. Exact Setup returned 20
(PROVENANCE_CONFLICT) before enrollment and preserved the original transaction.
The isolated campaign was revoked and the lab Gateway restored. VM147 stays
stopped and isolated with the power-cut and held snapshots. All seven damaged
files on VM147 have resident NTFS data streams. The intact current selector
also has a resident stream. A clean VM149 clone recovered the exact signed
3.2.229 transaction from msi-starting after power loss. It returned 0,
completed one enrollment and retained one installed event and ACK under the
original transaction. Reboot preserved WSS and the four identity files.
The scoped campaign and credential were revoked, the lab Gateway restored and
VM149 removed. A separate clean clone with QEMU directsync reproduced the
same seven zero-filled files and absent MSI registration after a late
power cut. Exact Setup kept the original reconciling transaction and
returned 20 (PROVENANCE_CONFLICT). The regression preserves an exact-size
zeroed file, completed plan and selector on fail-closed inspection.
Signed Setup 3.2.230 flushes the verified installation files, directories and
native registry hives before publishing completion. On a clean VM149 clone
with directsync, a hard cut at the same reconciling boundary preserved all
121 files and MSI registration. The exact retry returned MSI_COST_UNAVAILABLE
with its original fence unchanged. The registered Windows Installer LocalPackage
differs from the exact signed media and MsiOpenDatabaseW returns 110. The
protected signed media matches and opens with return 0. VM149 is stopped and
isolated with the native-cache failure snapshot. The native MSI cache durability,
safe recovery for both VM147 and VM149, other source profiles and production
qualification remain open.
Setup 3.2.231 added persistence of the verified registered LocalPackage and
uses database semantics during recovery costing. The signed clean VM150 run
reported Win32 32 while opening its cache for flush. It stopped before the
planned cut, preserved the prepared plan, and the cache still opened with
return 0. A regression with the actual reconcile read scope reproduced the
shared-handle failure. The source fix releases that cache read pin before
flushing the same verified file. VM150 and lab ISO were removed after evidence
capture. Signed Setup 3.2.232 preserved the registered LocalPackage, MSI
registration and all 121 payload files after a late cut on VM151. The same
signed EXE completed the original transaction offline with native0 at sequence
10 and one installed fact awaiting enrollment. The wrapper returned
PROVISIONING_UNEXPECTED (41) with no adapter. VM151 is stopped and isolated for
the original fact's enrollment, WSS and delivery verification. The new
disruption test qualifies this local boundary only. Recovery of the previously
damaged VM147 and VM149 state and other release-matrix profiles remains open.
The isolated online repeat for 3.2.232 completed one AUTO enrollment, accepted
WSS and five context profiles, and reconnected on the same device after reboot
with four unchanged identity files. The original native fact stayed unbound
because the wrapper ran another MSI transaction and acknowledged only that
new fact. The source fix resumes enrollment from matching signed MSI, protected
completion and current ownership proof and binds the original fact under the
provisioner lock. VM151 was reverted to the offline snapshot after the campaign
and credential were revoked and the original Gateway was restored. Signed
3.2.233 exposed a missing installer-state parent on a truly clean VM and
stopped before MSI. The regression now covers first install without creating
state and retains proof checks when it exists. Temporary VM152 and the isolated
catalog were removed.
VM151, its diagnostic snapshot, disk and dedicated ISO were removed after
the two 3.2.232 receipts were verified. Signed Setup 3.2.234 on a clean
Windows 10 19045 clone from VM147 preserved MSI registration, the exact
registered cache and all 121 files after a late power cut. The exact EXE
completed the original native transaction offline at sequence 10. The online
repeat returned 0 with one completed AUTO enrollment and one acknowledged
installed event for that original transaction. The protected completion stayed
byte-identical and remained the only native completion. Reboot preserved four
private files and opened a new WSS session on the same card. The scoped campaign
and credential were revoked, the original lab services restored, the scratch
catalog and VM152 with its disk and ISO removed. Recovery of the previously
damaged VM147 and VM149 states and qualification of other OS/source profiles
remain open.
Read-only tests on a temporary clone of VM149 isolated the failure to the
registered LocalPackage. The exact protected MSI opened successfully and
returned 0 for CostInitialize, FileCost and CostFinalize. The registered cache
returned 110 from MsiOpenDatabase and the installed product returned 1620
from MsiOpenProduct despite reporting state 5. The fence, plan and cache
hashes stayed unchanged. The temporary clone and disk were removed.
For VM147, read-only extraction from exact signed Setup 3.2.229 media
recovered the expected bytes for all seven zero-filled files. Six match the
installed-runtime manifest and the seventh matches the MSI marker and Core
component identity. A disposable offline clone of the held state was
repaired with only those seven exact file contents. The 121-file inventory
matched and the file ACLs, protected fence, plan and selector did not change.
The exact Setup 3.2.229 then recovered its original native transaction,
verified after reboot at sequence 10 with registered ProductState 5 and
an exact, readable LocalPackage. It left one installed event awaiting
enrollment after the offline wrapper returned 41. The clone was removed.
The first online clone reached native completion but Windows selected the
inherited .143 source address. The exact .152 campaign denied enrollment
without consumption. A fresh clone kept only .152 on the isolated adapter.
The first exact signed EXE invocation after the same seven-file repair
returned 0, completed one AUTO request and received one ACK for the
original installed event. Reboot opened a fresh WSS session on the same
card with four identical private files. Both clones and the temporary
catalog were removed, the scoped credential and campaign were revoked
and the original lab services restored.
On an offline clone of the VM149 hold, all 14,804 differing 4 KiB
LocalPackage blocks were entirely zero. The other bytes matched the
exact signed 3.2.230 MSI. Restoring only those blocks in the clone
preserved the file ID, ACL, registered path, fence, plan and selector.
The cache matched the signed MSI and both MsiOpenDatabase and
MsiOpenProduct returned 0. The first Setup invocation with the scoped
Gateway accessible completed the original native transaction at sequence
10 and received an ACK for its only installed event. Normal reboot
preserved the cache, all 121 runtime files and four private files. The
agent opened a new WSS session on the same card. The clone, scratch
database and temporary artifacts were removed. The scoped credential and
campaign were revoked and the original lab services restored. Unattended
recovery from the previously damaged 3.2.229 and 3.2.230 states remains open.
The same signed Setup 3.2.234 on a clean Server 2012 R2 build 9600
clone from VM144 retained the registered MSI cache and all 121 files
after the same late cut. ISA QGA timeouts required orderly restarts and
read-only diagnostic media to inspect the original transaction. The exact
offline retry completed it natively at sequence 10. Online resume
acknowledged that single original installed event and left the native
receipt unchanged. The lab clock was five hours ahead. Correcting the
guest clock and restarting Core during the same enrollment let the
baseline complete and the wrapper return 0. Five context profiles and a
new WSS on the same card after normal reboot were verified, along with
four unchanged private files. The test campaign and credential were
revoked and the temporary VM, ISOs and database removed. A fresh clone
with Proxmox localtime=0 and guest timezone UTC passed the same late cut
and offline recovery. Measured clock offsets stayed below one second.
The online resume returned 0 in 30.55 seconds without time correction
or a manual Core restart, with one unchanged native receipt, one AUTO
completion, one ACK for the original event and five context profiles.
Normal reboot preserved all four private files, the MSI cache and WSS
on the same card. The temporary campaign, credential, VM and database
were cleaned up. Upgrade, same-version repair, rollback, offline
remove/reinstall, UserSensor and Support remain open for this exact release.
The direct Server 2012 R2 3.2.218 to 3.2.234 trial used VM154's
accepted 218 snapshot and a matching isolated copy of its sequence-5
Gateway state. The old service had stopped at boot with SCM 1066 and
was started once after the clone's lab network was configured. Fresh
3.2.218 WSS identified the original card before Setup. The upgrade
returned 21 with target MSI and selector 3.2.234, private4 unchanged
and no new server event. The compound plan stayed retired and its
original child remained reconciling at sequence 6. Win32 32 came from
the installed-file flush inside the combined finalization while the
same Foundation file was pinned against writes. Source fix
`38f3ff61592e2957dadaa7a5b5db6341a017c7e2` binds the flush handle to the verified
file identity and change time after closing that file's read pin.
Real Windows regressions cover successful flushing and rejection of a
replaced file, and related checks passed (267 runtime and 175 Setup /
packaging tests). The signed 3.2.235 repeat used a full clone on VM153
with networking configured before boot. Core 3.2.218 started
automatically and connected on the original card. The upgrade stopped
in compound finalization with exit 21 after registering the target MSI.
The diagnostic reached the Windows Installer LocalPackage cache flush
and recorded Win32 32 there. The four identity files matched and the
Gateway retained the original sequence-5 event with no target WSS.
VM153 is stopped without a network adapter and retains the latest failure.
The original lab Gateway and worker are running and the scratch database
was removed. VM146 and VM152 were removed with their disks and snapshots
after verifying retention of the test reports. VM154 remains the source
for the next 3.2.218 repeat.
The registered MSI cache pin is now released before the durability flush
while retaining the verified file identity and change time. A Windows
regression reproduces the sharing violation in compound finalization
and rejects file replacement between verification and flush. The signed
3.2.236 lab EXE/MSI at source `57a86985b8be74e1c4ea733f870515375e5991a0`
have verified timestamps and hashes. On a full clone of the accepted 218
snapshot, Setup 3.2.236 returned 0 (258.92 seconds), the compound marker
and child receipt completed, and the staged update reached accepted.
After reboot, LocalPackage matched the signed MSI, all four identity
files matched, and the original card received fresh 3.2.236 WSS with
one acknowledged installed event at sequence 6. The offline VM152
snapshot and matching lab DB are retained for same-version repair and
rollback. The superseded 235 failure VM153 and its temporary media were
removed after checking its report hash. UserSensor, independent Support
and the other matrix gates for 3.2.236 remain open.
The same signed 3.2.236 Setup repaired the missing EndpointAgent SCM
entry on an offline full VM153 clone of the accepted VM152 snapshot.
Setup returned 10 with Core running and Auto, preserved the installed
MSI and four identity files, and queued one installed event at sequence
7. The SYSTEM delivery task returned 75 after the offline reboot. The
original event received one matching ACK automatically after link
restore, the task retired, and the same device card received fresh WSS
with no new MSI event after link restore. VM153 and the repair database
were removed after verifying the receipt. The original lab services and
VM152/sequence-6 database were retained.
For the offline rollback test a fresh VM153 clone started at the
accepted 3.2.218 VM154 snapshot and sequence 5. After the link was
disabled, signed Setup 3.2.236 reached trial and then returned 67
(444.72 seconds). Source Core, MSI and all four identity files were
restored. The offline reboot preserved both native events and the
SYSTEM task retried with exit 75. After link restore, Gateway accepted
sequence 6 for 3.2.236 followed by sequence 7 for 3.2.218. Local ACKs
matched, the task retired and the original card accepted fresh 3.2.218
WSS with no new MSI record. VM153, its probe ISO and scratch database
were removed, baseline Gateway and worker were restored.
On a fresh full VM153 clone of the accepted 3.2.236 snapshot, offline
uninstall returned 0 with Support cleanup complete, and the same
signed Setup repaired the retained installation with exit 10. An
offline reboot preserved removed sequence 7, installed sequence 8 and
all four identity files. After link restore the stock SYSTEM task
delivered both events once without another MSI operation and retired.
Core 3.2.236 connected on the original card. Support 1.1.9 re-registered
as generation 2 on the same credential with access disabled. VM153
and its matching accepted database are the offline baseline for
independent SSH. A disposable VM151 clone verified UserSensor after a
real console type-2 login of a temporary standard user. Explorer,
Tray and UserSensor started in the same session and the sensor binary
matched the signed-build payload. Gateway accepted a fresh sensor
sample and an ACTIVE interval under the device-only privacy policy,
with application, category and browser fields empty. The device card,
four identity files and sequence-8 history matched the source.
The temporary user, profile, VM151 and isolated database were removed.
A separate VM151 clone verified Support 1.1.9 through its loopback
broker port under a ten-minute policy. Strict SSH with the device
host key returned the temporary local administrator while Core and
updater were stopped and the Setup Observer was disabled. The API
recorded an operator attestation. Disabling the policy closed the
broker port. The observer and service states were restored, fresh WSS
returned after reboot, and temporary account, keys, VM and database
were removed. The baseline lab exporter was restarted after its
configured two-hour timeout. The temporary offline reinstall baseline VM153
was removed after independent SSH passed. A full VM151 clone of the signed
3.2.218 source then lost power on raw local-lvm/directsync during old-MSI
uninstall, at msi-executing sequence 2 with matching prepared plans.
Windows logged the unexpected shutdown and the stock recovery task resumed
the same staged operation. The accepted result was SERVICE/UPDATED/0.
Exactly one installed event at sequence 6 was acknowledged on the original
card. The next orderly reboot preserved the four identity files, the exact
signed registered MSI cache, the event and a fresh WSS connection. The
temporary VM151 and isolated database were removed after verification.
A fresh VM151 clone of the clean Windows Server 2012 R2 image ran signed
Setup 3.2.236 once under a one-use AUTO campaign on a new isolated database.
Setup returned 0 in 76.203 seconds. Gateway completed one enrollment,
accepted five context profiles, and acknowledged one installed event at
sequence 1. An orderly reboot preserved the card, the credential, all
four identity files and the exact LocalPackage hash, and opened a new WSS
session. The campaign, clone and scratch database were cleaned up.
The exact production Windows Setup 3.2.205 ran on a disposable Windows 10
19045 VM against the production provider restored from PBS, with an isolated
database and a one-use registration. Its stock Setup Client 1.0.11 fetched
and applied signed 3.2.237 after a single-device Console assignment. Native
exit was 0, soak was 181.306 s, and all four identity files and the registered
MSI hash survived reboot. Core and Foundation 3.2.237 appeared on a new WSS
session on the same device, and Setup Client 1.0.13 reported ready. The
temporary Windows VM, provider VM, disks, test media and management network
were removed. This unattended test had no UserSensor session. Independent
Support for the pair, other interruption boundaries and production
qualification remain open.
The server now recognizes 1.0.13 for explicit canaries when it reports
both source versions in a fresh ready hello. SQLite tests reproduced the
rejection before the change and passed afterward for a 3.2.237 source.
Fleet admission and qualification still require the separately qualified
observer set. With the fixed server on isolated PostgreSQL, the exact
signed observer 1.0.13 installed with Setup 3.2.236 fetched and applied
3.2.237 from an explicit Console assignment. Native exit was 0 and soak
was 182.088 s with one active UserSensor. After reboot the same card
accepted new WSS, genuine console UserSensor and fresh observer 1.0.13
reports. The four identity files and registered MSI matched. The fleet
qualification API returned 409 and persisted no qualification or policy.
The temporary Windows VM, database, services and media were removed.
The server now includes 1.0.13 in the qualified observer versions while
requiring both source versions in its hello. A PostgreSQL 15.20 replay
used the original canary timestamps and persisted evidence: the prior
code rejected the observer, and the new code qualified exact Setup
3.2.237 from Foundation 3.2.236. A stale UserSensor was still rejected
and the database contained no fleet policy. Temporary databases and ISO
were removed. Independent Support and production qualification for this
pair remain open.
STAB-18: [read-only production review](docs/verification/2026-11-14-stability-fleet-intents.md)
identified five aged, unrequested Core intents in one Linux bulk rollout.
The rollout detail shows assignment age and ownership, connection freshness,
retirement and installation removal alongside the update lifecycle. The
device overview dates WSS Core, observer-reported Foundation, Setup Observer,
corroborated UserSensor and Support telemetry separately. It distinguishes
Support telemetry from the operator's SSH attestation. Paused bulk Core
rollouts with entirely unrequested assignments can be cancelled through an
audited, replayable action. On 16 November the five production intents were
still unrequested in an active rollout after 20 days. The installed provider
lacks the bulk cancellation routes. On the lab PostgreSQL, an operator
inspected, paused and cancelled a five-target rollout matching that state
through the canonical API. An exact retry returned the same receipt.
The health profile now carries the Windows updater
service state and separate ALT service and path states. Console dates them from
the agent's health sample. On installed ALT VM142, three real health samples
showed the path watcher active, stopped and active again while the updater
service stayed inactive. The Console API matched the native states and
collection times, with all samples delivered on the same WSS session.
On VM143, signed Setup 3.2.237 upgraded 3.2.226 on Windows 10 and
reported the stopped updater as fresh inactive via a native SCM status
query. The agent service SID received SERVICE_QUERY_STATUS. The original
identity, native lifecycle ACK and WSS on the same device were verified.
The [native receipt](docs/verification/2026-11-14-stability-fleet-intents.md#нативная-приёмка-windows-setup-32237-на-vm143)
covers this exact transition. A later read-only production snapshot still
showed the same five unrequested and offline Linux assignments. A separate
operator-assigned Windows 3.2.192-to-3.2.205 job reported native switching
and is held in recovery_required. Its observer remains reachable, while
the last Core WSS is stale. The provider has no accepted native exit proof
or independent Support registration on that card. Native ownership is
still held. Console now displays Linux as a platform and only labels an
assigned row as waiting for its first request when its timeline and report
have no later evidence. Chromium verified both cases at desktop and mobile
widths. Production cancellation and the native hold diagnosis remain open.
STAB-19: The [Gateway capacity report](docs/verification/2026-11-14-stab19-gateway-capacity.md)
covers 32-, 96- and 192-device rehearsals. At 32 devices, both
acknowledgements met the proposed latency targets in the Linux TLS
test. At 96, scheduled WSS dispatch and the idle queue probe reduced
periodic result ACK. With deadlines persisted in the initial INSERT, the
worker eliminated 480 UPDATE statements per cycle. Periodic delivery
from requested_at still took 5.74–6.44 s at p95 and replacement delivery
took 6.23–6.59 s. Combining the active and historical collection reads
saved another 480 SQL round trips per worker cycle. At 96 devices,
both the baseline and the changed scheduler exposed a PostgreSQL deadlock
between command and collection row locks during WSS replacement.
Gateway delivery, start acknowledgements and result recording now lock the
same device row before command/collection rows. Both PostgreSQL concurrency
cases reproduced the deadlock on the baseline and passed with the change.
Three TLS rehearsals at 96 devices passed with zero PostgreSQL deadlocks
during load. Periodic delivery still took 5.80–6.13 s at p95. Start and
result acknowledgements met one second in the periodic wave and exceeded
it on reconnect. Gateway now skips the replaced socket's close query when
the committed replacement transaction confirms closure of that session.
At 96 devices this eliminated 96 redundant closes in each fixed run.
Reconnect result ACK improved to 1.65–1.89 s at p95 in that comparison.
The worker now commits periodic requests in 16-device transactions and
resumes from the last confirmed page after a failed commit. In paired
96-device runs, 32–39 commands reached clients before the final commit.
Periodic delivery p95 was 4.82–5.47 s and only one run met the 5 s target.
Reconnect result ACK was 2.15–2.27 s at p95 in the paged-worker runs.
A separate 96-device TLS comparison with three fresh supported profiles
confirmed 232–234 fewer SELECTs in the reconnect wave after combining the
context refresh checks. Delivery and refresh p95 changed in both
directions across pairs. Gateway now reads the next frame immediately
after granting command start. On 96-device reconnects, the preceding
empty queue check had delayed entry into the result handler by
1.24–1.33 s at p95. With the change the delay was 9.1–9.6 ms and
total result ACK was 1.41–1.59 s. At 192 devices result ACK went from
4.19 to 3.19 s at p95 in single runs. Pool acquisition accounts for
most of the observed handler tail. At the same 15-connection limit,
keeping all 15 connections in the test pool eliminated physical
reopens during reconnect. Result ACK took 1.42–1.51 s at p95 and the
paired effects on ACK differed. The next comparison should
isolate the contest for pool slots between reconnect work and feedback.
The shared device bearer verifier now reads credential and active
device in one statement, including ambiguity checks for retired
devices. The 96-client TLS comparison counted 96 fewer authentication
SELECTs per wave, with reconnect result ACK at 1.43–1.46 s p95.
Delivery and reconnect targets and production-scale qualification
remain open.
A four-run paired TLS trial on 96 clients bounded the opening WSS
database stages at eight over the same 5+10 pool. Reconnect start and
result ACK both met 1 s at p95 with the lab limit. Delivery exceeded
5 s in both configurations, and effects on hello and full wave time
changed direction across pairs. The limit remains a lab parameter.
The 731.585 s mixed trial used 96 clients with staggered heartbeat
and Power, three scheduler waves, and a different 32-client reconnect
group per wave. The health queue returned to zero in 2.204–3.406 s
from reconnect start. For the 64 continuously connected clients,
delivery p95 was 3.46–4.03 s. Each wave acknowledged command start and
results within 1 s p95 in both groups. The database contained 288
health snapshots and 755 confirmed Power events, with 64 result
replays and no extra snapshots. The worker also queued 96 session
collections for clients without that capability. Gateway now persists
the accepted periodic profiles for use by the worker and offline
devices. An authenticated HTTP command poll selects the legacy
fallback, as do devices that have yet to negotiate. Revision
`0054_periodic_context_profiles` stores this additive device state.
The corrected 96-client trial created 96 health requests and returned
the full scheduled queue to zero in 2.371 s after reconnect began.
Four TLS runs with mixed health and session profiles each completed
128 eligible commands on 96 clients, with 42 queued during reconnect.
The full queue recovered in 3.083–3.521 s. Two runs used a separate
pgbench database in the same cluster at 47.42–47.75 transactions/s.
Continuously connected delivery p95 was 4.22–4.40 s in control and
4.08–5.64 s under background SQL. Both groups met the 1 s p95 targets
for command start and result ACK. A second four-run comparison
measured the delay by command ordinal. The five slowest online
deliveries in every run were second commands on the same socket.
Gateway now counts successful scan and delivery work toward its
one-second interval and waits a full second after a scan error.
With the adjusted cadence, second-command p95 was 3.90–4.21 s
and queue recovery improved by about 0.3 s in both pairs. First-command
p95 increased slightly. Helpdesk application load and repeatable
delivery under representative shared-host load remain open.
The command delivery transaction now links a locked Context collection
directly to the newly inserted command. In two paired 96-client PostgreSQL
runs the change removed 384 SELECTs per 192 deliveries. Each run confirmed
the same results, snapshots and active sessions. Result ACK p95 remained
above one second in this loopback scenario.
Linux TLS pairs on the same candidate removed 256 SELECTs per 128
successful deliveries with about 47–48 pgbench transactions per second.
The two candidate runs recovered queued work in 2.958 and 3.143 seconds.
Start and result ACK p95 stayed below one second. Online delivery moved
in opposite directions across pairs. An evening production counter sample
measured 8.90–9.30 transactions per second for the active Helpdesk
database. A representative Helpdesk application workload remains open.

[Gateway recovery drills](docs/verification/2026-11-14-stab19-gateway-recovery.md)
verified replay after API restart, database interruption with the API
running, worker restart and forced process or PostgreSQL exit. A separate
local restore exercised API and worker from the recovered source,
database and synthetic signed release.
On Ubuntu 24.04.3, backend processes started from archive `fcad03de9ce5`
behind a loopback Nginx TLS listener. The actual agent lifecycle with a
synthetic collector retried after five seconds, opened a new WSS session
and drained SQLite in 5.151–5.221 seconds from each of three faults.
Each run invoked the collector once and retained one result and one snapshot.
The archived worker created a request in 62.119 seconds after a forced
restart with the default one-minute schedule and no duplicate request.

The [production PBS receipt](docs/verification/2026-11-14-stab19-backup-restore.md#восстановление-production-vm115-из-pbs)
records an external VM115 backup and a network-isolated restore to VM163.
HTTPS, the worker's database connection, deployed files, the Windows
artifact and the TLS certificate/key pair were verified in 434.14 s from
the restore request. VM163 and its disk were removed. The daily VM115 job
is enabled at 04:00 Asia/Yekaterinburg. On 16 November at 04:37 UTC its
configuration and the two existing VM115 PBS archives were independently
rechecked. The first scheduler-created archive was also restored without
network hardware. HTTPS, the worker connection, the deployed manifest,
Setup 3.2.205 and TLS passed in 454.08 s, including a restart to correct
the order of the guest-only Nginx loopback binding. Five witnessed rows
before the snapshot matched and five later rows were absent. The latest
matched row was created 31.26 s before the snapshot. The clone and its
disk were removed. Achieved daily RPO still requires regular scheduled
history and transaction evidence. Restored Worktime advertises the login
option and denies anonymous access. External release-signing inputs and
restored SSO sign-in remain open.

## SSO + WorkTime staged implementation (2026-10-27)

Latest checkpoint (supersedes initial progress below): auth/WorkTime/DLP/UI and
typed companion implemented, independently reviewed and corrected. PostgreSQL76
passed; final UI68 unit/14 browser; focused native ABI/companion/queue32 passed.
Initial broad backend2863 passed/38 failed/338 skipped:35 tzdata environment
mismatches fixed with pinned2026.3,2 obsolete head assertions now0042,1 optional
bridge startup failure fixed without weakening WSS fixtures. Focused121 passed,
8 skipped; full rerun in progress. Final review found no P0/P1; explanation queue
pagination and shared Helpdesk-service budget P2 corrections have regression
coverage. Keycloak26.8.1 now imported/bootstrap active with ownPG5544, LDAPS
hostname/CA verification and HTTPS discovery200, clients disabled pending pilot.
ALT210 accessible as osn-admin, current3.2.127; Windows currentCore149. No157
artifact/build/install or live application SSO acceptance claimed. Freeze clean
source, qualify/sign157 Windows and native ALT packages, reviewed independent
app deployment and bounded synthetic-AD pilot remain required.

Goal: implement user-supplied SSO + Helpdesk + Endpoint + DLP + WorkTime spec,
with independent subagent reviews and focused feature tests at each A–F gate.
Source base78d24e9 main, branch codex/sso-worktime-20261027. Preserve original
dirty checkout; user explicitly authorizes Endpoint changes/deploy, separate
agent update and Linux/local-domain-PC validation. No fleet rollout, mass AD or
GPO change, forced migration or organization-wide personnel monitoring.
Shared design/plan live in Helpdesk docs/superpowers/{specs,plans}/2026-10-27-
sso-worktime*. Confirmed identity authority is Helpdesk RegistryPerson; exact
OIDC issuer/sub + ADGUID, no automatic username/email merging. Separate realms,
opaque server sessions, MFA and scoped local grants. Device/WSS credentials
unchanged; personnel events independent of Activity and its shorter retention.
Current State: A auth/identity worker, C WorkTime worker, D UI worker and
Keycloak infra worker active. Root adds separate DLP routes/grants.
Verification: DLP technical-admin implicit read regression RED(200) then
GREEN403explicit dlp:read,1testpassed. Initial architecture reviews completed.
Next: review/test each deliverable, real DB migration/concurrency, integrate
server/frontend, typed companion delivery then signed build and installed pilot.
Handoff: AD-MAIN has no Keycloak/DNS and unusable LDAPS TLS/no machine cert;
user authorizes separate .19 deployment. No remote mutation yet; no completed
stage or installed SSO/WorkTime acceptance claimed.

## Capability Platform v2 (2026-09-24)

The source baseline is `31b3bdbbdcb07d2bb23beb9a6412e1ef2250fefd`
on `codex/endpoint-capability-platform-v2`; the installed Agent baseline is
`3.2.65`, and Alembic starts at `0027_context_observed_backfill`. The design
and implementation checklist are in
`docs/architecture/endpoint-capability-platform-v2.md` and
`docs/superpowers/plans/2026-09-24-endpoint-capability-platform-v2.md`.
The new migration is `0028_capability_platform_v2`. Fifteen new read-only
capabilities are implemented on the existing Module/Gateway/Operation route.
The Agent release version is `3.2.67`: the production `update_builds` registry
already contains `3.2.66`. New server feature groups default to disabled.
The implementation commit is `5bfc2e3b47cb5e17506b4f46f6e9c572807f470a`.
Production Lab exposed a same-WSS-session replay of an unacknowledged command;
the follow-up fix is `1dc3ad3acfc56ebcee96c598b6a0e746d2b29bdc`.
The final full Python gate passed `1901 passed, 41 skipped` after the fix.
Focused Windows packaging checks passed (`87 passed, 1 skipped`).
`python -m tools.contracts.generate_contract_artifacts --check`,
`python -m compileall -q endpoint_server endpoint_contracts pc_agent`,
Console `npm run test` (`21 passed`), `npm run test:e2e` (`3 passed`, including
TypeScript typecheck and production Vite build) passed after the gateway fix.
`git diff --check` was clean. Packaged canary evidence is recorded below.

Windows local primitive smoke checks succeeded for resource snapshot, process
find, printer list, print service status, queue summary, software find, system
free space and a bounded Event Log query. The dedicated ALT test host
`test-agent-lin@192.168.101.162` timed out on SSH again at the live gate;
ALT live acceptance remains unverified. Automated ALT tests passed in the
full Python gate.

The immutable Windows Agent 3.2.67 update archive is
`C:\Temp\endpoint-agent-3.2.67-5bfc2e3b47cb-update.zip` (27,723,718 bytes,
SHA-256 `135bbb2add4da1f5cbbcd989b185396c0f232dd08b554e4529a35d6c97b8e258`).
Its inner runtime manifest names source revision
`5bfc2e3b47cb5e17506b4f46f6e9c572807f470a`; all 2,539 member hashes
and ZIP CRC passed. The packaged `pc_agent.exe --print-version` matched.
Installed Windows preflight and `verify_installed_windows_agent` returned
`READY`; the selected runtime manifest matched version 3.2.67 and the source
revision. The previous installed Agent was 3.2.65. The registered Update build
is `5adf0dfc-612a-4f57-a2af-32db13ebd85c`; the first local canary rollout
`f2402ffa-59ba-41da-8d41-28015c650b9f` applied to device
`c450fc70-63e6-4c2b-baf6-7de79820d63f` (`ADMIN-2`).

The initial server backup is
`/var/backups/endpoint-platform/pre-capability-v2-20260924T160518Z.dump`
(16,315,112 bytes; SHA-256
`806da935a344520175cd58905ac676b00ca228c488b430617ae36ac9fac44b37`);
`pg_restore -l` passed. Server archive `5bfc2e3b47cb` had SHA-256
`b928876bfe3460be140d606a383e1942a4f84c1913e9f28e15db2663637b3a92`.
Production migrated from 0027 to `0028_capability_platform_v2`. Six new
read-only feature flags were enabled after settings validation; older Agents
remain gated by minimum version 3.2.67. The gateway replay fix has its own
verified backup
`/var/backups/endpoint-platform/pre-gateway-fix-20260924T162842Z.dump`
(SHA-256 `dcef8f05c3ad7a3a297cd4fbc81a11e38d178eaa19b8db8fb3975f8c8e3c6cc7`)
and release archive SHA-256
`d587d0c30c049048aa3787d9bb1de40bd535704d31d581bd48495453a9c4c0b5`.
The active release is `/opt/endpoint-platform/releases/endpoint-platform-1dc3ad3acfc5`;
its migration unit succeeded, API/worker/Nginx/PostgreSQL are active, strict
hostname/CA HTTPS `/healthz` returned 200, and WSS sessions reconnected.

The existing published `inventory.local.adapters@1.0.0` succeeded on Windows
Agent 3.2.67 (operation `ab4ab8bb-0f01-4248-8329-8029f26c7299`). Four
Windows-only acceptance recipes were created, statically validated, run in
Lab, accepted and published: `print.health.check@1.0.0` (printer status, queue
summary, print service status; Lab `d61b1367-785c-47ad-b481-ecb0f4407254`),
`process.presence.check@1.0.0` (process find; Lab
`4410b194-0c5f-4d19-897a-bb5766397583`),
`software.installation.check@1.0.0` (software find; Lab
`9cc70631-e47f-4cb0-828a-bca969dd9935`) and
`system.quick.check@1.0.0` (resource snapshot, free space; Lab
`46aa3957-9a43-487b-8e9e-9496a19115ae`). Every Lab operation and step
succeeded and yielded an audited passed Windows evidence record. Published
`system.quick.check` run `be469846-86e7-4d1a-9993-807a9ed82407` succeeded;
its safe Evidence SHA-256 is
`e826e4c91810d8c28296c5786c4a7a7013b3dc7435b48e413f8600e7b50b28a8`.
Console showed a 24-hour TTL; the result was then pinned with an acceptance
reason and the ordinary expiry removed. Context remained fresh, and Agent
service remained running after the repeated Lab and published operations.

The local rollback rollout `c35b0c39-654e-4c0d-9e74-242ee8034031` applied
registered Agent 3.2.65 (archive SHA-256
`73b7a150655e5c1b0bc784eb548115ba013d1e8e082debb058a9140f4389dee7`).
The selector named source revision
`2528aeb809d882eb0b9363ecc8c230b552e7cea1`, both services returned to
normal state, WSS was online, and Console removed the 3.2.67 capabilities.
Reapplication rollout `a1eec0de-5f70-4109-b408-eedcd52ce128` applied
Agent 3.2.67 again at 16:39:58 UTC. The selector again named the expected
source revision, Agent ran and Updater stopped; installed preflight plus
`verify_installed_windows_agent` returned `READY` after reapplication. A
one-device small IT canary rollout `8f16b3c1-8c13-4bf5-a4ba-bf73ec80e72a`
targets `9169e45c-9566-4277-b58e-bf76287c2b59` (Windows clean canary AUTO;
Agent 3.2.63 before update). The existing published adapter module succeeded
before the update (`c38de880-e9ab-4674-a41c-233ca316633c`), while the four
v2 recipes were correctly unavailable with a 3.2.67 minimum-version reason.
The canary applied at 16:45:04 UTC. Console then showed Agent 3.2.67 online,
the new effective capabilities and fresh Context. The existing adapter module
again succeeded (`ffd574af-fc8a-4e42-99a8-ce1ba18fd901`), as did published
`system.quick.check` (`dc786b81-5265-4c5e-8822-62dd1c0627d1`).
Rollback rollout `8728bce9-fcca-431f-9d20-559db8e760fe` targets the same
device and the verified registered 3.2.63 archive (SHA-256
`215b218812b0bb1d975e4639c60b20bec8a4e9369778953f3e5c4035f28ae315`).
It failed at 16:50:50 UTC with `launcher_apply_failed`; the canary stayed
online on 3.2.67. The local EndpointAgentUpdater Event ID 3 gave the exact
cause: `target version collision with different bytes`. Its original 3.2.63
runtime has different bytes from the registered 3.2.63 package, so the updater
correctly refused to overwrite that version directory. No bypass was applied.
The separate rollback rollout `775fb402-d41f-4a69-9e05-b43693169a33`
targets verified build 3.2.65, absent from this canary's version directory.
It applied at 16:56:20 UTC; Windows Agent ran on 3.2.65 with source revision
`2528aeb809d882eb0b9363ecc8c230b552e7cea1`, Updater stopped, WSS was
online and Console removed the 3.2.67 capabilities. Reapplication rollout
`d02c2f41-e742-4d8c-97e2-0f7ae0036e56` applied 3.2.67 at 17:01:59 UTC;
the selector, services, WSS and effective capabilities returned to the v2
state. Before the pilot, a third verified custom-format DB backup was saved at
`/var/backups/endpoint-platform/pre-capability-v2-pilot-20260924T165442Z.dump`
(15,972,485 bytes, SHA-256
`752119196151d7ade2812b22ab05aad3d34e4bee546047b2cef15759932771a4`);
`pg_restore -l` passed and the file is private to postgres. Pilot rollout
`e58138e7-2ef3-4607-86a5-6a4fcc54ec97` has one explicit Windows target,
`ff6fd7b0-ad25-419f-83ad-cf5e683ed1bc` (`MUNSLU-S2`, Agent 3.2.63
before update). Another online candidate (`A2-IAO`, Agent 3.2.46) is held out
because its exact previous rollback artifact is not registered. Before the
update, published `inventory.local.adapters` succeeded
(`d02ffec5-e12d-47d8-ba21-bd397ec9ed19`) and v2 recipes showed a minimum
Agent version incompatibility. The pilot applied at 17:04:45 UTC. Console
showed Agent 3.2.67 online with v2 capabilities and fresh Context; the
existing adapter module succeeded again
(`82f3138d-131c-4714-9d53-0af792632612`) and published
`system.quick.check` succeeded (`cbb8df85-b386-4eab-ad02-e282d048e1eb`).
Pilot rollback rollout `ba27eb4c-9a8d-4b96-a46a-359f048e7db0` targets the
verified 3.2.65 build. It applied at 17:10:04 UTC; Console showed Agent 3.2.65
online with older effective capabilities. Reapplication rollout
`4e1a6909-f527-4c64-afd6-fd099e228e27` applied 3.2.67 at 17:15:26 UTC.
The pilot was online with fresh Context and the restored v2 capabilities;
published `system.quick.check` again succeeded
(`5312954a-85d5-485e-b163-a57a9add1cf8`). At 17:16 UTC all three Windows
rollout devices reported Agent 3.2.67 with recent WSS presence. The API,
worker, Nginx and PostgreSQL services were active, migration result was
`success` at DB head 0028, root volume had about 20 GiB available, and strict
CA/hostname HTTPS `/healthz` returned 200. The post-fix API journal had no
`Gateway state rejected`, replay-conflict, or traceback lines in the checked
window. The final pilot population remains one device: `A2-IAO` stays on
3.2.46 until an exact rollback artifact and a separate gate are available.
ALT live verification remains open because the dedicated test host's SSH
connection timed out; no claim of live ALT acceptance is made.

## Context and Evidence Retention v2 (2026-09-24)

The implementation plan is
`docs/superpowers/plans/2026-09-24-context-evidence-retention-v2.md`.
The architecture and production measurement procedure are in
`docs/architecture/context-evidence-retention-v2.md`. Work starts from main
`0aa22537d93e29e79eb43dce01e8e1e50ee23a6f` on
`codex/endpoint-retention-v2`, with Agent `3.2.65` unchanged. The new Alembic
head is `0027_context_observed_backfill` after a follow-up observation-freshness
repair. Production backup, migration and acceptance
evidence follows.

Production release `d626c1ed44b38637870e2968c599fc793142fa6e` was
deployed from `codex/endpoint-retention-v2` after `1849 passed, 40 skipped`,
21 Console unit tests, three browser E2E tests, contract generation check,
Alembic offline SQL, compileall and `git diff --check`. Previous release was
`0aa22537d93e29e79eb43dce01e8e1e50ee23a6f`; DB moved from
`0025_console_enrollment_queue` to `0026_context_evidence_v2` with migration
unit result `success`. The verified custom-format backup is
`/var/backups/endpoint-platform/pre-retention-v2-20260924T131917Z.dump`
(17,765,654 bytes, SHA-256
`0a3bcd6eb403067e069abc9d9f96af53b3388b747748b68a0ae0bc2705cee5a8`).
The release archive SHA-256 matched on both machines:
`e53b36362c8b28deac253855600d2e7a05ce106dee00edfb2581cedcdfb30d8d`.
API, worker, PostgreSQL and Nginx were active; strict hostname/CA HTTPS gave
`200` for health, Console login and its versioned JS asset. Unauthenticated
service API returned `401`. Existing completed Module detail projected one
successful step with its safe result. The live Agent `3.2.65` session remained
connected after the API restart. Initial due counts were 35,549 raw collection
payloads, 1,955 raw snapshot payloads and 92,150 scheduler bookkeeping rows;
later counts fell to 35,370, 1,766 and 91,984, respectively, as bounded
cleanup ran. At 13:29:25 UTC, Agent `3.2.65` completed fresh `health_v1` and
`session_v1` collections; both `ContextCurrent.last_observed_at` values advanced
after deployment. A bounded production snapshot-retention invocation removed
100 rows; all current pointers remained valid (`broken_current=0`) and six
current profiles for the `3.2.65` device remained. The read path for an older
successful diagnostic operation returned its lifecycle with
`result_available=false`, without a 503. PostgreSQL race tests were opt-in and
skipped locally because no disposable local PostgreSQL URL was configured. The
dedicated Linux test host was unreachable over SSH during this release.
An authenticated Console session subsequently completed the live acceptance
on the Windows Agent `3.2.65` device. The read-only published module
`inventory.local.adapters@1.0.0` created operation
`ebd18e17-9944-4c7c-8294-4fb8abd49dfb`, which reached `succeeded` in
19.9 seconds with one successful safe step result. Console showed the 24-hour
Evidence expiry and then the pinned state without an ordinary expiry. A
read-only production DB check at 14:02 UTC confirmed `module` evidence with
safe payload present, a 64-character SHA-256 digest, non-NULL `pinned_at`,
NULL `expires_at` and `scrubbed_at`, and exactly one
`operation_evidence.pinned` audit event. Console Context showed separate
changed/observed times, and the Changes tab displayed a durable
`NETWORK_CHANGED` event. The dedicated Linux test host remained unreachable
over SSH; the live Windows Agent acceptance used the existing host without
an Agent update. At 14:03:43 UTC, more than one worker interval later, the
pinned payload still existed, `expires_at` remained NULL and the PIN audit
count remained one. Reloading Console still showed the pinned safe result.
API, worker, PostgreSQL and Nginx were all active.

Post-deployment audit found that revision 0026 backfilled `last_observed_at`
only from the last changed snapshot. Existing completed deduplicated baseline
and inventory collections could be newer. Revision 0027 backfills those
observations from retained collection timestamps without changing snapshots;
the pre-migration query found 12 affected current rows (eight baseline and four
inventory). Follow-up release `db107f895bfc54cedef80a981eacb4f6794d79f1`
was published and deployed after `1850 passed, 41 skipped`, contract and
compile checks, offline Alembic SQL, and a successful full migration through
0027 on a disposable PostgreSQL database. Its test current pointer preserved
the original snapshot/`updated_at` and advanced `last_observed_at`; the
disposable database was removed. The second verified custom-format backup is
`/var/backups/endpoint-platform/pre-observation-backfill-20260924T134545Z.dump`
(17,451,925 bytes, SHA-256
`47c79fa17d8c4dbd98cedb0e98bba13ebc73ceb83b73a98e60c0f67de0ef3510`).
The follow-up release archive matched on both machines at SHA-256
`c434799debbdf317d063801a91cbc9f9cffd38a0714e222d1036d490ef70f86a`.
The migration unit returned `success`; production revision is
`0027_context_observed_backfill` with zero remaining current/collection
freshness mismatches. Agent `3.2.65` remained connected and completed fresh
health and session observations after the second API restart. API, worker,
PostgreSQL and Nginx remained active, strict HTTPS health returned `200`, and
post-release warning-or-higher service journal entries counted zero.
At 13:55 UTC, a separate disposable PostgreSQL 16 database on the production
host was migrated through revision 0027 and used for an actual concurrent
Evidence PIN versus expiry cleanup check. The uncommitted PIN held the row;
the cleanup transaction's `SKIP LOCKED` batch processed zero rows. After the
PIN committed, another cleanup processed zero rows, the safe payload remained,
`expires_at` was NULL, `pinned_at` was set, and one immutable PIN audit event
existed. The disposable database was dropped. This check used synthetic
records and did not change production application data.

## Current Console v1 work (2026-09-24)

The active implementation plan is
`docs/superpowers/plans/2026-09-24-endpoint-console-v1.md`, based on main
`2995b06d3b45a26d39b6acc4129e5892b6c7c942` and the user-supplied spec
in `docs/superpowers/specs/2026-09-24-endpoint-console-v1.md`.
The Module Platform capability constraint repair is revision
`0022_module_step_capabilities`; Windows Setup release metadata is revision
`0023_windows_setup_releases`; the credential-free Console module owner is
revision `0024_console_module_owner`, and enrollment queue pagination uses
revision `0025_console_enrollment_queue`. The Console foundation, fleet/context,
enrollment, updates, operations, Module Workbench, and audit were implemented
on `codex/endpoint-console-v1` and published to `main` at
`4801e21b20c342ba006b9bd9c40c42e6642ce27b`. The approved Windows Agent
3.2.63 runtime contract is unchanged. An isolated browser test covers the real
local API through manual enrollment approval, canary creation and rollback,
and module publication and device execution with simulated Agent results. The local run
also corrected module operation detail projection and the approved enrollment
queue/label, and aligned campaign display names with the Russian Console.
Device detail now projects the current user, OS and version from safe snapshots;
Context shows collection state and server-derived freshness. The browser flow
covers Setup download, campaign editing, and a Russian-label regression guard
across primary pages. Campaign editing now formats the existing expiration in
the browser's local time and preserves the original instant when only other
fields change; a browser regression runs in `Asia/Yekaterinburg`.
Completed rollout history now
uses its own filtered, paginated server query. The Module Capability Catalog
shows backend-provided Russian names, platforms, minimum Agent version, risk,
consent, and parameter rules.
Published modules on device detail and compatible devices in Module Lab now
use bounded, paginated API queries and visible page controls.
Windows campaigns and active Setup releases now also have bounded, paginated
Console queries. Campaign policy can select a signed release from later pages;
the Setup catalog publishes a typed page response. The legacy enrollment
campaign list contract remains unchanged. Module version history is bounded
and paginated. Device Context changes and update history have typed, paginated
responses and page controls; mixed baseline/inventory changes retain global
chronological order without exposing raw snapshots. Module validation and lab
histories also have bounded pages; the acceptance control uses a server-derived
summary of all passed platforms, including evidence beyond the current page.
All Console, operation journal, and audit JSON routes publish typed response
models; the Setup binary download remains a file response. The 2026-09-24
release `758043d02f3bce895e27cb3c9dd615f0692fa217` runs in production at
DB revision `0025_console_enrollment_queue`. The previous release
`a49cd5aa351a` is retained for rollback. The verified pre-release PostgreSQL
backup is
`/var/backups/endpoint-platform/pre-console-758043d-20260924T060319Z.dump`
(17,359,610 bytes; SHA-256
`eca3b674e313949f7e72e469840ade6c1aac99f34cb591e7d079d8a6c802dca8`).
The release archive SHA-256 is
`68ee7be926f36bb18af00ea35b0cd0687f34f09eebac464ef70146a107817d7b`.
The final code revision passed 1784 Python tests (39 skipped), contract
generation check, and compileall. The frontend passed 20 unit tests, three
Playwright E2E flows, and production build. Provider release-gate CI passed on
the deployed code revision.

The administrator credential was rotated as requested; previous sessions were
revoked and production browser login succeeded. Strict CA/hostname HTTPS
returned 200 for health, login, and the hashed Console asset. API, worker,
Nginx, and PostgreSQL are active. The local Windows Agent `3.2.63` completed
one real `adapter.list` Module Lab operation and one published device operation;
both reached `succeeded` with safe step results and audit events. Module
platform, execution, and read-only primitive flags are enabled; network
primitives remain disabled. The original mode-600 environment file is backed
up at
`/etc/endpoint-platform/endpoint-platform.env.pre-console-local-agent-20260924T054931Z`.
The workstation does have Endpoint Agent MSI `3.2.63` installed. The failed
preflight checked stale canary provenance for MSI `3.2.41`, whose ProductCode
was removed by later universal Setup major upgrades. Reinstalling the same
signed, SHA-256-verified `3.2.63` MSI through the canary wrapper refreshed the
protected provenance; the collector and validator then reported `READY`.
Universal Setup does not refresh that canary-only record, so another Setup
major upgrade can make this particular preflight stale again. Console rollout
and rollback use verified ZIP runtime builds and the Windows runtime selector,
not MSI. A live Console rollout/rollback cycle on this workstation remains
unverified; browser E2E covers those actions with simulated Agent outcomes.
PR #35 was merged by fast-forward into `main`. The historical Wave 1
plan below is retained as a record, not a current deployment gate.

## Goal

Deliver Wave 1 Device Context, then expose normalized projections in web_ovpn without coupling that panel to raw agent results.

## Current State

Headless Agent V2 architecture baseline is repository
`5b53f080d884193189b7458e27ab55a04cb6efe4`. Historical ALT pilot evidence
covered `3.1.84`; the pilot currently selects the intact immutable `3.1.80`
rollback release.

6A enrollment and update control-plane work are merged locally. Device Context
foundation has passed independent review and local acceptance: strict profiles,
bounded ALT collectors, fixed Gateway capabilities, additive lifecycle/snapshot
storage, safe service routes, scheduler and retention. The typed safe SDK plus
the feature-gated `web_ovpn` adapter API and Russian-first endpoint pages have
also passed local review in clean worktrees. Explicit netctl correlation has
also passed review without IP-only matching. ALT packaging/provisioning and the
isolated test-agent acceptance harness are complete. A valid wildcard
`*.sosnadmin.local` certificate is in active use on the TLS source host; its
private key has not been copied into the workspace.

The production Endpoint Platform release is `9f8f5b49f578`: the API, database
and proxy are active, but this release does not contain Gateway WSS, the active
proxy does not expose the WebSocket upgrade route, and the database remains at
`0010_session_last_seen_index`. Task 9 live acceptance is blocked until the
reviewed WSS release/configuration and `0011_gateway_wss` migration are
deployed, a database backup is verified, and the rollback artifact is restored
on the controller.

The initial administrator `osn-admin` is active with the explicit
`updates:write` grant. Bootstrap was audited, and the strict-HTTPS login check
created then revoked its temporary verification session.

The test-agent pilot retains a secure permanent credential and token-bearing
legacy identity, and its finalized service has no one-time claim dependency.
The credential-free canonical headless enrollment identity is not present yet;
it must be created and matched to the controller Device before a WSS canary.

Historical single-device update proof on `test-agent-lin` recorded that the
controller-delivered `3.1.84` canary reached `applied` after the post-restart
handshake, then an authenticated rollback selected the already immutable
`3.1.80` release and also reached `applied`. That proof used the pre-WSS
runtime and does not satisfy the headless WSS gate. The Task 9 root worker uses
the separately reviewed stable root launcher; headless canary payloads do not
replace it. A deliberately malformed `3.1.83` archive was rejected without moving
the selector and recorded as a terminal failed canary; its immutable artifact
was not overwritten. The post-rollback `baseline_v1` request completed through
the former Gateway adapter. The controller metadata for rollback `3.1.80`
remains, but its artifact file is currently absent, so no new assignment is
allowed.

Wave 1 is merged and deployed in `BorisDruzak/web_ovpn` at `f1108f4`. The
`openvpn-web` runtime has the matching typed Endpoint Platform SDK, a
root-managed least-privilege `web-ovpn-context` credential, and the configured
CA file. DNS resolution for `endpoint.sosnadmin.local` is pinned to the
internal resolver for the internal domain; live health and adapter calls pass
hostname and CA verification. The network-device list shows a session-only
Endpoint Agent state: it refreshes no more than once in five minutes, preserves
a stale safe cache on failure, and confirms a relationship only for a unique
normalized-MAC match. No MAC, IP, raw context, token, CA path or upstream error
is rendered or returned by the new status route. The status route is
session-protected; existing Bearer API authentication is unchanged.

The service credential was rotated through the controller lifecycle with no
scope change and no expiry policy. The replacement was staged and verified over
strict TLS before an atomic web-host switch; the old credential was revoked
with immutable created/revoked audit records, then its local backup was
securely removed. Production acceptance verified one active replacement
credential, the rejected old bearer, and a successful current identity-feed
call.

## Constraints

- Headless Agent V2 architecture work is documentation and local guardrail work
  only. It must not deploy to production, alter production configuration or
  data, restart services, or change the dedicated test-agent host.

- web_ovpn and network_configuration remain read-only until a clean dedicated worktree exists.
- ALT Linux is first; no real device collection, deployment, or canary belongs to the foundation.
- Collectors are bounded/read-only; safe APIs never expose raw result payloads or credentials.
- The periodic allowlist is baseline (24h), health (5m) and network (15m).
  Diagnostic is manual-only. Scheduler and retention are local server work;
  their migration must not be run remotely in this foundation task.
- DNS for `endpoint.sosnadmin.local` is configured and the internal CA is
  available as deployment input outside Git. TLS verification remains mandatory.
- Disk resize is cancelled. Deployment uses the existing disk only after a
  capacity check confirms it is sufficient; no resize is a prerequisite.

## Next Steps

Requester device-binding staging acceptance found a native tray startup defect
in MSI 3.2.76: packaged Python 3.12 lacks `wintypes.HCURSOR`. Correct the cursor
handle and x64 window/module signatures, exercise a real Windows notification
icon/message loop, and build/install source-bound MSI 3.2.77 before continuing
manual Windows tray acceptance. Keep the original staging database/config and
Windows 3.2.75 package backups for final restoration. Full First Wave acceptance
remains open; the green prior CI does not prove the repaired package.

MSI 3.2.77 starts its tray, but the real Limited interactive client cannot open
the device-binding pipe or query its LocalService server process (Win32 error 5).
MSI 3.2.78 adds required pipe read-attributes access and publishes only process/
token identity-query rights before the listener starts, preserving service-SID
and interactive-session checks. Native ACL regression tests pass; complete
staging challenge/redeem acceptance and restoration remain mandatory.

1. Review and merge the local Endpoint Operations API v1 package described in
   `docs/superpowers/specs/2026-08-09-endpoint-operation-v1-design.md` and
   `docs/superpowers/plans/2026-08-09-endpoint-operation-v1.md`. The first
   typed operation, `context.diagnostic.collect`, is feature-gated and
   default-disabled; no production enablement, database migration, agent
   rollout, or Helpdesk integration is included in this package.
2. Treat the Gateway/update/rollback pilot as accepted only for the dedicated
   `test-agent-lin`; do not assign a production endpoint or run a bulk rollout
   without a separate change decision.
3. Keep the `web_ovpn` Endpoint Platform integration feature-gated. Any
   credential-expiry policy, production endpoint assignment, bulk rollout,
   IP-only correlation, or exposure of raw agent result payloads requires a
   separate approved change.

## Verification

Foundation completion needs strict contracts, collector privacy/capability,
PostgreSQL lifecycle/idempotency, semantic hash/diff, scheduler/retention,
safe projection and generated-schema tests. Scheduler keeps one active request
per device/profile and expires bounded offline work; retention preserves the
current snapshot, its prior snapshot and explicit pins.

Endpoint Operation v1 local acceptance on 2026-08-18 recorded 265 contract,
30 operation (4 PostgreSQL-dependent skips), 36 context (1 skip), 70
architecture and 55 transport tests passing. `tests/gateway` has 54 passing
tests but two pre-existing tests that monkeypatch the removed
`pc_agent.runtime.application._https_update_hook`; `tests/packaging` has 57
passing tests and one pre-existing stale hash for
`pc_agent/context_profiles/baseline.py` in `initial-runtime-3.2.13.json`.
The full suite stops at collection because two legacy agent tests import absent
`scripts.build_module_zip` and `scripts.register_support_modules`. These are
separate baseline repairs, not evidence to enable the feature.

## Handoff

### ADMIN-2 Gateway disconnect incident, 2026-09-29

- Reproduced on deployed production `abdd5c7ef596`: expired ordinary connect-refresh
  collections created a command with deadline before creation, raising Pydantic
  ValidationError and closing authenticated WSS sessions with internal_error.
- Branch `codex/fix-expired-connect-refresh` is synchronized with main; the server
  runtime differs from exact production base in only the three corrected context/
  delivery files. Requester-binding changes are excluded. Expire overdue collections and
  their active delivery state before refresh/delivery; preserve operation-owned
  deadlines and already received/terminal results. Refresh idempotency buckets use
  the delivery window so a retry does not replay an expired request for 24 hours.
- Added failing-before-fix delivery/replay and same-day retry regressions, plus
  guards for operation ownership, received results, unrelated devices and no TTL.
- Verify Linux provider/context CI, generated contracts and production archive;
  deploy an immutable release using PRODUCTION_RUNBOOK with backup/rollback.
  Confirm stable ADMIN-2 WSS heartbeats and successful fresh collections afterward.
  Windows broad checks have separate fixture failures; record exact receipts.

Production deployment, the dedicated test-agent pilot, and the Wave 1 network
list presentation passed their gates. The deployed `web_ovpn` integration
remains a narrow service-to-service boundary; its page cache is MAC-free and
its only automatic association is the unique-MAC confirmation. Any production
endpoint assignment, bulk rollout, credential-expiry policy, or new data source
requires a separate decision.
