# Native agent power collection

The power collector runs without a DLP policy and while WSS is disconnected.
Facts and native cursor checkpoints commit atomically in the independent
protected `power-events-v1.db`. Retention is 30 days, 10,000 serialized events and
5 MiB of live event payload. SQLite page/journal overhead is additional. Oldest
facts leave first at capacity; cumulative expiry, overflow, native-loss, reset
and permanent-rejection counters remain visible in power source status.
Quarantine keeps at most 128 identifier/reason/time rows, at most 30 days, and
stores no payload or raw OS data.

Each fact UUID is deterministic for `(source, boot_id, native_record_id)`.
Observed time may change on re-reading; native time and other stable fields do
not change. The server's native duplicate checks therefore accept replay after
an ACK loss. Exactly matching batch UUID and ordered per-event result IDs are
required before local disposal. `retry_later` remains queued with a retry delay;
rejected facts leave the hot queue and increase permanent rejection/loss counts.
An in-flight item already evicted by local bounds cannot block its later peers.

## Windows

Only whitelisted System provider/event metadata is projected. XML exists only
transiently inside the fixed native reader subprocess; rendered messages, user fields, command
lines and XML are never persisted or sent.

| Native metadata | Power fact |
| --- | --- |
| Microsoft-Windows-Kernel-Boot27, BootType0 | OS_STARTED/transition |
| Kernel-Boot27, BootType1 or2 | OS_RESUMED/transition (Fast Startup/hibernate) |
| Microsoft-Windows-Kernel-General12 | Boot metadata only; no independent startup |
| Kernel-General13 StopTime | OS_SHUTDOWN_STARTED/transition |
| Microsoft-Windows-Kernel-Power42 | OS_SLEEP_STARTED/transition; EffectiveState5 means hibernate |
| Kernel-Power107 or Microsoft-Windows-Power-Troubleshooter1 | OS_RESUMED/transition |
| Kernel-Power41 | OS_UNEXPECTED_SHUTDOWN_REPORTED/reported, at detection time |
| User32 1074 | OS_SHUTDOWN_STARTED/request; cancellable |
| PowrProf PBT_APMSUSPEND4 / PBT_APMRESUMEAUTOMATIC18 | Immediate sleep/resume transition, unknown sleep subtype |
| SCM shutdown notification | OS_SHUTDOWN_STARTED/transition; ordinary service stop creates none |

The stable boot boundary is Kernel-Boot27's native record and timestamp. General12
may arrive on either side of it and can roll out of retained logs; it cannot
change an existing boot/fact identity. Historical records without a known native
boot boundary are skipped and counted as lost rather than assigned to the
agent's current process. Callbacks use a separate lookup of the latest OS boot,
never the old boot at the current replay page. EventLog6005/6006 are not used.
Forward record-ID pagination is bounded to128 rows. Oldest/newest System record
IDs detect out-of-range rollover. Before reusing a cursor, one exact-record
lookup checks its persisted SHA-256 anchor over provider, event ID, record ID
and native timestamp. Reused numbers in overlapping recreated log generations
therefore cannot silently preserve old coverage. A missing/mismatched anchor,
including a legacy checkpoint without one, resets context and coverage, reports
a reset/degradation and replays the bounded retained 30-day window. Matching
anchors preserve historical replay even when the live OS boot has changed.
Only the 64-character digest is persisted, atomically with the page/cursor.
Before projecting a page, one reverse Boot27 lookup at/before its first record
recovers the historical boot context even when the boundary is older than the
30-day fact window. Later boot boundaries update that context in record order.
The context commits in the same spool transaction as its facts and cursor; the
lookup itself creates no startup fact. Missing historical context keeps the
source degraded, including empty pages. A retained checkpoint cannot carry an
obsolete boot across a newer boundary excluded by the fact-age filter.

The reader uses a fixed subprocess entry (module execution for Python, private
`--windows-power-read` dispatch in the frozen core). Static imports from the core
entrypoint include this worker in its existing PyInstaller dependency closure.
Its only input is a bounded stdin JSON checkpoint/time pair; no paths, commands
or privilege requests are accepted. The reply contains at most128 whitelisted
metadata rows, a16KiB checkpoint and separate live boot identity, within1MiB.
One shared per-loop lock serializes collector and SCM reads. A read has a10-second
deadline; cancellation/timeout kills and waits for its process before releasing
the lock. Native reads never enter the default executor, so a stalled optional
read cannot hold `asyncio.run` executor finalization or updater handoff.

The fixed host sends `S` then EOF for SCM shutdown and only EOF for service stop.
New cores attempt a durable shutdown write for at most2 seconds, then follow the
existing cancellation path, including native child termination/reaping. Older cores stop on any byte/EOF. A completed
update-pending runtime exit still wins over a simultaneous host-pipe signal.

## ALT Linux / systemd258

The existing main unit already grants supplementary `systemd-journal` membership.
No root main process, helper privilege or package permission change is added.
`journalctl --output=json --lines=+128 --after-cursor=…` pages forward; using
plain `--lines=128` would tail and lose undelivered earlier records. A checkpoint
is verified by an exact one-row `--cursor` lookup before reuse. Missing/rolled
cursors reset to the retained30-day window and increase the reset counter.
Linux checkpoints carry `projection_version=2`. Older checkpoints discard their
cursor and coverage once, preserving `current_boot`, so retained shutdown rows
missed by the earlier message filter are replayed within the same30-day bound.
The first recovered page reports reset/degradation; coverage starts from the
recovered native evidence (or collection time if empty), never the old coverage
claim. The marker, recovered facts and cursor share the existing atomic spool
transaction. Later pages/restarts resume forward with stable native event UUIDs;
already queued facts are deduplicated and server replay stays idempotent.

Only trusted `_UID=0` rows with the expected system unit/PID are admitted:

| MESSAGE_ID / native evidence | Power fact |
| --- | --- |
| 6bbd95ee977941e497c48be27c254128 from fixed systemd sleep units | OS_SLEEP_STARTED/transition; unit selects sleep/hibernate/hybrid/unknown |
| 8811e6df2a8e40f58a94cea26f8ebf14 from those units | OS_RESUMED/transition |
| 98268866d1d54a499c4e98921d93bc40 from systemd-logind.service | OS_SHUTDOWN_STARTED/request |
| 7d4958e842da4a758f6c1cdc7b36dcc5 from PID1/init.scope, UNIT=shutdown.target | OS_SHUTDOWN_STARTED/transition |
| 39f53479d3a045ac8e11786248231fbf from PID1/init.scope, UNIT=shutdown.target | OS_SHUTDOWN_STARTED/transition; shutdown target reached |
| b07a249cd024414a82dd00cd181378ff from PID1/init.scope | Historical OS_STARTED at system startup completion |
| /proc/sys/kernel/random/boot_id plus /proc/stat btime | Current OS_STARTED once per kernel boot |
| Public logind PrepareForShutdown(true) / PrepareForSleep(true) | Immediate request evidence |

False logind signals can also mean cancellation; they do not manufacture resume
or startup. Journal sleep-stop supplies stronger resume evidence. `busctl wait`
uses public AddMatch subscriptions and validates the well-known sender, object,
interface and member. `busctl monitor` would need extra BecomeMonitor privileges
and is deliberately not used. Raw `MESSAGE` is never requested or parsed.

Missing journal access, nonpersistent journal, signal subscription failures,
future timestamp skew and malformed native rows reduce source coverage or
availability. Source reported_at is the collection time, never refreshed by
sender retries. An old available status cannot masquerade as a fresh sample
after collector failure. Sudden Linux power loss has no universal trusted
retrospective event in this source: no power-loss time or unexpected-shutdown
fact is invented from a missing shutdown, journal gap or reboot.

## Native API references and limits

- [systemd258 journalctl](https://www.freedesktop.org/software/systemd/man/258/journalctl.html)
- [systemd258 logind](https://www.freedesktop.org/software/systemd/man/258/org.freedesktop.login1.html)
- [systemd258 message IDs](https://github.com/systemd/systemd/blob/v258/src/systemd/sd-messages.h)
- [systemd258 successful start-job metadata](https://github.com/systemd/systemd/blob/v258/src/core/job.c#L677-L683)
- [systemd258 target completion](https://github.com/systemd/systemd/blob/v258/src/core/target.c#L183-L185)
- [systemd258 shutdown target semantics](https://www.freedesktop.org/software/systemd/man/258/systemd.special.html#shutdown.target)
- [systemd258 busctl wait implementation](https://github.com/systemd/systemd/blob/v258/src/busctl/busctl.c)
- [Windows EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery)
- [Windows event query XPath restrictions](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events)
- [Python3.12 asyncio subprocess ownership](https://docs.python.org/3.12/library/asyncio-subprocess.html)
- [pywin32 build311 event APIs](https://github.com/mhammond/pywin32/blob/b311/win32/src/win32evtlog.i)
- [Windows suspend/resume notification API](https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerregistersuspendresumenotification)
- [Windows Fast Startup distinction](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation)

The sanitized Windows fixture was captured read-only from the operator OS. It
contains actual provider/record/time and whitelisted fields, without machine or
user identity. It proves parsing/mapping of that metadata; it is not dedicated
VM transition, package installation or sleep/hibernate acceptance. Modeled
Fast Startup, hibernate and notification tests do not replace that native gate.
