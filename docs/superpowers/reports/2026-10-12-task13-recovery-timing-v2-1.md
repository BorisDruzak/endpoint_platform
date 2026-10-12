# Task 13 recovery timing v2.1

The reviewed B creator exited1 before reconciliation, slot creation, child
launch or target calls. Its initial source/runtime verification took about104
seconds. At capsule creation only420.754908 seconds remained against the480
guard. The guard correctly refused. Independent refusal review SHA is
`87efe175ec7ba5f151c3dc70c85dd1edb1b99730db544fe7253eed3eeedce1ee`.
Both slots remain absent and original preservation/three consumed claims are
unchanged. I/B are retained with their original code, requests and deadlines.

The operator's current natural instruction specifies no expiry. New v2.1 uses a
source-reviewed finite six-hour task-intent policy and a thirty-minute admission
interval, both explicit typed fields in each NEW gate. It binds expiry to the
earlier of the fresh gate plus1800 seconds and the actual human request plus21600
seconds. Old-mode or missing/mismatched-policy gates refuse. This is a new
gate/code/request binding; it does not extend any old capsule or request.

Actual ReadOnlyWindow and LiveAuthorization remain1200 seconds with UTC and
monotonic checks. Original plan/seal/deadlines/receipts/Facts and the strict v1
parser are unchanged. v2.1 still permits only the one original-seq04 physical
slot, and recaptures the actual request and subsequent user instructions.

The v2 creator now reserves840 seconds before fresh preflight and780 before
irreversible launch. UTC/monotonic budgets are checked again AFTER expensive
guards immediately before slot commit and Popen. A late refusal before commit
preserves the empty slot; a refusal after commit permanently burns it without
spawning a child. Legacyv1 retains480/420; child420/225 guards remain unchanged.
The caller also checks at least1020 seconds before creator startup.

Verification uses real owned synthetic native slots, without target calls:
old-policy/type rejection,1800-second admission,21600-second consent/clamp,
later-message rejection,800-second startup refusal,779-second UTC/monotonic
refusal after preflight and after expensive guards, and permanent postcommit
no-retry behavior. Timing regressions were first RED before implementation.
Fresh J/C source/admission/execution reviews are required before target action.
