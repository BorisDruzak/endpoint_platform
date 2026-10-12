# Task 13 recovery v1: operator record framing diagnosis

Implementation: `36ebfb5bc4f8b0d5ad9b490da8105262cccb6e3a`.
Protocol source SHA-256: `0b6ef3462f5964ec99e42abc381794615ec90fc8bd3f0c9057129fcb4bc33a91`.

The actual operator message bound to observation D contained one terminal LF:
388 bytes versus the canonical directive's 387 bytes. All six fields matched
the reviewed gate. The strict framing comparison refused it before claims or
bundle creation. Separately, its expiry was 2026-10-12T08:35:16.401477Z;
the actual check at 08:42:46Z was already too late. Neither condition authorizes
extending the deadline or applying the message to another source revision.

The fix accepts exactly one terminal LF or CRLF only for the canonical directive
comparison. The actual app record, bytes and hash are preserved. Additional
whitespace, text, repeated endings and bare CR still fail. Changing the raw
message after capture fails replay verification even if the directive's fields
are equivalent. All field, gate, source, sequence, latest-user and expiry checks
remain active. A new reviewed gate and actual bound human message are required.

## Evidence and verification

Raw D record SHA-256:
`f7ebfad4b881002cca3ba7f08e516efe51a36d12a535167daca4aaf84d82a5c8`.
Diagnostic expiry refusal after the fix SHA-256:
`c37f8e6942c10b122fdbbe156af65ac04acd9308b3030d0815f562817631b276`.
These are refusal evidence, not execution authority.

New framing regression cases: RED 2 failed / 7 passed before the fix;
GREEN 21 permission and framing cases passed afterwards. Both additive
recovery suites passed: 83 tests on Python 3.12.14 / Windows PowerShell 5.1.
Independent source review: PASS_SOURCE_REVIEW_ONLY, no Critical/Important
findings; 21 tests, raw LF-to-CRLF replay rejection and ten invalid suffix
checks independently passed. Full exact bundle review remains a separate gate.

Broader applicable Task13 verification also passed: 352 passed, 11 deselected
in 232.76 seconds (`pytest tests/tools -q --tb=short -k` with the explicit
Task13 selection). The deselected unchanged historical session/state cases
require a previous human permission literal or absence of already consumed
claims. Their guards were preserved, not weakened to manufacture acceptance;
this is not a claim that the unfiltered suite passes.

| File | SHA-256 |
| --- | --- |
| recovery_permission.py | ebfaec075a7d521cf3d3cbb54de5374d8b07da9438df87e71134f6d11bd2b622 |
| test_task13_additive_recovery.py | ff01ccc2a11dab1355a575a33da3e29d3a04db47f8a4f523186866b1245c9e36 |
| test_task13_recovery_receipt.py | 1f27a226ee118373522ea73c5a1e98d1c383ed75f2b268a08729d86f35db7eb3 |

The three historical consumed claims retained their exact identities. No new
execution claim, capsule, authority, seq04 launch or receipt04 was created.
The additive recovery slot remained ABSENT. Original artifacts and guards were
not changed; runtime 3.2.82, MSI and Setup were not changed.

This diagnosis is distinct from the historical oversized inline command
(34,172 UTF-16 units including NUL, refused by the builder after old claims
were consumed), already addressed by sealed stdin transport at baseline
47b688c. Observation A's guest exit1 with empty streams remains UNKNOWN;
successful later read-only observations do not establish its cause or prove
seq04 recovery. Scope remains one authorized seq04 attempt, STOP before seq05.
