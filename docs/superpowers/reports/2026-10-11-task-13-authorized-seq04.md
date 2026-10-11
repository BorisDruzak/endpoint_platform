# Task13 authorized seq04 attempt: UNKNOWN / BLOCKED

One authorized execution attempt stopped locally before watchdog preparation.
Comparator dispatch: **NO**. Canonical receipt04: **ABSENT**. Separate seq04 launch
permitted now: **NO**. STOP; no retry, marker or restore was performed.

## Implementation and verification

Baseline: `46b5c40370cd4616f1425963f612eb5d82480ecd`.
Implementation: `c6d7f141d1db7ee2bef153e1ee20dfeb76548dfc`,
`feat(canary): authorize one seq04 after audited read-only recovery`.

Scoped files: operator documentation and execution plan; authorized execution,
gate admission and read-only recovery tests; `authorized_execution.py`, `bundle.py`,
`loader.py`, `permission.py`, `supervisor.py` under
`tools/canary/task13_continuation/`.

The actual human authorization record and fixed independently audited read-only
recovery gate admit a fresh single-use launch claim. CREATE_NEW precedes Popen;
the claim key excludes CID. Parent and child retain and verify its exact owner.
The prior consumed claim and historical recovery evidence remain immutable.
Existing canonical gates, native identity, clocks, watchdog, comparator, receipt
and root settlement conditions remain in force.

RED: four failures and three errors in 0.99s. Initial GREEN: seven tests in 21.13s.
Full relevant continuation, identity, MSI and watchdog suite: 254 passed in 195.56s.
After the final parent claim-hold addition, the eight authorized-execution tests
passed in 16.38s, including denied claim mutation and no second Popen after failure.
Independent preliminary tests: six passed in 19.56s. `git diff --check` passed.
These tests do not prove canonical VM execution acceptance.

Exact source/runtime bundle review returned PASS before VM contact. Both primary
and independent review missed feasibility of the generated preparation command.
The independent failure audit subsequently records an Important finding at
`transport.py:124`: command length exceeds the retained Windows bound.

## Fresh authority and full initial canonical preflight

A new capsule was created at `2026-10-11T15:40:21.579993+00:00`, expiring at
`2026-10-11T16:00:21.579993+00:00` (1200 seconds). The historical read-only capsule
served only as admission evidence; its expiry was not extended.
The new execution closure includes 55 source entries and 2879 runtime files.

All eight fresh initial read-only observations completed with exit code 0 and empty
stderr, and the canonical validator passed. Independent offline replay also passed.

| Constituent | Result | SHA256 of transport result |
| --- | --- | --- |
| Management state / checkpoint | PASS | `69684a0c0ff9d07ae3cde2e469b43b1ca41b58a43899aaa8f490dcb554cd43ef` |
| Provider | PASS | `3d09d0ac8665d31f2bea513d992167f57689adc0fd80f685ef10b29cddc93394` |
| Guest | PASS | `c0ffb07c94e211e6d0b745da1d9545f7a042a8f20ea5f57ff611bc998de98059` |
| Inventory | PASS | `89f96b34eb298edaa2358e9f6a9468c60f73a2d2ce3ab71c445a1039a65c56f7` |
| Current state | PASS | `b96088bd5c5b4ca69232c66220d000d4e37ecff5c5c00f042a572b41e0ba01d1` |
| Native process identity | PASS | `37353a57b48a170c8fc3973baa1c8b2c780609d8dcb235a84f36bea862f9437d` |
| Guest clock | PASS | `f77def98c06c9d58b4a72ed15f57437d0e08997ee04b0ea2a9067f1044b0f4b6` |
| Management clock | PASS | `2d6959d001bfbbaa9f747922b27c3cd9c5064259738a0f63c6b400c19a5fa847` |

Native identity states: 14 PROCESS_ABSENT, two PID_REUSED, zero IDENTITY_UNKNOWN.
The old RuntimeException RCA remains **UNKNOWN**; current observations do not
retroactively establish its cause. Original plan, seal, receipts00–03, baseline,
snapshot and 80 prior recovery evidence files remain unchanged.

## Proven failure and independent audit

The frozen preparation script is 12741 bytes. Its UTF16LE/base64 argument has
33976 characters. Exact Windows argv serialization, including terminating NUL,
requires **34172 characters**, exceeding **32767** by 1405.
`transport.powershell` raises `ValueError: Windows command-line bound` before
`self.call`, transport intent creation or Popen. The limit was not changed.

The new launch claim and original global seq04 dispatch claim had already been
consumed. They remain consumed permanently. The old consumed claim was neither
restored nor reused. Preparation and comparator transport intents/results are
absent. No watchdog preparation or workload mutation was dispatched to the VM.
Only the eight read-only target observations occurred.

Root and outer supervisor native exit codes are 1, wait results are 0, streams complete,
timeout false. The supervisor recorded UNKNOWN with retry_allowed=false.
Immediate dispatch preflight, execution evidence, receipt04, resume-gate and
root-completion are absent. No canonical comparator PASS occurred.

Independent failure audit: **fail-closed integrity PASS; execution UNKNOWN/BLOCKED**.
This is not a canonical execution PASS. The audit confirms initial preflight replay,
the exact local failure, retained claims, unchanged history and absent later phases.
The independent reviewer also checked this final report offline and found no
substantive corrections. No additional VM contact occurred.

## Evidence pins

Raw native identities, command arguments and topology remain in protected local
evidence; only hashes and bounded findings are recorded here.

| Artifact | SHA256 |
| --- | --- |
| Execution source/runtime closure | `41810d8b1f464a4931c817c9237b08a19a178a65a424df5ef677c2bc461cb9d8` |
| Independent source review | `1d6e2a46c7684eb7b0af1cb994e075ecfbfe89de80a738c9f243ed7a8805969b` |
| Trust | `054e08157458ca179db2b916ae101d8540c573a4d544824dcb7925b63c92553b` |
| Fresh capsule | `002daa797a7696efbc183475f3b523165eff456f45c783680b0313900190b78c` |
| Initial canonical preflight | `d52a561a621c52be752cfd5e6824b5b7239cc089466e9ad4963f74e6c614e2f6` |
| Preparation source | `354cfcdeac9003708e3d706c7a44dfbb83ca679be2c8a89e93620d4e97ee02e1` |
| Native root transport | `16f14a3f35d6f224987e925717269dd60f0d35b32cc85a92f98a3832a15aabab` |
| Outer observation | `d1a65cb0ecd1c5b194cda071e1a39c80cd6a9eb1bbb1d5ee9ec8f7ab3d58e2fe` |
| Old consumed claim | `8a1185254bc199ee4f081c2965f16fd24589b1a2fb50877ae02e4b8c784e1a6d` |
| New launch claim | `411c2e829e63f9bf6653999dca96c6393421e03424de175be051d0badd6902d8` |
| Global seq04 dispatch claim | `79322ea623ada3c552b105ff2ce5aa1cf342f2da5f0fbf14134ae9b08ffa490b` |
| Primary offline execution failure audit | `2958d8fd0b1451b6f18f055d03211201398a3a880b576d9834fc6a1199eb70d5` |
| Independent execution failure audit | `2b7736e3070fa4a48424aefb4caca3accccdbbb7c17a1bbdd95234874d15db3a` |

A future attempt requires an additive reviewed recovery procedure and separate
authorization. Neither transport correction nor another launch is included in
this completed attempt. STOP remains in force.
