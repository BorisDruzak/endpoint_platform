# Windows 189 fleet results and Setup 190 inventory delivery

## First Windows 189 wave

Production policy 17 reached three APPLIED Foundation 187-to-189 assignments. The read at 11:26Z confirmed ready Core/Foundation 189, observer 1.0.8, live WSS, fresh UserSensor and Support 1.1.4 on each PC. Existing Support grants had expired. Those component reports establish readiness of the service and its version. They do not establish administrator SSH on the three workstations.

| Address | Setup assignment | Accepted UTC | Native exit | Stable seconds | UserSensor |
| --- | --- | --- | ---: | ---: | ---: |
| 192.168.101.27 | `483c563c-7506-4744-a4f2-54d478799fad` | 10:56:40 | 0 | 181.907 | 1 |
| 192.168.101.22 | `32dd3744-a022-4146-a797-55dc94e49e3a` | 10:56:56 | 0 | 182.790 | 1 |
| 192.168.101.29 | `3db4ea84-0722-434d-bb80-34db14266783` | 11:04:50 | 0 | 181.639 | 1 |

## Native inventory release

Full Setup 190 carries the eight-second Windows CIM inventory budget from `77c5a3526f9297bda04c4e02b12d30a407599e3e`. The existing Core-only trial required temporary administrative access to its OTA directory on test120. The native release uses the existing Setup update controller and observer. Test120 already runs the fixed Core 190 with Foundation 189. Its existing 190 version directory cannot be assumed available for a distinct native 190 payload.

The release uses frozen runtime source `e453348935be155f7112640640449603d7f4901d` and native packaging `70ad18dfb0e3ca22c021094fe4c981618b7380ec`. Focused Python 3.12 context and Windows profile tests passed, 60 passed with three skipped. The executable, MSI and embedded Support signatures validated with timestamps. Frozen inventory and version modules matched the bound source. Support remains 1.1.4 with the serviced Windows OpenSSH profile and the existing signed observer 1.0.8.

Production registered the immutable Setup 190 candidate and its Full Setup release. Capacity for two downloads was recovered by archiving the obsolete 172 upload pair from `/tmp` after verifying the local originals and actual served 172 artifact. The off-host archive SHA256 is `4612619a8c68df826e0ce25b679940575838cf833ccd0bf5aa5982d981485bdd`. Publication left 549642240 bytes available and unmounted the temporary RAM staging area.

At 11:34:17Z the authenticated production Console assigned Setup 190 on 192.168.101.27 (A2-MUNSLU-N), using exact Foundation/Core 189 and observer 1.0.8. After native acceptance and a fresh complete inventory, Console created qualification `d4a0b921-64a8-4982-ab7d-23b43dc1b08a` for Foundation 189 through 2026-12-11T11:42:19Z. It then assigned the same signed Setup to 192.168.101.22 and 192.168.101.29. The three workstations completed without manual file, ACL, or service preparation.

| Address | Setup 190 assignment | Accepted UTC | Native exit | Stable seconds | Fresh inventory observed UTC |
| --- | --- | --- | ---: | ---: | --- |
| 192.168.101.27 | `3a58c2b4-2bd2-4792-9133-6c9ea56486eb` | 11:41:10 | 0 | 182.025 | 11:41:35 |
| 192.168.101.22 | `d05e85c3-302e-496b-8d5d-94245ca9ab8a` | 11:49:27 | 0 | 182.850 | 11:49:45 |
| 192.168.101.29 | `95354561-2705-4420-a0a0-443aac2eae1a` | 11:50:17 | 0 | 181.496 | 11:50:51 |

The post-install inventory on each workstation reported Windows x86_64 and no warnings. Each native proof recorded a genuine UserSensor, verified services and restored companions. Subsequent live reads confirmed fresh telemetry and Support 1.1.4. The assignments cover the three nominal 189-source workstations. Test120 retains the already tested Core 190 inventory fix. Policy 17 remains the 187-to-189 automatic campaign, and the published Windows enrollment download remains 177. Older Windows Foundations still require an exact-source qualification for Setup 190.
