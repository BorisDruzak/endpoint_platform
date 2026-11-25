# STAB-15 Windows production-primary 3.2.205 to 3.2.262

One isolated Windows 10 Enterprise Evaluation x64 guest, build 19045, ran the exact **production-primary** Setup wrapper 3.2.205 against a clean lab database. VM126, VM206 and the production canary were outside the trial. The approved PBS-restored Gateway (VM227) retained the exact hostname/TLS chain inside closed `vmbr226`, with only the trial guests connected, no default routes and no production database connection.

The normal local administrator and QGA were verified before enrollment. One official Microsoft activation from distinct restricted egress changed SPP from `5 / 0` to `1 / 129600 minutes`. That egress was removed before accessing the lab bridge. The user-authorized local administrator credential was saved under the workstation's Windows Credential Manager and verified with one normal interactive logon check.

| Input | Source | SHA-256 |
|---|---|---|
| Setup 3.2.205 | `f0d1d7cf2f9b59052f35bd0ba0188f8e49cc9649` | `e4acd9c00630b1c468a1b4d8ab1db07134d9160fa07b3cd3036f6c51692bef4a` |
| MSI 3.2.205 | same | `689e1d9dc0dcbd0e1943e98f27cfa88cc36fe99dbf9316e58e54d4292a1fc26f` |
| Setup 3.2.262 | `8e9976fecf9cfa9ae7e88f2d820df0e93aedaf0b` | `a4a918c5270ed3f322157240612af0d3138540e7ace56ecfa8a3836fc7f5fb33` |
| MSI 3.2.262 | same | `c7e3fb223363b009555248a797ea09214bea3857d5ef866d4a2040d2c1544cd2` |

The initial native Setup exited 0. The sole card `5e0fea60-f1cd-4003-ba34-02b60b9bb446` received ACK1 on .205 and had a fresh .205 WSS and READY Observer 1.0.11. The source executable matched the exact embedded Core even though that historical inner executable reported `NotSigned` when checked alone. The signed outer wrapper and MSI, including the embedded package's distinct provenance, were checked separately. A stopped, link-down source snapshot `226/primary205-accepted-offline` was paired with the private lab PG dump, 550,809 bytes, SHA-256 `3a3145fc2c40bd7d5988c7af638bbecf79afdf14095f259abd3c5b40a5fa8d12`. The dump passed TOC inspection and full decode, and is retained under restricted access outside git and the evidence ZIP.

The same VM resumed in the closed lab. A single standard .262 assignment `b33c6589-4635-4ea4-887d-09a2b4388e98` created attempt `2ff95743-0dac-4d05-a285-35fac435fb2b`. The provider observed the downloaded artifact verified and installing at 20:04:17 UTC.

## Direct update and service verification

The normal assignment downloaded 177,713,056 bytes with HTTP 200 and used native operation `d4f49d5b-a060-4a18-a9ca-6c2da24171e6`. The local result was `UPDATED / SERVICE / SERVICE_RUNNING / 0` at 20:09:06.066 UTC. The journal entered `accepted`, sequence 5. Windows cached one exact .262 MSI and ran one exact .262 Core under the automatic service. The signed Setup and MSI establish package provenance. Authenticode on the installed inner .262 Core alone reported `NotSigned` and its SHA-256 matched the sealed build. Four protected identity inputs kept the same file IDs, security descriptors and bytes. The aggregate SHA-256 was `06482f0e290ff4cf0338fa23680dbf4e74ea87b20f49cec549af0cf419563d18`.

Gateway accepted ACK2 `64a0643e-cc9e-52c9-b667-3bd5b8623bb1` for the exact .262 MSI and native exit 0. The single assignment moved from `verifying` at 20:09:07.177 UTC to `applied / setup_post_restart_confirmed` at 20:12:20.131 UTC, about 193 seconds on the server clock. The original card and sole credential remained. Fresh .262 WSS `8b6b2a1a-fa0c-4b68-b2c1-615ffebec9f4` opened at 20:07:37.541 UTC and had a heartbeat at 20:12:37.830 UTC. The sole normal `health_v1` collection `0d8b39f4-a9f8-4841-9e08-7d465f989d41` was acknowledged on that WSS at 20:12:59.653 UTC and completed successfully at 20:13:01.012 UTC, with one delivery and one successful result. Stock Observer 1.0.13 reported READY on .262 Foundation and Core at 20:13:09.087 UTC. This was a service transition during Setup. The OS stayed in the same boot throughout the assignment and the health check.

## Receipts and retained fixture

The portable archive `C:/endpoint-platform-wix-build/stab15-win205-to262-226/stab15-windows-primary205-to-262-evidence.zip` has SHA-256 `947938a2322608897a3d3f166a437c9f59e42ee066ea7be6569129ac68476611`. All 33 receipt hashes and the ZIP CRC passed. The final matched lab DB dump (ACK2 and health) is kept separately under restricted access, 557,547 bytes, SHA-256 `9900837dd6cfcb9a9fca40f306d65b0f61d3bed46a2ebe57099fd1793d141f6a`.

VM226 shut down normally at 20:13:51 UTC. Its current config has no network interface configured and all three CD-ROM slots are empty. It retains only `local-lvm:vm-226-disk-1` (40 GiB) and its `primary205-accepted-offline` snapshot. The unused first disk was removed after a repeated cluster reference and LVM origin check. Three detached temporary ISOs, hypervisor staging scratch and the temporary Internet egress were removed. The lab Gateway VM227 and isolated bridge were removed after exporting its DB checkpoints. The retained source snapshot carries a disabled link to that retired bridge. For any later online trial, restore only the paired lab database and build a closed network before enabling a link. No production publication or deployment was part of this run.

## UserSensor evidence in the two database checkpoints

The .205 checkpoint contained one installation event and the final .262 checkpoint contained two. Both had zero rows in `policy_assignments`, `policy_device_states`, `policy_applications` and `policy_sensor_health_current`. The read-only check matched each archive to the SHA-256 above and counted the COPY records for those five tables. The counts establish that this trial supplied no Gateway evidence for an interactive UserSensor sample. They do not establish whether the companion process ran on the guest. [Checkpoint counts](C:/endpoint-platform-wix-build/stab15-win262-prod205-lab/vm226-policy-checkpoint-counts.json) (SHA-256 `1a7ac0572ae61c5d8344518c701b207e457601a5bf23b1fb1a006fb629ffb14b`).

For a trial that includes UserSensor, assign an activity-enabled policy to the single lab device and verify its application before an ordinary interactive logon. On the candidate WSS, check that the listener reports `READY` and that both `user_sensor_last_seen_at` and the Gateway receipt time are fresh for that logon. The full Setup qualification checks those timestamps within 150 seconds and allows up to 30 seconds of positive clock skew. [Qualification checks](../../endpoint_server/setup_updates/policy.py)
