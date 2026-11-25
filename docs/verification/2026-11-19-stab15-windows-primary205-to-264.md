# STAB-15 Windows primary 3.2.205 to 3.2.264

One normal .205 → .264 Setup assignment passed on Windows 10 Enterprise Evaluation x64 build 19045. The native outcome was 0, with ACK2, fresh WSS and a successful health collection on the same card. One genuine interactive UserSensor was restored in the same Windows desktop session and supplied a fresh sample. The isolated Gateway accepted the exact .205 source profile through its standard qualification API. The qualification existed only in the disposable lab database.

## Exact inputs and isolation

| Input | Source revision | SHA-256 |
| --- | --- | --- |
| Production-primary .205 Setup (catalog source commit) | `c9a46030b77109d7462651e934f0f798af685409` | `e4acd9c00630b1c468a1b4d8ab1db07134d9160fa07b3cd3036f6c51692bef4a` |
| Installed .205 MSI | `f0d1d7cf2f9b59052f35bd0ba0188f8e49cc9649` | `689e1d9dc0dcbd0e1943e98f27cfa88cc36fe99dbf9316e58e54d4292a1fc26f` |
| Signed .264 Setup | `ffa9178a70d799512793a0cc8c8fe682cf802357` | `7c278545e6ea37e38f55d9aa954c2622f5767aba789f225551c8fb445e1749a4` |
| Signed .264 MSI | same | `f05bd0a67375015e21b39ae25e778baacd609acb91d4d076e1f6d8e11c9c7539` |

VM245 was a full independent clone of stopped VM226 at `primary205-accepted-offline`. The paired ACK1 lab checkpoint matched SHA-256 `3a3145fc2c40bd7d5988c7af638bbecf79afdf14095f259abd3c5b40a5fa8d12`. The test observed active Evaluation, remaining grace and working QGA before assigning an update.

The authorized PBS volume `vm/115/2026-11-17T23:00:12Z` was restored into VM246 without a NIC. Original network configuration and original application, worker, Nginx and PostgreSQL services were disabled offline before the first boot. Only the paired lab checkpoint was loaded in a new Unix-socket-only database. The trial Gateway services used that socket and the original hostname TLS key stayed inside VM246. The sole copied lab operator credential was rotated inside the disposable database for ordinary API authentication. The closed `vmbr226` had exactly the VM245 and VM246 TAPs, no global bridge address and no uplink. Both guests had zero IPv4 and IPv6 default routes, and the client had no external DNS. The exact hostname passed TLS health over the private link before the assignment. VM226 remained stopped.

## Native and functional evidence

- The lab reconciled the original card `5e0fea60-f1cd-4003-ba34-02b60b9bb446`, ACK1, exact .205 Core and cached MSI, and ready Observer 1.0.11. The activity-enabled policy was applied before the trial logon. Before the assignment, VM245 was configured to prompt for a username and restarted so the operator could sign in with the restricted lab account. After that restart, policy ACK was recorded at 05:07:45.403 UTC.
- An ordinary operator logon opened desktop session 1 at 05:11:37.314 UTC. The installed .205 UserSensor reported sample 05:12:32.276 UTC, received at 05:12:45.612 UTC. The activity listener was READY. Evidence contains process identity, session, times and hashes.
- At 05:13:07.679 UTC the normal admin API created sole assignment `d21e80b7-40d7-485c-98c6-70393f5b2b84`, bound to .205 Foundation/Core and Observer 1.0.11. The exact Setup download returned HTTP 200 and 177,728,264 bytes. Attempt `1e9e5b6d-5b1c-4baa-9019-f1d801b3c6a4` ran native operation `1aae06c7-854d-4629-8a4f-db5f2d1781f4`. The local Setup result was `UPDATED / SERVICE / SERVICE_RUNNING / 0` and the protected journal reached `accepted`, sequence 5. One .264 cached MSI matched the signed candidate's recorded hash. The single running Core matched the sealed package. The four identity inputs retained matching file IDs, security descriptors and bytes.
- New .264 WSS `6ce0cca7-9ced-4eb7-8be7-c7212e13ba78` opened at 05:17:38.214 UTC on the original card. The Gateway received ACK2 `75a94d79-d800-5260-9512-2735e5734294` at 05:18:56.435 UTC, exact .264 MSI and native exit 0. At 05:22:18.431 UTC the assignment reached `applied / setup_post_restart_confirmed`. Its native proof recorded 182.148 seconds of connected soak, six samples, one Sensor, stable services and stable companions. The source and target were observed in the same OS boot.
- The exact target UserSensor hash `bdbcdf4b4cbabed1fea44f0aca0b656875b122035fcaa60dcc06972ceeed58e3` and exact target tray hash `acded19eb179d51df09f226b80ebbb32b4587c742781aac5f96bae625b9d6445` were observed in desktop session 1 after native acceptance. The applied policy reported READY and a fresh sample at 05:22:35.001 UTC, received 05:22:38.839 UTC. The sole `health_v1` collection `462ecda6-0fc4-42ef-86c9-7b480c511f4c` completed successfully at 05:22:40.141 UTC, with one delivery and one result on the new .264 WSS.
- Stock Observer 1.0.13 reported READY with .264 Foundation/Core at 05:23:05.019 UTC. The standard lab API qualified the exact release against the .205 source profile at 05:23:16.353 UTC, HTTP 200, qualification `288f96fc-1932-4d97-b120-6e8108dbaf46`. The final census showed one card, one active credential, two installation events, one assignment, zero fleet policy rows and zero target enrollment campaigns. Support Access was absent in both local censuses for this profile.

## Receipts and cleanup

The portable archive contains 38 receipts and an internal SHA-256 index. The verifier checked the exact inputs, policy-to-logon ordering, native result, ACK order, preserved identity, same-session health and exact-source qualification. Archive CRC and all 38 receipt digests passed. SHA-256 `6fd314b9a3fd74cd4c63616d2b2358d438da6f15223ebed356b47a6a4e2fe788`. [Archive](C:/endpoint-platform-wix-build/stab15-win264-prod205-lab/win205-to264-native-evidence.zip) · [Archive digest](C:/endpoint-platform-wix-build/stab15-win264-prod205-lab/archive.sha256) · [Verified result](C:/endpoint-platform-wix-build/stab15-win264-prod205-lab/verified-native264.json)

After evidence verification, both disposable guests and their disks, the private server database, closed bridge and scratch were removed. A separate final check confirmed VM226 remains stopped with its original disk and .205 source snapshot. [Cleanup check](C:/endpoint-platform-wix-build/stab15-win264-prod205-lab/cleanup-checked.log)
