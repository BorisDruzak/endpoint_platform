# Endpoint test-registration audit

Read-only audit on2026-11-05. No device was retired, disconnected, uninstalled,
deleted or had its credential revoked. The user requested identifying test agents;
the separately authorized update is only A2-INFAN-N/192.168.101.29.

## Evidence and confidence

Checked all21 non-retired Device records against latest authenticated instances
and WSS sessions, enrollment requests/campaigns, validated inventory snapshots,
pending Core/native operations and existing release/acceptance reports. Names,
historical IP addresses, virtual hardware, offline state and the absence of a
WorkTime binding do not alone establish a disposable test registration.

At04:24Z,11 devices had current connections and10 were offline. Every non-retired
record still had one valid credential. No current WorkTime activity bindings were
present; that does not prove the absence of production or external dependencies.

## Confirmed test lineage: old registrations recommended for retirement

These four are older registrations of the dedicated Windows acceptance lineage
DESKTOP-2EVR855, historically192.168.101.187. Three inventory snapshots share QEMU
hardware UUID3C3CCCC0-5151-4F4B-9787-BD2E47B7ED69 with the currently connected test
registration. The79 registration has matching enrollment hostname and the dedicated
VM123 acceptance campaign; no hardware UUID is retained in its latest snapshot.
The canonical acceptance report documents VM123 as a dedicated test environment.
All four have closed WSS sessions, no current Core target/native chain and no
nonterminal Endpoint operation at audit time. Historical failed recovery evidence
must remain intact even after server-side retirement.

| Device UUID | Historical label | Last seen UTC | Recommendation |
| --- | --- | --- | --- |
| a2da1090-c7e7-40e7-bc75-82cfef05a810 | VM123 Agent3.2.92 acceptance | 2026-10-14 14:24 | Retire old registration; preserve history |
| 9c7a7cb2-93a9-4ab8-a3b0-4cd8fdd0f683 | VM123 independent3.2.79 acceptance | 2026-10-23 14:27 | Retire old registration; preserve quarantined native evidence |
| d72fda38-f2cf-4bd9-ae47-a2c47021f8b8 | VM123 independent3.2.81 acceptance | 2026-10-19 08:57 | Retire old registration; preserve history |
| cb5851bd-fe70-48fc-ab7e-6afa44c9a7fa | VM123 independent3.2.118 acceptance | 2026-10-17 14:40 | Retire old registration; preserve history |

Retirement here means a separately authorized, audited withdrawal of that exact
Device/credential, retaining snapshots, operations and immutable receipts. It is
not deletion of a VM, its disks, local installation or recovery journals. Never
target an old IP address instead of the exact Device UUID.

## Confirmed test devices still connected

| Device UUID | Current identity/address | Recommendation |
| --- | --- | --- |
| d3ed13cd-1b40-4ccc-b035-240a184cf247 | DESKTOP-2EVR855,192.168.101.187; QEMU UUID matches acceptance lineage; Core/Foundation158 | Keep as current Windows acceptance reference unless intentionally ending its use |
| 943c87ef-f121-40b9-a31f-003e9459e292 | DESKTOP-9ST5HO2,192.168.101.120; QEMU UUIDE9AA6F83-BECE-40F6-AEFE-53D61DA5A675 | Keep as full Setup/UserSensor canary unless intentionally ending its use |

Both are proven tests and have no pending Endpoint native/Core operation at this
audit. Their retirement would stop their future Endpoint testing/telemetry. This
audit does not retire either one.

## Keep: workplace/operator identities despite test-sounding labels

| Address | Validated inventory hostname | Why not classified as disposable |
| --- | --- | --- |
| 192.168.100.1 | ADMIN-2 | Operator workstation; labelWindows local MSI pilot |
| 192.168.101.29 | A2-INFAN-N | Real original affected PC; labelTemporary installer150; current authorized update |
| 192.168.101.144 | A1-OHTRUD-S1W | Workplace PC in verified production158 rollout |
| 192.168.101.27 | A2-MUNSLU-N | Workplace PC in verified production158 rollout |
| 192.168.101.170 | C1-MUNZAK-S2 | Workplace PC in verified production158 rollout |
| 192.168.101.207 | A2-PRIEMN-S1 | Workplace PC in verified production158 rollout |
| 192.168.101.22 | A2-IAO | Workplace PC in verified production158 rollout |
| 192.168.101.2 | MUNSLU-S2 | Workplace PC in verified production158 rollout |
| Historical192.168.101.69 | B2-KDN-S2 | Physical workplace identity; offline does not make it a test |
| 192.168.101.210 | alt-arh1-pc1.sosnadmin.local | Physical ALT workplace/native singleton; acceptance label is not test-only ownership |

## Insufficient proof: do not retire on this audit

| Device UUID | Historical address/label | Remaining evidence gap |
| --- | --- | --- |
| 3139e3ba-29c0-4575-8e2d-ce16433ad564 | .77,ALT KDE reference parity; alt-t2-pc133.sosnadmin.local,QEMU | Likely reference VM, but disposable ownership not independently established; one pending Core target |
| 853d3c7b-23a8-4812-854c-0093a824c475 | .162,ALT test pilot | Dedicated test host uses this address in project instructions, but this old Device lacks fingerprint continuity; pending Core target |
| d283a42e-2781-4398-a345-1fa81b751705 | .81,Ansible ALT rollout | No validated hardware identity/purpose; pending Core target |
| b23db6ad-1e21-4d99-a4b8-5ae0861398ad | .56,Ansible ALT rollout alt-a1-pc2 | No validated hardware identity/purpose; pending Core target |
| d15b50bb-7f4b-4900-a02e-f91a11fa3ef4 | .70,Production ALT cutover canary | No disposable ownership proof; pending Core target and explicit production label |

Pending operations must be reviewed through their canonical controller before a
later decommission decision. None were cancelled or relabelled by this audit.

## Sources

- Current Endpoint PostgreSQL inventory, enrollment, instance/session and operation
  metadata, read-only04:24–04:25Z. Operator receipt:
  `C:\Temp\endpoint-test29-20261105\device-identity-audit.txt`.
- [Dedicated VM123 acceptance](../superpowers/reports/2026-10-13-agent-3.2.82-final-acceptance.md).
- [Production158 rollout](2026-10-27-agent158-fleet-rollout.md).
- [Original A2-INFAN-N repair scope](../superpowers/specs/2026-10-26-installer-owner-recovery-design.md).
- [Test120 full Setup/UserSensor acceptance](2026-11-04-test120-usersensor156-full158.md).
