# STAB-15 exact ALT native rollback 3.2.249 → 3.2.248

**Passed** on ALT Workstation K 11.4 x86_64. Disposable VM196 used one NIC on closed bridge vmbr144, no default guest route, and one new card in a separate lab Gateway database. The Gateway's normal native release verifier admitted both signed sources. The device initially installed 3.2.249 by native Setup, then registered with one manual approval, reached ACK 1 and established WSS on 3.2.249.

| Version | Source revision | Native kit SHA-256 | Setup SHA-256 |
|---|---|---|---|
| 3.2.249 | `8a82b96ffa29994283b16d5b15afbc255d3cc469` | `8ceb7cae4b0abb112071a1af8c934b3693507a9de2a6c668d2e479d1a52e6bda` | `a34bf7706e70c5390d94942b8640e4fde2dae231e5dda44cc68b50a15fd42af1` |
| 3.2.248 | `7bd7086a4650c9c9abd2218b2b9bbd0633235302` | `1d48569c8a8f45eb8213caffa8851c3d66ec24f62460d22c370c6daf042cc16e` | `9c6fefca444bfdf70bb4cd930c842c2e1a70bd420f4f1110b1faf4e14fb09f64` |

The Setup from each kit matched the bytes embedded in its signed Core RPM. The ordinary `upgrade` uses `rpm -U --oldpackage` after validating the signed Core and UserSensor pair and binding the exact Setup executable to the target Core RPM. The runbook's separately documented exact 3.2.156 manifest adapter covers the historical source that predates this binding.

One execution of the unchanged **3.2.248** kit's Setup `upgrade` with its exact Core and UserSensor RPMs and pinned publisher key completed with outer exit 0 and native exit 0. Both 3.2.248 RPMs passed `rpm -V` immediately and after a full guest reboot. The device UUID and journal generation stayed the same. The four retained files (configuration, CA, credential and enrollment identity) preserved their hashes, ownership and modes across the transaction and reboot. The local intent was `upgrade`. Gateway stored the resulting sequence 2 as `installed`, acknowledged it, and showed one device and exactly two installation events. The lab Gateway showed zero OTA targets and reports.

After the boot ID changed, Core, Support and update path were active, the same card preserved ACK 2 and runtime-ready, and a fresh 3.2.248 WSS session `25e7d25c-0bcc-4d97-a4d6-55d5760b3bf6` appeared at 00:57:16 UTC.

Removed the disposable VM and disk, PVE staging and the dedicated Gateway processes, database, scratch and IP alias. Source VM132 remained stopped and all three original VM142 services remained active. Signed workstation kit bytes were retained. Workstation receipt manifest SHA-256 is `c96c958a926bdbe1a8959a2d681de54055506ddf9534563be937147cfeb3c597`.
