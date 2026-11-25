# STAB-15 — Windows Setup 3.2.264 after power loss

The signed candidate underwent two separate power-loss tests on isolated Windows 10 Enterprise Evaluation 19045 x64 full clones of VM143’s `pre-stab206-native` snapshot, both starting with healthy 3.2.192. The clones had no virtual NIC or external route. Each test ran its own exact signed Setup once.

The local Windows release gate on source `ffa9178a70d799512793a0cc8c8fe682cf802357` passed with 3029 tests and 4 skips. The first gate at `b6218d4d` failed on 15 older fixture expectations. The final commit changed only those fixtures. Setup and MSI passed Authenticode with a timestamp under publisher `4D4C23389F5FF77BC4EB32044761019EAE8FB776`. The embedded MSI matched the standalone artifact and Observer 1.0.13 retained the exact signed 3.2.245 bytes. The [candidate record](../releases/windows-3.2.264-candidate.json) lists hashes and the Windows gate, build and evidence index paths.

## VM243 — power loss during an open compound MSI transaction

Before the cut, operation `6d37c85e-5e97-4fd7-becc-33efb38c45cd` was at `switching` sequence 2. Its child fence was at `msi-executing` sequence 2, both deferred-helper phase receipts were complete, and Windows Installer had recorded the compound transaction opening (1040, record 13162). Native attempt `09db3110-b4a1-45f0-8e3c-304f1618db07` had no exit receipt. PVE confirmed the power cut at 04:18:51.707Z on 19 November.

On cold boot the stock recovery task returned **21** and retained the same stage, attempt, child fence and upgrade pointer bytes. User32 event 1074 record 1625 confirmed the subsequent ordinary Windows Restart. The task was observed running during the second boot and subsequently Ready with result **21**. The same four protected hashes matched again. No MSI events in the monitored set appeared after either boot. The lab guest clock was about five hours ahead of PVE UTC. Its observed boot times were 09:19:01.500 and 09:25:30.500 on that clock.

The original signed 3.2.192 cached MSI, private-four aggregate (bytes, file IDs and ACLs), and original lifecycle entries remained unchanged. After both held boots the selector and original selected Core path were absent. Core, Updater and BrowserPolicy were Disabled/Stopped and independent Support remained Auto/Running. The operation still needed native outcome evidence before recovery could proceed.

## VM244 — power loss after preparation, before native MSI

Before PVE confirmed power-off at 04:32:01.684Z, two matched read-only witnesses showed operation `1a539ac4-7849-4349-b3b2-5f8aa84c2095` at `prepared` sequence 1 with the same stage hash. The boot task was present in both Scheduler and TaskCache. The Task file was present, the MSI transaction watermark stayed at 12173, and no native attempt or fence existed. The process-start and sentinel checks excluded a new MSI client at that point.

The stock boot task cancelled the same preparation to `rolled-back` sequence 2 with `preparation_cancelled` and wrote `ROLLED_BACK`, code 67, to the Setup result receipt. The task was removed, and the terminal journal had no attempt, fence or selector switch. The source Core .192 ran with its original selector, signed MSI cache, private-four aggregate and service profiles. The only post-boot MSI events were the empty settlement pair 1040/1042, records 13071/13072, from a single client. Neither event referred to a product transaction.

## Cleanup

PVE verified removal of both disposable VMs, their dedicated disks and ISO media. VM143 remained stopped and its source snapshot remained present.

## Scope

The tests exercised native Windows Recovery Task behavior for one legacy source and exact signed candidate bytes. Windows 11, Windows Server, online recovery and real workstations remain outside this evidence.
