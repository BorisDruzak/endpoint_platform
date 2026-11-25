# Signed Setup169 candidate

169 is prepared for the next controlled test. It is not native-qualified,
enrollment-promoted, fleet-enabled or assigned to any workstation.

Runtime source4525435f1345e0d44253948f2867a0a099475f6b;
native packaging982b84181486a28e9b351947ca665323cdeae2d8.
Binding `packaging/windows/initial-runtime-3.2.169.json`.
Producer `C:\endpoint-platform-wix-build\setup169-4525435`.
Initial runtime119 files/tree20434630595dc71d5a97b2aa8c73638921025e71e67ad8ca4909f7926bb1f3ec,
280 exact committed source inputs, component220A91EB-0942-59DC-B931-844B15D31F6E.
Frozen runtime and all native helpers were rebuilt; none were reused.

| Artifact | SHA256 | Bytes |
| --- | --- | --- |
| EndpointAgentSetup-3.2.169-x64.exe | 7dce65e273a2b96432b7ca57eb7b38a01cebe1bce7246fab22c7cff0777fb4b1 | 146246784 |
| EndpointAgent-3.2.169-x64.msi | 07a01d95af8f4b65dd1b0f763d4ada5d83cc41068002077ebd6ed590b88a8301 | 104431616 |

EXE and MSI signatures Valid and timestamped, publisher
4D4C23389F5FF77BC4EB32044761019EAE8FB776. Exact source fix bytecode was checked in
the packaged native helper, including parent namespace validation before mkdir.
Both Core and helper contain the canonical trial-selector serializer; immutable
grant validation is unchanged. Native helperf912e92587dfb88d35282e8d968cecd8c0891e940f5b89d3d20f30687c4cec3e,
438 modules/112 members, build tools absent. Signed observer remains1.0.6/f6359376cac7f5a5de6476ed9c41ea652fb95fe7e64c285d1ff2eaa8f6b0b069.

Server copies were published atomically with root:endpoint-platform0640 and
rehash verification. Canonical audited registration produced Setup release
dee3a7c6-c758-47fc-beca-f01f8d7c7ef3. It created no enrollment registry row,
qualification or assignment. Fleet revision3/all_active/max_parallel2 stayed
disabled; existing enrollment download165 and AUTO campaign were unchanged.
Server remains75adbf4b414fb5e9d65622a5b0b32a6f6f1c7dc4/schema0045.

Additional source/build commits:

| Commit | Message | Files / verification |
| --- | --- | --- |
| 975f4c36638a677981deadb0fc2bddaa96e6b833 | docs(updates): record native168 acceptance and cold observer failure | AGENTS, current/168 records, native168 evidence; complete diff, JSON validation, diff check |
| 4525435f1345e0d44253948f2867a0a099475f6b | build(agent): stage full Setup3.2.169 observer provisioning fix | version.py;50 packaging tests passed |
| 982b84181486a28e9b351947ca665323cdeae2d8 | build(windows): bind Setup169 to corrected observer provisioning | AGENTS, current/169 records and binding;40 packaging tests,280 source inputs and119 payload files verified |

The observer mkdir fix itself is d7304706263f1427b6ed267e66661a3989ecf8d6;
178 focused Windows tests passed before its commit. Independent review found no
material issue. Full native build, MSI payload verification, source-bound archive
inspection and signatures passed. No push/PR and no native169 acceptance claimed.

146 is independently healthy on168: at14:04:14Z both components168, original168
jobAPPLIED, policyAPPLIED, UserSensor14:03:25Z and real Activity14:04:10Z. This
does not accept168's failed cold provisioning path, nor169's future live test.

27 and120 retain their original accepted-native exit21 holds. A scoped one-off
repair is prepared separately for review; it is not part of169 and is not
authorized by this artifact. It may create only the missing protected1.0.6
directory and, on120, normalize the exact same selector back to its original
grant-bound byte order, then invoke the original cached native recovery mode.
It must not replay MSI, replace grants/captures, rewrite private data, or claim
native0/APPLIED. Server reconciliation of original failed jobs remains a separate
gate after real recovery and fresh telemetry. The general future recovery design
must preserve native outcome separately from post-native companion/update-client
completion and retain an audited failed/recovered history.

The outgoing independent support tunnel is still design-only and not shipped.
