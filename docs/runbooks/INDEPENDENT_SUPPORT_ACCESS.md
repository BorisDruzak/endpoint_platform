# Independent Windows support access

For published native Linux Setup183/Support1.0.0 use the separate
[Linux native Setup workflow](LINUX_NATIVE_SETUP.md#console-enrollment-and-independent-linux-access),
including exact Linux username/UID and install/remove/reconcile commands. The
Windows fields, primary release and procedures below remain unchanged.

This is a separate support channel for diagnosing an enrolled Windows device
when Core, EndpointAgentUpdater or EndpointSetupUpdater is unavailable. Ordinary
software updates still use the signed full Setup workflow. Installing a component,
enabling policy, establishing a tunnel and verifying administrator access are
different states; a connected tunnel alone is not successful administrator access.

## Подключение при неработающем агенте или обновляторе

Служба `EndpointSupportAccess` устанавливается и запускается автоматически,
имеет тип запуска Auto и работает независимо от Core и задачи обновления.
Она сама обращается к Endpoint; команда включения доступа через сломанный агент
не требуется. Windows, сеть и сервер Endpoint/SSH-шлюз должны работать.

1. Откройте `https://endpoint.sosnadmin.local/admin/devices`, выберите нужный ПК
   по имени и Device UUID, затем раздел **Доступ поддержки**. Карточка доступна
   и при состоянии основного агента «не в сети».
2. Проверьте компонент, свежесть его собственного отчёта и срок политики.
   После установки с настроенными серверными defaults разрешение включается
   автоматически после первого успешного отчёта Support1.0.1, на8часов.
   Повторная регистрация не продлевает этот срок. Явные настройки, отключение,
   отзыв или сброс конкретного ПК имеют приоритет. Если срок закончился,
   задайте срок до8часов, существующего администратора, одобренный публичный
   Ed25519-ключ и причину, затем нажмите **Включить доступ**. Для доменных ПК
   используется `SOSNADM\admin-2`; после чистой установки тестовый120 тоже
   использует эту доменную учётную запись. Для автономного ПК
   укажите его действующего администратора; аккаунт и пароль не создаются.
3. Нажмите **Обновить доступ**, дождитесь свежего отчёта и подключения туннеля.
   Скопируйте из этой же карточки Device UUID, **Порт устройства на шлюзе**
   и **SSH-ключ устройства, привязанный к Device UUID**. Поля относятся к одному
   ПК и не должны смешиваться с данными другой карточки.
4. С операторского Windows-ПК используйте проверенный SSH-ключ и существующий
   alias `endpoint-platform-server`. Он ведёт на обычный администраторский SSH
   сервера Endpoint. Порт2222 из карточки используется исходящим соединением
   самого устройства, а не входом оператора.

Из корня репозитория в PowerShell (пример для тестового120; `$hostKey` копируется
из актуальной аутентифицированной карточки, не из сканирования порта):

```powershell
$hostKey = 'ssh-ed25519 <ключ из карточки нужного Device UUID>'
.\tools\support\Connect-EndpointSupport.ps1 `
  -DeviceId 'c87eaa22-4fd1-4830-bc11-88142afda87e' `
  -RemotePort 32009 `
  -WindowsAdminUsername 'SOSNADM\admin-2' `
  -HostPublicKey $hostKey `
  -RemoteCommand 'whoami /user'
```

Для доменного ПК замените UUID/порт/ключ на его данные, а имя входа — на
`'SOSNADM\admin-2'`. Без `-RemoteCommand` открывается PowerShell. Параметр
`-InspectOnly` проверяет и показывает команду без подключения или записи pin.
По умолчанию используется операторский `~/.ssh/id_ed25519`; иной уже одобренный
ключ задаётся через `-OperatorKeyPath`. Операторский публичный ключ в политике
должен соответствовать этому закрытому ключу; закрытые ключи никуда не копируются.

Скрипт проверяет ключ шлюза строго, сохраняет отдельный pin для Device UUID
и отказывается подключаться при его изменении. После явного сброса ключей
сначала подтвердите новую привязку в Endpoint и причину восстановления; не
перезаписывайте несовпавший pin автоматически. После входа проверьте hostname,
`whoami /user` и права, затем собирайте нужные службы и журналы. Успешный SSH
можно отметить как подтверждение оператора; «туннель подключён» не заменяет вход.

Если обычные средства диагностики не позволяют завершить порученную работу,
Codex использует этот канал и при необходимости продлевает временную политику
в рамках уже разрешённой задачи, без повторного вопроса о самом подключении.
Неработающий Core не является основанием ждать его восстановления. При этом
неизвестный результат MSI, его журналы и владелец восстановления сохраняются.

## Components and trust boundary

`EndpointSupportAccess` is a signed LocalSystem service with no dependency on
Core, the update worker or its scheduled observer. Its onefile executable lives
in `C:\Program Files\Endpoint Platform\Support\EndpointSupportAccess.exe`.
Its keys, separate CA, policy credential and configuration live in
`C:\ProgramData\Endpoint Platform\Support`. Both are siblings of Agent, with
protected SYSTEM/Administrators access. Agent identity and credentials are read
only during installer bootstrap after durable enrollment proof; service startup
does not read them.

The service runs a distinct Microsoft OpenSSH daemon at `127.0.0.1:22222` and
makes an outbound authenticated connection to `endpoint.sosnadmin.local:2222`.
The gateway's dedicated SSH daemon binds its LAN address only. It has a complete
separate configuration; the existing administrator SSH service, configuration,
keys and firewall are not changed. A root-owned broker permits each unique
`eps-<device UUID hex prefix>` account to bind only its assigned gateway loopback
port in32000..41999. No shell, TTY, agent forwarding or direct TCP forwarding is
permitted for tunnel identities. Workstation host keys are bound to Device UUID,
not inferred from hostname, IP or an unauthenticated scan.

Host keys, device tunnel keys and approved operator keys have distinct roles.
The installer generates device private keys locally; private keys and enrollment
material are never embedded in a release. The Windows login must already exist
and be an enabled administrator. The original pilot used `test_agent_win` on101.120;
the clean reinstall uses the selected existing domain principal
`SOSNADM\admin-2`, as do the other tested domain Windows devices. A bare `admin-2` must not be substituted for that
confirmed domain identity. No Windows
administrator account is created by this feature.

### Existing Windows principal in policy

`windows_admin_username` accepts an existing local SAM name such as
`test_agent_win`, or an explicit short-domain SAM principal such as
`SOSNADM\admin-2`. The bounded ASCII grammar allows letters, digits, underscore,
dot and hyphen in the SAM name; a short domain allows letters, digits, underscore
and hyphen, up to 15 characters. Both components start with a letter or digit;
the complete principal is limited to 64 characters, matching the existing
database column. Only one backslash separator is allowed. UPN, DNS aliases,
spaces, controls, wildcards and SSH configuration characters are rejected.

Explicit domain principals are normalized to lowercase in policy. The Windows
component resolves and validates the exact existing administrator SID before
configuration, and renders lowercase local or `domain_short_name\user_name`
rules as required by [Microsoft's OpenSSH configuration documentation](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration#allowgroups-allowusers-denygroups-denyusers).
The Console uses the account returned by the effective enabled policy. A disabled
policy projection hides its account and operator keys; their stored server intent
is preserved. New or disabled policy input can therefore be empty after reload:
confirm the exact existing local/domain account and approved key when enabling.

Domain policies require the matching provider contract and domain-capable
Support component 1.0.1. Existing local-name policies and the local pilot account
remain compatible; the provider does not globally require component 1.0.1.
Enabling domain policy requires a fresh independent report from an installed
running component 1.0.1 or newer. Installer registration does not advance the
observed runtime version. The running service reports its compiled version in
the optional status field `component_version`; omitted legacy reports mean
1.0.0. A stale report or an old runtime makes existing domain policy ineffective
and removes its broker lease while preserving the administrator's stored policy
and history. Local policies and disabling access remain compatible.
Installation, a resolved SID or a policy update does not replace actual
key-authenticated SSH acceptance for the selected principal.

## Policy and revocation

With explicit installation defaults, new/pristine registrations queue a disabled
15minute intent and receive one bounded initial lease after actual installed
Support1.0.1 status. Without configured defaults they stay disabled. Existing
manual policies and every disable/revoke/reset retain precedence. An administrator
with existing `updates:write` scope and valid CSRF can later enable/renew the
exact device with approved keys/account and an aware expiry of at most8hours.
There is no permanent authorization or automatic renewal on retry or heartbeat.

The component polls HTTPS with its independent `eps1` credential and the copied
CA. It requires a fresh policy after every service start. A monotonic60-second
freshness deadline bounds access during DNS/TLS/API failure; disable/revoke stops
owned SSH descendants. The unprivileged server exporter emits60-second snapshots;
the separately installed root broker reconciles them every5seconds. Missing,
invalid or stale snapshots remove authorization and terminate owned sessions.
The exporter unit uses `RuntimeDirectoryPreserve=restart` so an actual restart
retains an already-valid snapshot. Its original60second expiry remains binding;
a stopped or failed exporter cannot extend authority. An ordinary stop removes
the runtime directory, and reboot clears `/run`. Missing/stale input still
revokes access. Gateway startup clears retained keys before accepting connections. Device
retirement or source-credential revocation also removes support authority.

Disabling a policy preserves the independent credential and permits later
explicit enablement. Revocation invalidates its generation. Recovery/rebinding
requires explicit administrator authorization followed by durable authenticated
installer registration. An install retry never consumes another enrollment claim.
Historical audit is retained. The access-verification record is clearly labelled
an operator attestation: a TCP tunnel cannot promise recording of every arbitrary
shell command.

## Installation and operating-system dependencies

### Setup184 candidate / Support1.1.0

The separately registered184 candidate uses Windows-serviced OpenSSH capabilities
and the existing independent outbound tunnel. It does not contain portable SSH
executables or the Preview ZIP. Its source scope is177 forward on test120; primary
downloads and the fleet target remain177 until a separate promotion.

Preparation checks the fixed Client/Server capabilities before stopping active
Support. Missing features use only Windows FoD, without changing WSUS, GPOs or
adding download sources. An existing global SSH service/configuration/firewall is
preserved. A missing default firewall name is reserved by a disabled, operation-
bound rule before servicing; only that exact unchanged reservation may be removed.
Unknown servicing, reboot requirements and conflicts retain durable receipts.
Never replay DISM or remove the old channel to make the check pass.

The OS profile verifies the complete OpenSSH PE/helper closure, Microsoft
signatures, matching versions, hashes, protected owner/write ACLs and canonical
non-reparse paths. TrustedInstaller hardlinks shared with WinSxS are expected;
private Endpoint identity files still require a single link. Valid Windows
servicing changes are revalidated by a fixed system PowerShell query in the policy
worker. Slow validation cannot extend the main loop's60second lease. Invalid or
partial replacement closes owned SSH children and reports a dependency failure.

Activation requires a nonce/image/device/credential/dependency/PID-bound initialized
service proof. SCM Running alone cannot retire the previous signed payload.
Failed activation restores the previous compatible image/configuration while
preserving explicit credential reset/revocation. Keys and grant expiry are not
renewed by migration. The old private runtime can remain inert for compensation;
its presence does not mean it is selected.

`EndpointSupportAccess.exe --inspect-os` performs read-only validation and returns
JSON. It installs no feature, registers no service and changes no access policy.
Use the signed candidate for an exact target preflight. A successful preflight on
a host with both capabilities installed does not qualify missing-feature or
reboot-required FoD installation on that host.

### Historical Setup176/177 / Support1.0.1

Full Setup stages the signed independent helper at
`C:\Program Files\Endpoint Platform\Agent\EndpointSupportAccess.exe`.
Schema3 binds its exact bytes, MSI component/keypath and embedded uninstall
Binary in the Foundation inventory; historical schemas1/2 are unchanged.
MSI owns this staged helper, and does not own or control the active Support
executable, service or sibling directories. A native failure, unknown outcome
or staged health rollback therefore leaves the active support channel intact.
The signed Setup activates Support only after its native wrapper returns accepted
success; rollback67 and reboot results skip activation. A same-version retry
requires the ordinary no-active-operation gate. Fresh enrollment activates it
after durable identity proof and before Core starts. `--install` provisions from
the durable enrolled identity, creates private support state and registers the
independent service. Existing valid Microsoft OS OpenSSH executables may be
selected through read-only signature/version/hash checks. Setup176 does not
install Windows capabilities, run DISM, change Windows Update or change GPOs.
A fresh device without the OS server receives the exact private offline runtime
embedded in the signed Support payload.

The bundled input is the unchanged official Microsoft Win64 ZIP
[10.4.0.0p1-Preview](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/10.4.0.0p1-Preview),
SHA256`b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957`.
Upstream labels this Preview and not production-ready. Its qualification here is
for the requested testing-stage reserve channel; it does not imply vendor
production certification. A closed manifest binds all archive members, selected
runtime files, imported-library closure, sizes, hashes and Microsoft publishers.
Installer verification checks every one of its15PE signatures and timestamps
before publishing an immutable runtime slot.

Public executable code lives under
`C:\Program Files\Endpoint Platform\SupportRuntime\<version-and-digest>`:
SYSTEM/Administrators may write, and Authenticated Users have read/execute for
OpenSSH privilege separation. Private keys, credentials and configuration remain
in the separate protected Support state directory. The daemon runs directly
with `-D -e -f` and its own loopback configuration; no global SSH service,
configuration, host key, registry default shell or inbound firewall rule is
installed or modified. Normal Windows SSH authentication can create transient
virtual-account SID mappings and service-logon rights; no custom LSA plugin or
persistent global LSA configuration is installed.

The running service validates exact selected paths, recorded executable hashes
and ACLs before launch; it imports neither build helpers nor Core. A changed OS
binary or tampered bundle fails closed until signed installer revalidation.
For an existing OS-backed component whose selected OS dependency disappeared,
installation refuses profile migration before changing keys/configuration or
stopping the old service, preserving compatibility with its compensation payload.
Unknown foreign files or interrupted incompatible slot publication remain blocked.
Component errors are reported separately from native agent receipts. An unknown
Windows servicing outcome from an earlier release is preserved and never replayed.

`--uninstall` unregisters independent authority, stops/removes only its owned
service and removes only its owned payload and data. Product uninstall must execute cleanup
at native commit, so a rolled-back MSI removal cannot erase support private keys.
After known native commit, ordinary schema3 uninstall separately verifies that
the active Support executable and service are absent. Leftover or inaccessible
resources produce a separate durable `support-cleanup.json` receipt with known
native result0. After native completion and fence retirement, the authenticated
owner returns Setup68/`SUPPORT_CLEANUP_INCOMPLETE`; this is an independent
cleanup failure, not an unknown native outcome. It does not authorize another
MSI transaction or deleting a foreign service. Historical schemas1/2, major
upgrades and staged reverse removal do not
apply this independent-channel absence condition.
Ordinary upgrades retain identity and keys. No historical native UNKNOWN outcome,
journal or recovery ownership is cleared to install this feature.

The standalone pilot alongside historical172 is not owned by that historical
MSI. If removing that pilot before upgrading to a support-aware full Setup,
explicitly invoke the signed component's `--uninstall`. Read-only historical
uninstall finalization and staged runtime retirement do not gain new mutations.

## APIs and deployment assets

- `endpoint_contracts/support_access.py`: strict bounded wire models.
- `/agent/v1/support-access/register`: durable device-authenticated public-key
  registration; independent bearer for `/policy`, `/status` and `/unregister`.
- `/api/admin/support-access/devices/{device_id}`: policy and separate component,
  tunnel, freshness and operator access-proof states; audited policy operations.
- `endpoint_server/support_access/`: database authority and unprivileged exporter.
- `deploy/server/support_access_broker.py`: standalone stdlib-only privileged
  broker installed root-owned at `/usr/local/libexec/endpoint-support-broker.py`.
- `endpoint-support-{gateway,exporter,broker}.service` and broker timer:
  independently supervised transport, snapshot publication and revocation.
- `pc_agent/platform/windows/support_access*.py`: isolated policy, native process
  and SCM boundaries; `pyinstaller_windows_support_access.spec`: signed artifact.

The gateway LAN listener and the `SUPPORT_GATEWAY_HOST`, `SUPPORT_GATEWAY_PORT`
and `SUPPORT_GATEWAY_HOST_PUBLIC_KEY` settings are explicit deployment changes.
Migration0046 is additive and seeds no policy or workstation access.

## Acceptance and release gate

First qualify only192.168.101.120. Save the prior agent/updater/task state and
private identity proof; preserve the existing direct SSH service. Verify an
actual key-authenticated Windows command through the gateway with strict gateway
and UUID-bound device host-key checks. Repeat with Core, updater and scheduled
observer stopped, across natural reboot/reconnect, and after service restart.
Verify wrong operator/gateway/device keys, wrong gateway port, lease expiry,
disable/revocation and stale-policy cutoff. Verify reinstall/rollback and explicit
key recovery. Restore original agent/updater/task state after fault injection.

Only after these checks pass may a new immutable full Setup be signed, tested
from the actual source Foundation and qualified in Console. The user authorized
subsequent fleet delivery through Endpoint. Keep normal qualification gates and
bounded waves; unsupported/offline devices are reported separately from successful
installations. Preserve historical172 bytes and every earlier failure receipt.

Actual command outputs, artifact digests and live device results belong in a
dated verification receipt. This runbook describes the required workflow and
does not itself assert that any live check or rollout passed.

## Finalizing a completed restoration

Support remaining available is independent of native update settlement. If a
completed staged rollback restores an older MSI that reserved post-install work,
the parent must finish that exact restoration reservation before another update.
The role-bound finalizer proves terminal rollback, the original private plan and
role capabilities, native completion, installed bytes, private state, startup
configuration and exact original selectors. It permits only the proven previous
selector restored by that parent. A new immutable receipt precedes retirement
of the matching reservation; historical validation remains strict.

For an interrupted finalization, newly signed SYSTEM Setup provides
`--recover-staged-restoration <restoration-transaction-uuid>`. Its own media is
code authority; the target remains bound to the older restoration evidence.
The protected authenticated owner requires genuine native settlement and death
of prior owners. It does not reinstall MSI, restart services, change selectors
or replace grants. A mismatched or unresolved native operation remains blocked.

## Удаление и повторная установка начиная с Setup177

Штатное защищённое удаление фиксирует событие только после подтверждённого
завершения MSI с native0. Перед удалением собственных маркеров оно освобождает
принадлежащие Endpoint настройки браузеров, сохраняя чужие значения. Результат
очистки браузеров и Support передаётся отдельно от результата MSI. Не удаляйте
маркеры владения вручную, пока связанные значения ещё существуют.

Отправка уведомления выполняется после завершения владельца установки и
освобождения его блокировок. Она ограничена по времени и не оставляет отдельного
отправителя после удаления. Недоступность сервера не превращает успешное удаление
в ошибку MSI: защищённая очередь сохраняет факт для следующего Setup. До получения
уведомления сервер показывает последний подтверждённый факт. При следующей
установке накопленное удаление доставляется перед новым событием установки.

При обычном удалении сохраняются четыре файла идентичности устройства. Повторный
Setup использует прежний UUID и credential; карточка, телеметрия и история остаются
на месте. Состояние «удалён» не равнозначно административному выводу устройства
из эксплуатации. Heartbeat не отменяет подтверждённое удаление; новые задания
для такого устройства блокируются до подтверждённой установки.

Ключи самого канала Support после удаления создаются заново. Разрешённая привязка
к прежнему UUID требует подтверждённой последовательности удаления и установки,
прежнего действующего device credential и неизменённого решения администратора.
Ручное отключение, отзыв или сброс не обходятся переустановкой. Прежнее
автоматическое разрешение может получить новое ограниченное окно только в рамках
этой однократной привязки; повторы и heartbeat не продлевают доступ.

Изменившийся SSH-ключ по-прежнему вызывает отказ подключения. После разрешённой
переустановки сверьте новую привязку с актуальной аутентифицированной карточкой,
фактами native0 и, если он доступен, прежним доверенным административным каналом.
Сохраните старый публичный pin как свидетельство и замените только pin данного
UUID. Не отключайте строгую проверку ключей и не используйте сканирование порта
как подтверждение новой идентичности.

Полная очистка — отдельная операция: сначала дождитесь известного native0,
очистки принадлежащих продукту значений и полученного сервером события удаления.
Сохраните журналы вне рабочих каталогов и отзовите утраченный credential.
Прежнюю карточку с историей сохраните. При одобрении новой регистрации можно
указать её UUID в поле **Предыдущая карточка после полной очистки**. Сервер требует
совпадения отпечатков двух заявок и потреблённую прежнюю регистрацию на том же
устройстве; объединения credential или истории не происходит. Дайджесты заявок
и install claim имеют разные защитные контексты и напрямую не сравниваются.

Неизвестный результат MSI, незавершённый rollback или смена административной
политики не дают права повторять установку, удалять журналы или обходить отказ
привязки. Факты прежних версий без нового уведомления остаются неизвестными;
миграция не придумывает для них состояние установки или ProductCode.
