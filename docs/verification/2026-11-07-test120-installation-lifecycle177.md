# Test120: UserSensor, удаление, переустановка и резервный доступ177

Проверено на `192.168.101.120`, `DESKTOP-9ST5HO2`, при активном обычном RDP-сеансе
`SOSNADM\endpoint-test120`. Итоговая приёмка тестового ПК: **PASS**, 2026-11-07T00:20:42.243992+00:00.
Все времена ниже UTC. 177 опубликована как основная Windows-версия. Политика12: enabled/all_active/max2. Начальная доступная группа: 6 ПК приняты. Состояние офлайн-устройств и точные задания сохранены в записи выпуска; их успешное обновление не предполагается.

## Причина UserSensor и исправление на будущее

Прежняя ручная полная очистка удалила маркеры владения BrowserPolicy, оставив
принадлежащие Endpoint значения Chrome/Yandex. Строгий applicator верно отклонял
такое состояние как `POLICY_CONFLICT`; запущенный UserSensor и READY listener
не означали принятых образцов. Это была ошибка операторской очистки, а не
доказанная неисправность UserSensor. Причина и исправленная чистая176 сохранены
в [отдельном отчёте](2026-11-07-test120-usersensor-cause-clean176.md).

В177 штатное защищённое удаление само освобождает точные собственные значения
перед удалением маркеров. Чужие значения сохраняются. Физическое отсутствие
собственных значений И маркеров проверено перед обоими последующими полными
очистками. В финальной чистой177 после перезапуска Core не применялось ручного
исправления реестра, политик или перезапуска UserSensor.

## Фактические проверки

| Проверка | Подтверждённый результат |
|---|---|
| Console176 →177, задание `7a0db343-d209-45c6-9038-b2c2f2062e76` | APPLIED/native0,185.317с,6 образцов,1 UserSensor, CPUmax0.0063, private4 сохранены |
| Штатное удаление177 | native0, службы/Support удалены, сервер получил removedseq2, очистка Support/browser complete |
| Повторная установка с сохранённой идентичностью | Setup REPAIRED/10, отдельный подтверждённый MSI native0; тот же UUID/credential/private4, история сохранена, installedseq3 |
| Удаление при недоступном HTTPS | native0, нет остаточных служб; сервер сохранял прежний подтверждённый installed до доставки уведомления |
| Переустановка после восстановления HTTPS | removedseq4 перед installedseq5; тот же UUID/private4, новый ключ Support, ручной запрет доступа сохранён |
| Чистая подписанная172 и Console172 →177, задание `fa9c3a87-4c45-44e0-91c9-607d6bd428e4` | APPLIED/native0,185.161с,6 образцов,1 UserSensor, private4 сохранены; без подготовки workstation после назначения |
| Финальная полностью чистая177 | Setup0, native installedseq1/0, новая регистрация с исторической ссылкой, новый credential и ключ Support |
| Независимый SSH при остановке Core/updater и отключённом observer | два настоящих входа администратора с интервалом96.908636с, тот же SupportPID6660, свежий независимый отчёт |
| UserSensor до/после остановки | принятые возрастающие метки: 2026-11-07T00:15:20.849608+00:00, 2026-11-07T00:16:20.892381+00:00 / 2026-11-07T00:19:21.037764+00:00, 2026-11-07T00:20:21.090512+00:00 |

Код10 — документированный успешный `REPAIRED`/`EXIT_ALREADY_INSTALLED` внешнего
Setup. Он не подменяет native0: отдельные native-факты получены сервером и
связаны причинной последовательностью. Неизвестных native-исходов или повторов
MSI для их обхода в этой проверке нет.

Резервный вход: `SOSNADM\admin-2`, SID
`S-1-5-21-2662010196-1888334160-2524870385-7188`, права администратора проверены
реальной командой. Байты работающей службы совпали с подписанным177 Support
`69205b83e588c064d82c014c39afde0a9641ef11c86d8a2cee702fa7afc95c41`. `EndpointAgentUpdater` восстановлен в исходное
Manual/Stopped, Core — Running/Auto, observer — включён/Ready. Изначальный
системный SSH120 сохранён с PID3564; доменный secure channel исправен.

## Идентичность и история

Обычное удаление/переустановка использовали UUID
`4231a496-1ab5-4318-b558-2d2e954b5f03` и неизменённые четыре приватных файла.
Число сохранённых sessions/snapshots не уменьшилось. Последовательность до
полной очистки: installed,removed,installed,removed,installed,removed.

После полной очистки172 получила новую карточку
`a68f65b1-1ebf-45f2-84e6-6b67afac64a5` со ссылкой на423. Финальная чистая177:
`c87eaa22-4fd1-4830-bc11-88142afda87e` со ссылкой на `a68f65b1-1ebf-45f2-84e6-6b67afac64a5`. Предыдущие
карточки остаются removed, не retired; утраченные credential отозваны отдельно
с аудитом. Старые native/private журналы сохранены в защищённых архивах вне
рабочих каталогов. Ни credential, ни история между новыми UUID не объединялись.

Настоящие запросы полного повторного enrollment одобрены через canonical API
с `previous_device_id`, тем же AUTO campaign и совпавшими отпечатками заявок.
Живая Console проверена на1440/390, после reload: installed/removed, причинная
история и ссылка на предыдущую карточку; overflow и console errors отсутствуют.

## Найденный при живой проверке дефект привязки истории

Исходный provider сравнивал Claim fingerprint HMAC с Request fingerprint HMAC.
Их защитные контексты различаются. На живых данных старый/новый Request совпали,
Request/Claim не совпали; прежний Claim был потреблён. Исправление соединяет
потреблённый Claim с исходной Request через сохранённый FK и сравнивает два
Request-дайджеста, сохраняя совпадение обоих Device binding, removed/nonretired
и повторную проверку администратора. Отсутствующая прежняя Request даёт отказ.

Прежний PG fixture искусственно копировал одинаковый дайджест между доменами.
Новый тест использует настоящие публичные builders: RED воспроизвёл409 вместо204;
GREEN30passed72.78с. Проверены отсутствие FK, иное оборудование, непотреблённый
Claim, несовпадающий Device и retired. Независимый review:0Critical/Important.
Provider-only `266e38e5c2ead35f95978da1b95cc7a4fadb2a82`
развёрнут отдельно; уже подписанные байты177 не менялись. Та же ожидающая заявка
172 продолжилась и была успешно завершена без повтора MSI.

## Ручной запрет и автоматическое разрешение

На423 вручную выключен доступ с сохранением исходных principal/ключа; временно
блокировался только outboundTCP443 к192.168.100.19 на тестовом120. Изначальные
firewall profiles не менялись; единственное собственное правило удалено в finally,
HTTPS200 восстановлен. После offline reinstall Support установлен, новый host
key привязан, но доступ остаётся выключен. Disabled HTTPS projection скрывает
account/keys, поэтому их сохранение дополнительно проверено по сырым сохранённым
полям и аудиту; после ручного запрета нет нового pending/granted auto-access.

В финальной новой карточке автоматический grant выдан ровно один раз, revision2,
manual policy writes0, expiry `2026-11-07T08:14:14.517608Z`, срок8ч. Gateway loopback port
32009. Регистрация, tunnel_connected и реальный SSH различаются;
последний подтверждён отдельно. После разрешённой обычной переустановки строгий
pin правильно отклонил новый host key. Его сверили по HTTPS и прежнему доверенному
OS SSH, архивировали старый публичный pin и заменили только pin данного UUID.

## Сборка и проверка исходников

- Runtime `25f2ad8a5e13991e4e76260da939d29aafba8674`, native packaging `d21bc3bba119a178607de6f64f620fb53eeadf01`.
- Новый initial runtime GUID `3D98B33C-4437-46F3-A689-D22DB351799C`,119 frozen files,
  tree `a7ae6717d994460b3a4815a94dc8377ab54fbc908014e54fe10f24d9aa61370c`.
- EXE178729632bytes SHA256`9d06a8339c2ed3b2c563f2b5258ad9fdbef0962b6d85f79e6e88490ca7f426fc`.
- MSI136970240bytes SHA256`d096726d6d0521a522fdb81d0b3ee551d583befba5d216c09a96332fd21359f3`, ProductCode`{51548FA4-95F6-4448-B0E4-99CB47CF32A1}`.
- EXE/MSI/Support: реальный Authenticode Valid, timestamp, publisher4D4C23389F5FF77BC4EB32044761019EAE8FB776.
- Прочитаны настоящие MSI semantic/resources и125 Foundation records; frozen
  semantic code сравнен с точным runtime source, browserID/OpenSSH resource связаны.
- Проверено отсутствие Core/runtime/updater/observer в Support и offline import
  closure привилегированного native worker. Signed observer107 сохранён8a1a30e7….
- Сборка PowerShell7.6.9/Python3.12.14/PyInstaller6.22.3/hooks2026.8/WiX4.0.6.
  Неудачные попытки WindowsPS5.1 сохранены и не публиковались: module path/type
  data и вложенная JSON array форма. Финальная упаковка использовала только
  свежие177 helper bytes того же C/B source; старые176 helpers не подмешивались.

Полный `python -m pytest -q --maxfail=1`:6808passed,470skipped,7 прежних warnings,
821.80с до узкого candidate-visibility расширения. Оно дополнительно проверено
65 отдельными тестами, включая реальный PG downgrade/upgrade и concurrency.
Provider parent hotfix:30passed отдельно после RED. `npm.cmd run build`,22 UI
tests/typecheck и живые desktop/mobile проверки пройдены; предупреждение chunk
более500KB сохранено. Эти наборы не названы одним полным прогоном окончательного
provider patch.

Точная команда parent GREEN:
`python -m pytest tests/server/test_installation_lifecycle.py tests/server/test_enrollment_request_admin_api.py tests/server/test_installation_lifecycle_postgresql.py::test_explicit_full_wipe_link_is_audited_history_only -q --tb=short`.

## Deployment, сохранение состояния и ограничения

Provider/schema48 развёрнут с backup/config/hash/capacity gates. Первые6 реальных
SSH probes до/во время/после рестарта API прошли, SupportPID11380 не менялся.
Поздний parent-only hotfix сохранил GatewayPID24963 и exporter107695; schema и
конфигурация не менялись. Backup parent dump47531861bytes,
SHA`e121f3fbf57d478c42b5e20c348a06b55576d2936f4b19f06c6a42114431d11e`.
Одноразовые завершённые задачи экспортированы/сняты; временное firewall rule
удалено, оба запуска disposable PG и соответствующие SSH forward завершены
с exact PID/path/port guards; данные тестового кластера сохранены.

Начальная публикация177 скрыта из основной загрузки, но включена транзакционно
в единственную AUTO campaign `09e62472-a6ae-49ab-aaaa-6613836b4423`.11→12 immutable
versions; CIDR192.168.101.0/24, expiry2030-09-27, quota100 не расширялись. Обычные
переустановки не потребляли claims. Две явно одобренные полные очистки дали новые
регистрации; usage8→10. Qualification176 `4372c370-5e3e-471e-9145-f4ff3bcf1632`,172 `13d53e38-deeb-4657-827a-f64cb402b67e`;
expiry `2026-12-06T23:32:51.074103+00:00` / `2026-12-07T00:10:08.224472+00:00`. Иные source-профили не
квалифицированы этим тестом. Fleet scope all_active/emptyUUIDlist/max2 динамический.

Linux primary156 и его kit/подписи/метаданные не менялись. OpenSSH private fallback
остаётся тем же Microsoft10.4.0.0p1-Preview, SHA b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957;
vendor Preview/non-production-ready ограничение сохранено. Браузерная телеметрия
Yandex26.10 ранее отложена пользователем; её успех здесь не заявлен.

Ранние3 unit cases могли затронуть реестр операторского ПК до введения fail-fast
guard. Полного снимка до них нет, отсутствие изменений не доказано. Следующие
тесты используют MemoryRegistry; общий guard запрещает реальный constructor.
Не предпринималось догадочного восстановления реестра оператора. Автоматическая
проверка отклонила удаление локального Vitest cache; cache оставлен, только его
два точных пути добавлены в local Git exclude, без изменения исходников.

GitNexus MCP в сеансе отсутствовал; committed/local source, native artifacts,
API и реальные PostgreSQL пути проверялись непосредственно. Helpdesk/Web не
редактировались. Секреты, private keys, cookies и environment files в отчёт/Git
не включены. Подробные локальные receipts: `.superpowers/sdd/2026-11-07-installation-lifecycle`.

## Завершающая проверка и закрытие временного доступа

Повторный живой gate в00:50:47.646593UTC подтвердил все6 исходно доступных ПК:
WSS/Core/Foundation177, свежие Setup107 и Support101, применённая политика,
свежая sensor health, активных update chains0. Основная загрузка177 проверена
в живой Console на1440/390 после reload: точная ссылка и SHA совпадают,
ошибок Console и горизонтального overflow нет.

`python -m pytest pc_agent/tests/windows/test_foundation_upgrade_source.py -q --tb=short`
прошёл:8passed0.18с. Дополнительно проверены JSON/ссылки, исходники/байты реальных
EXE/MSI, точное сохранение176 checkpoint и неизменность Linux156:3322 JSON leaves.
`git diff --check` пройден.

Единственная оставшаяся временная административная сессия этого задания R16
отозвана в00:51:08.302474UTC. Её точный серверный root0600 receipt удалён после
проверки UUID/revocation/inode; локальные cookie/CSRF очищены. Другие сессии,
постоянная fleet policy12 и действующий восьмичасовой Support grant120 сохранены.

Завершающий документационный коммит включает только:

```text
AGENTS.md
docs/releases/current-agent-release.json
docs/releases/windows-3.2.176-current-checkpoint.json
docs/releases/windows-3.2.177-setup.json
docs/runbooks/INDEPENDENT_SUPPORT_ACCESS.md
docs/superpowers/plans/2026-11-07-installation-lifecycle.md
docs/verification/2026-11-07-test120-installation-lifecycle177.md
packaging/windows/README.md
```

Его SHA сообщается отдельно после фиксации; подписанные runtime/native bytes
и действующий provider при фиксации документации не пересобираются.

## Коммиты и полный состав файлов

`50ec0cbb95c8b5a7eee89678b02d9058dae20e97` — `docs(support): record corrected clean-install telemetry proof`

```text
AGENTS.md
docs/releases/windows-3.2.176-setup.json
docs/verification/2026-11-07-test120-clean176-support.md
docs/verification/2026-11-07-test120-usersensor-cause-clean176.md
```

`25f2ad8a5e13991e4e76260da939d29aafba8674` — `feat(installer): track committed removal and retained reinstall`

```text
contracts/jsonschema/endpoint-installation-event-ack-v1.json
contracts/jsonschema/endpoint-installation-event-v1.json
contracts/openapi/endpoint-platform-v1.yaml
docs/superpowers/plans/2026-11-07-installation-lifecycle.md
docs/superpowers/specs/2026-11-07-installation-lifecycle.md
endpoint_contracts/__init__.py
endpoint_contracts/installation_lifecycle.py
endpoint_server/console/fleet.py
endpoint_server/console/installer.py
endpoint_server/console/routes.py
endpoint_server/context/connect_refresh.py
endpoint_server/context/scheduler.py
endpoint_server/db/migrations/versions/0048_installation_lifecycle.py
endpoint_server/db/models/__init__.py
endpoint_server/db/models/installer.py
endpoint_server/enrollment/admin_request_routes.py
endpoint_server/gateway/command_service.py
endpoint_server/installation_lifecycle/__init__.py
endpoint_server/installation_lifecycle/models.py
endpoint_server/installation_lifecycle/parent.py
endpoint_server/installation_lifecycle/routes.py
endpoint_server/installation_lifecycle/service.py
endpoint_server/main.py
endpoint_server/setup_updates/policy.py
endpoint_server/setup_updates/preparation.py
endpoint_server/setup_updates/routes.py
endpoint_server/setup_updates/service.py
endpoint_server/support_access/installation.py
endpoint_server/support_access/native_rebind.py
endpoint_server/support_access/routes.py
endpoint_server/support_access/service.py
endpoint_server/updates/service.py
packaging/windows/Install-EndpointAgentCanary.ps1
pc_agent/platform/windows/installation_lifecycle.py
pc_agent/platform/windows/installation_notification.py
pc_agent/platform/windows/installer_host_entry.py
pc_agent/platform/windows/installer_native_entry.py
pc_agent/platform/windows/installer_transaction_bridge.py
pc_agent/platform/windows/provision.py
pc_agent/platform/windows/service_launcher.py
pc_agent/platform/windows/setup_entry.py
pc_agent/platform/windows/support_access_native.py
pc_agent/platform/windows/support_bootstrap.py
pc_agent/pyinstaller_windows_installer_host.spec
pc_agent/pyinstaller_windows_setup.spec
pc_agent/tests/conftest.py
pc_agent/tests/runtime/test_headless_lifecycle.py
pc_agent/tests/windows/fixtures/windows_context_profiles_v1.json
pc_agent/tests/windows/test_installation_lifecycle.py
pc_agent/tests/windows/test_installer_host_entry.py
pc_agent/tests/windows/test_provisioning_contract.py
pc_agent/tests/windows/test_setup_entry.py
pc_agent/tests/windows/test_support_optional_origin.py
pc_agent/tests/windows/test_support_setup_lifecycle.py
pc_agent/tests/windows/test_usb_sensor.py
pc_agent/version.py
tests/activity/test_console_activity.py
tests/context/test_collection_lifecycle.py
tests/context/test_connect_refresh_lifecycle.py
tests/context/test_connect_refresh_lifecycle_postgresql.py
tests/context/test_scheduler.py
tests/contracts/test_contract_artifacts.py
tests/contracts/test_installation_lifecycle.py
tests/contracts/test_package_exports.py
tests/fixtures/contracts/endpoint-installation-event-ack-v1.json
tests/fixtures/contracts/endpoint-installation-event-v1.json
tests/gateway/conftest.py
tests/modules/test_module_operation_service.py
tests/operations/test_operation_routes.py
tests/operations/test_operation_service.py
tests/packaging/test_installation_notification_stage.py
tests/packaging/test_offline_updater_contract.py
tests/power/test_console_power_presentation.py
tests/server/test_agent_gateway_api.py
tests/server/test_console_fleet.py
tests/server/test_installation_lifecycle.py
tests/server/test_installation_lifecycle_postgresql.py
tests/server/test_migrations.py
tests/server/test_setup_release_registry.py
tests/server/test_setup_update_service.py
tests/server/test_support_access.py
tests/server/test_support_install_access.py
tests/server/test_update_admin_api.py
tests/server/test_update_agent_api.py
tests/server/test_update_service.py
tests/server/test_windows_publication_defaults_postgresql.py
tools/contracts/generate_contract_artifacts.py
tools/register_windows_setup_release.py
webapp/src/ConsoleAcceptance.test.tsx
webapp/src/EnrollmentPage.tsx
webapp/src/FleetPages.tsx
webapp/src/InstallationHistory.test.tsx
webapp/src/InstallationHistory.tsx
```

`d21bc3bba119a178607de6f64f620fb53eeadf01` — `build(windows): bind immutable 3.2.177 runtime`

```text
packaging/windows/initial-runtime-3.2.177.json
```

`266e38e5c2ead35f95978da1b95cc7a4fadb2a82` — `fix(enrollment): match reinstall history within request digest domain`

```text
endpoint_server/installation_lifecycle/parent.py
tests/server/test_installation_lifecycle_postgresql.py
```
