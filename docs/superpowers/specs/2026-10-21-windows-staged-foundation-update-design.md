# Windows Agent: подготовка без остановки, переключение и автоматический откат

Дата: 2026-10-21. Статус: согласована пользователем; реализация и native acceptance ещё не выполнены.

## Согласованный результат

Пользователь согласовал подготовку при работающем агенте, быстрое переключение, проверку новой версии после запуска и автоматический откат. Нужно убрать двойное копирование старого runtime и проверить настоящее обновление на тестовой Windows-машине.

Длительная подготовка не должна останавливать связь и телеметрию старого агента. Новая версия становится принятой только после подтверждения работы. До этого предыдущая версия и необходимые установочные пакеты сохраняются. Подлинность исполняемых файлов проверяется до их запуска.

Эта спецификация охватывает Windows Foundation MSI и сопряжённый Core. Существующий быстрый Core OTA сохраняет собственный рабочий путь; его механизм подтверждения используется как образец. Изменения production-сервера, миграции, массовое назначение обновлений и обновление рабочего компьютера пользователя в эту проверку не входят.

## Проверенный исходный код

Базовый коммит: `c22024492dbb6b12fe5760c54868d18987b668f2`, совпадает с `origin/main` при проверке. Рабочая ветка: `codex/windows-staged-foundation-update`. Несвязанные изменения исходного checkout остаются нетронутыми.

- `packaging/windows/Install-EndpointAgentCanary.ps1`: остановка служб происходит перед `prepare`; их запуск — после native reconciliation. Успех текущего Setup сам по себе не является подтверждением WSS новой версии.
- `installation_provenance.py`: `archive_retained_core` копирует старый payload в `installer-state/retained`; `restore_retained_core` затем копирует его обратно в `Agent/versions`. Это два отдельных прохода записи файлов. `_archive_directory` также вызывает flush для уже существующего каталога.
- `runtime_identity.py`: retained receipt v1 требует одновременно архивный payload и опубликованный runtime. Простая замена copy на rename нарушит этот контракт.
- `installer_fence.py`, `compound_upgrade_plan.py`: активный installer barrier запрещает запуск. Нужен узкий режим проверочного запуска, а не преждевременное удаление barrier.
- `updater_service.py`: Core OTA уже готовит отдельный каталог до остановки, переключает selector и ждёт подтверждения с `operation_id`/`attempt_id`; при неудаче возвращает предыдущий selector.
- `compound_installer.py`: современная Foundation использует отдельную package-bound authority для старого и нового MSI. Native commit предшествует обычному запуску агента; существующий recovery ориентирован на завершение установки и не заменяет откат после неудачного запуска.

Архитектурный GitNexus MCP был запрошен перед исследованием, но соединение завершилось timeout. Его актуальность и impact не подтверждены. Выводы выше проверены по исходникам; отсутствие ответа графа не означает отсутствия зависимостей. Перед финализацией реализации нужно повторить доступную проверку GitNexus без ручного sync.

Текущие зависимости: WiX schema v4, Windows Installer 5.0 (`InstallerVersion=500`), PyInstaller 6.22.3 и hooks 2026.8 в Windows build profile. Версия реально используемого WiX CLI и все build inputs фиксируются при сборке кандидата.

## Выбранный подход и границы

Сохраняем существующие MSI-компоненты и подлинные старые пакеты. При работающем агенте создаём одну проверенную копию runtime, который MSI может удалить. После native удаления его владельца публикуем эту копию переносом каталога на том же томе. Повторной записи payload при успешном обновлении нет.

Полное исключение первой копии потребовало бы менять ownership MSI или перемещать используемые файлы. Это не выбранный подход: исторический MSI может удалить собственные файлы, а открытые executable/DLL не гарантируют возможность переноса работающего дерева.

Неизменившиеся ZIP/retained деревья повторно не копируются. Старые v1 archives читаются без переписывания исторических receipts. Новый layout получает отдельную версию схемы. Hardlinks, junctions и произвольные пути в receipts не используются.

## Жизненный цикл

| Состояние | Агент | Условия перехода |
| --- | --- | --- |
| `preparing` | Старая версия работает | Проверены media, место, исходная identity; готовятся файлы и откат |
| `prepared` | Старая версия работает | Одна полная retention-копия и проверенные пакеты готовы |
| `switching` | Управляемая остановка | Повторно подтверждены исходные selectors, media, ownership и отсутствие конкурента |
| `native-settled` | Запуск пока закрыт | MSI API, callbacks, registration и native commit действительно завершены |
| `trial` | Работает только кандидат | Разрешён ровно запланированный runtime; OTA/вторая установка запрещены |
| `accepted` | Кандидат работает | Получено свежее подтверждение и пройдено окно наблюдения |
| `rolling-back` | Кандидат остановлен | Восстанавливается точное прежнее состояние |
| `rolled-back` | Прежняя версия работает | Подтверждены native inventory, selector и восстановление работы |
| `recovery-required` | Запуск ограничен | Недостаточно доказательств для безопасного продолжения/отката |

Переходы журналируются до необратимой операции и подтверждаются после неё. Это application lifecycle поверх существующих native child phases, а не переименование их успешных receipts. `accepted` не записывается по exit code MSI или `SERVICE_RUNNING`.

### Подготовка при работающем агенте

Setup резервирует единственную установочную операцию, но не создаёт прежний блокирующий launch fence и не отключает службы. Отдельная защищённая reservation запрещает OTA, вторую установку и cleanup выбранных версий, сохраняя обычный запуск и переподключение прежнего агента. При гонке с уже выполняющимся OTA подготовка отказывается от работы до первого изменения.

Проверяются подпись/цепочка доверия, хеши, полные runtime manifests, minimum Foundation/Core compatibility, package identity, transforms/patches, место для всего обновления и восстановления. Входящие media и recovery executable находятся в защищённом cache вне удаляемого MSI дерева. Секреты не копируются в публичные receipts.

Сохраняемые runtime неизменяемы для обычного агента. Подготовка проверяет исходную identity до и после чтения; подмена, изменение selectors или незнакомый файл отменяют подготовку. Перед остановкой повторяются проверки identity, ACL/namespace и reservation, а не часовой цикл копирования.

Результат подготовки — immutable manifest/receipt и отдельно изменяемый lifecycle journal. Запись receipt не даёт полномочий на последующие мутации без нового живого owner checkpoint.

### Одна retention-копия и перенос каталога

Immutable capture receipt сохраняет проверяемые identity/package/manifest данные существующего v1 формата. Новая версия storage journal описывает две фиксированные позиции: staging payload под `installer-state/retained/<digest>` и runtime `Agent/versions/<version>`. Пути выводятся из проверенных digest/version; внешний абсолютный путь не принимается. Подтверждённая позиция хранится в отдельном защищённом журнале `staged → promoting → published`. Новые readers понимают этот layout; старые helpers не получают поддельный v1 archive с отсутствующим payload.

До promotion проверяются завершение native удаления старого продукта и отсутствие его ownership. Остаточный целевой каталог не перезаписывается вслепую: допускается только точный известный MSI остаток, проверенный по исходному inventory и убираемый под журналируемой authority; неизвестное содержимое вызывает `recovery-required`.

Перенос выполняется только между каталогами одного проверенного NTFS-тома, с durable journal и flush затронутых родителей. Это условие проверяется до остановки. При другой конфигурации обновление отклоняется заранее, без скрытого возврата к двойному копированию.

После promotion runtime и retention verifier читают одно и то же опубликованное дерево. Архивные package/manifest/receipt остаются на месте. После сбоя проверяются обе фиксированные позиции и идентичность дерева: наличие двух конфликтующих payload или отсутствие обоих не трактуется как успех. Журнал не позволяет выбрать произвольное дерево по признаку существования каталога.

Оптимизация checkpoints/flush выполняется только после измерений. Убираются ожидания и повторные flush неизменённых каталогов; обязательные записи журнала, завершение записи payload и отзыв полномочий при потере owner сохраняются.

### Переключение и проверочный запуск

После `prepared` Setup останавливает старый Agent и нужные общие компоненты, перепроверяет неизменность исходного состояния и выполняет существующий аутентифицированный native upgrade. Строгие проверки owner/package/session, завершение callbacks и защита enrollment сохраняются.

Native barrier после settlement переводится в специальный trial mode. Он разрешает запуск только назначенного Core с точной source/tree identity и проверенных Foundation служб. Этот режим не разрешает второй updater, обычное обслуживание MSI или запуск другого selector. Если остановка старой версии не подтверждена, переключения нет.

Общие Foundation файлы заменяются через MSI, а не пользовательским `copy` поверх служб. Условие быстрого переключения означает отсутствие retention-копирования в паузе; оно не отменяет время настоящей MSI транзакции или необходимость перезагрузки, если её потребует Windows.

### Подтверждение работы

Кандидат обрабатывает защищённый trial request и после настоящего аутентифицированного WSS handshake пишет ограниченный startup proof. Он привязан к installation operation, новому attempt, compiled Core/source identity, ожидаемой Foundation и времени не раньше начала попытки. Старое подтверждение и подтверждение другой версии отвергаются. Privileged owner не получает сетевые credentials: сетевым владельцем остаётся Agent.

После handshake требуется 60 секунд стабильной работы с новым heartbeat; общий срок ожидания — 180 секунд. Эти значения являются параметрами реализации с ограниченными допустимыми значениями, а не основанием продлевать установку на часы. Проверяются отсутствие раннего crash, соответствие назначенной версии и корректное получение текущей политики. Отсутствие интерактивной сессии не выдаётся за отказ Activity Sensor.

Службы/пользовательские companions, которые были запущены до обновления, восстанавливаются в соответствующих контекстах. User Sensor и Tray не запускаются в Session 0 вместо пользователя. Успех фоновой установки проверяется отдельно от восстановления интерактивных companions.

Только затем durable `accepted` разрешает обычный запуск/OTA и последующую фоновую очистку. Сбой cleanup после `accepted` не отменяет принятую версию.

## Автоматический откат и прерывание

Ранний crash, отсутствие свежего proof или истечение срока переводят операцию в `rolling-back`. Сначала подтверждается остановка кандидата. При Core-only изменении возвращается прежний selector и запускается сохранённый Core.

Если изменена Foundation, одного selector недостаточно. Owner выполняет компенсирующую native транзакцию: удаление точного кандидата и восстановление прежнего подписанного MSI, его служб и native component registration; затем возвращает точные прежние selectors и проверяет запуск старой версии. После успешного native commit исходную транзакцию нельзя считать всё ещё доступной для rollback.

Reverse path получает отдельную строго привязанную authority: exact old/new media, направление rollback и ссылка на исходную не принятую операцию. Нельзя выдавать downgrade за обычный upgrade, подделывать старый callback, редактировать immutable MSI или отключать его проверки. Совместимость неизменяемого старого helper — обязательная native проверка для каждой поддерживаемой исходной семьи. Неподдерживаемая исходная семья отклоняется до остановки; она не включается в список успешно поддерживаемых обновлений.

Если старому helper при фактическом восстановлении нужен исторический layout с двумя деревьями, recovery owner материализует его из проверенной единственной копии до вызова этого helper. Это отдельная ветвь реального rollback с v1 receipt, без переписывания исходного capture receipt и без использования несовместимого нового storage layout старым кодом. Совместимость не выводится из совпадения номера версии.

Установка старого MSI при фактическом откате вправе восстанавливать его файлы. Требование убрать двойное копирование относится к обычному успешному обновлению; оно не запрещает необходимые записи при аварийном восстановлении.

Перед `switching` создаётся ограниченная recovery task под SYSTEM, запускающая точный подписанный cached recovery owner с operation ID. Cache/task проверяются по защищённой identity; произвольные команды/пути не принимаются. При гибели исходного owner или загрузке Windows задача получает mutex и новую живую authority, проверяет settlement и защищённый журнал. Она не продолжает старую HMAC-сессию. Живой владелец блокирует конкурирующую recovery task.

До переключения потеря owner отменяет подготовку, сохраняя старый агент. После переключения recovery заканчивает доказуемый rollback; неоднозначная native транзакция или повреждённые доказательства оставляют `recovery-required`, а не запускают непроверенный runtime. Неожиданные reboot-required коды не становятся `accepted`: trial возобновляется после подтверждённой загрузки. Task удаляется после конечного принятого/восстановленного состояния; доказательства незавершённого восстановления сохраняются.

Временный отказ завершающей проверки не требует ручного запуска recovery: новая task допускает до трёх повторов с интервалом в одну минуту и без параллельных экземпляров. Каждый повтор заново получает живую authority и подтверждает native settlement. Параметры повторов входят в защищённый хеш XML; исторические task без повторов остаются совместимыми. Отложенный запуск компонентов текущего пользователя сохраняет task; отсутствие подходящего пользовательского сеанса не разрешает запуск от SYSTEM или другого пользователя. Проверки файлов, ACL, владельца, MSI и границы принятия не ослабляются.

Device identity, credential bytes, CA/origin, outbox и исходные защищённые descriptors не переинициализируются. Изменения схемы локальных данных допускаются только обратно совместимые на время rollback window; несовместимый кандидат отклоняется до переключения.

## Очистка и совместимость

После принятия сохраняется одна предыдущая рабочая пара Foundation/Core с проверенными media; staging temporaries удаляются в фоне. Выбранный runtime, предыдущий runtime и данные активного journal не удаляются. Удаление старой recovery task и временных файлов повторяемо после сбоя.

Старые схемы archives/selectors не переписываются задним числом. Новые readers поддерживают v1 и новую схему раздельно, без догадки по отсутствующим полям. Существующие legacy allowlists не расширяются по одному номеру версии. Новый номер подписанной сборки выбирается после проверки занятых версий; исторические releases не пересобираются под прежними именами.

Внешний HTTP/OpenAPI контракт менять не требуется: это локальный Windows lifecycle и существующее соединение Agent. Проверка исходников потребителей и GitNexus при доступности остаётся частью impact review; пустой граф не доказывает отсутствия динамического влияния.

## Проверка на отдельной Windows-машине

Используется выделенный тестовый Windows guest после проверки отсутствия активного Setup/controller/installer. Сохраняются исходные immutable receipts и enrollment baseline. Рабочая машина пользователя и production-агенты для fault injection не используются. Сбои и перезагрузки выполняются только внутри этого guest и новой операции, без повторного использования старых acceptance sequence.

Обязательные исходные состояния: подлинная legacy Foundation 3.2.79 и современная Foundation 3.2.120, включая вариант с отдельным Core 3.2.121. Подлинные подписанные media проверяются заново; версия нового кандидата фиксируется отдельно. Невозможность безопасного rollback одного из этих состояний означает незавершённую приёмку задачи, а не разрешение исключить его из отчёта.

| Сценарий | Необходимое доказательство |
| --- | --- |
| Подготовка и успешный Foundation upgrade | Во время подготовки старые PID/WSS/heartbeat сохраняются; после переключения подтверждена новая версия |
| Runtime с 2500+ файлами | Счётчики payload bytes/write показывают одну retention-копию; promotion сохраняет file identities и не копирует payload обратно |
| Падение кандидата и отсутствие proof | Автоматически восстановлены прежние Core, Foundation registration и связь с сервером |
| Старый/чужой proof, неверная версия | Кандидат не принимается |
| Ошибка MSI до commit | Native rollback и точное исходное состояние, без поддельного успеха |
| Потеря owner и перезагрузка guest | До переключения работает старая версия; после переключения наблюдается recovery/rollback с настоящими проверками settlement |
| Прерывание promotion на каждой границе | Одно авторитетное дерево, повторяемое восстановление без второй payload-копии |
| Диск заполнен, неверный ACL/hash, reparse/hardlink, конфликт каталога | Отказ до опасного действия, сохранение доказательств и enrollment |
| Конкурентный OTA/Setup и cleanup | Единственный владелец; выбранные деревья не изменены конкурентом |
| Нет пользователя / пользователь вошёл | Корректный service proof и отдельно корректный Sensor/Tray в пользовательской сессии |

Измеряются отдельно package staging, hashing, ACL, IPC/grants, flush, retention, MSI, promotion, время без heartbeat, health window и cleanup. Историческое время на другой машине — контекст, а не сопоставимый benchmark. На одном guest сравниваются одинаковые исходные состояния и media; фиксируются cold/warm условия, CPU/disk и точные SHA.

Цели приёмки для репрезентативного guest: обычное обновление локально подготовленного пакета до `accepted` укладывается в 10 минут, пауза до первого нового WSS handshake — в 2 минуты; reboot-required сценарии измеряются отдельно. Это цели новой реализации, не уже полученные результаты. Если они не достигнуты, проверка производительности не объявляется успешной.

Обязательны целевые unit/contract проверки provenance, durable state, owner loss, bridge phases, selector, native registration и recovery; затем настоящий подписанный Setup/MSI и source-bound Windows acceptance. Источниковые тесты/CI не заменяют installed proof. Отчёт связывает commit, build hashes, фактические версии, timings, конечные статусы и сохранность enrollment; секреты и приватные machine facts остаются в защищённых локальных evidence.

## Затрагиваемые границы реализации

- Windows owner/bridge и native driver: online preparation, reservation, trial/rollback authority и recovery task lifecycle.
- Provenance/runtime identity/durable state/disk readiness: новая схема одной retention-копии, promotion и совместимость чтения v1.
- Installer/compound barriers и service launcher: ограниченный trial launch и запрет конкурентного обновления.
- Agent startup proof/online update runtime: свежая локальная post-handshake проверка без второго сетевого клиента.
- WiX/build/release inputs: проверенная native последовательность, recovery executable source closure и новый подписанный кандидат.
- Windows tests и итоговый acceptance report: success, rollback, interruption и сопоставимые измерения.

## Документальные основания

Проверена документация Microsoft Windows Installer через Context7 (`/websites/learn_microsoft_en-us_windows_win32_msi`): [transaction functions](https://learn.microsoft.com/en-us/windows/win32/msi/installer-function-reference), [MsiEndTransaction](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msiendtransaction), [multiple-package installations](https://learn.microsoft.com/en-us/windows/win32/msi/multiple-package-installations). Она подтверждает native transaction boundaries; автоматический откат после проверки приложения является ответственностью нашего lifecycle, а не обещанием MSI.

## Incoming Core preparation supplement (2026-10-22)

The online window includes preparing the incoming Core, in addition to retaining
the genuine previous Core. An internal archive inside signed Setup is only a
transport: its exact manifest, compatibility contract and all member bytes must
equal the inventory read from the authenticated MSI. It conveys no new origin,
native feature exclusion, ownership or launch authority.

Write each member once to protected operation storage while the old Agent runs.
Publish by same-volume NTFS rename while the old Agent still runs. The staged
launch gate permits only the exact old selected tree. Managed stop and sealing
retain their existing revalidation. Keep native MSI feature/component/file checks
unchanged; the MSI adopts matching files under its normal file-version/hash
rules. Installed acceptance must prove all candidate payload file identities
across this native installation. A two-file native file-rule probe only proves
the operating-system mechanism.

Bind storage phases to the immutable operation. Unknown/foreign state fails
closed. Before-switch cancellation needs fresh native settlement and complete
original-state proof, then moves only an owned complete candidate back to private
storage. Interrupted private preparation stays as evidence without selecting a
future version. Every write and rename retains live-owner mutation checkpoints.
Add the compressed cache allocation to the existing native full-payload costing.
No signature, hash, ACL, native, health or rollback gate is omitted.

### Post-native helper consolidation

After genuine successful native End(Commit), fresh forward upgrades may run the
five existing ordered post-native functions in one authenticated fixed helper.
Every check, mutation grant and durable journal boundary remains. Intermediate
logical completion never acknowledges the owner; only the final verified ready
marker does. Journal the physical peer before verification so owner-loss recovery
can exclude a live helper. Recovery and repair keep their existing granular path.
The service remains stopped until all existing launch requirements pass.

Within one helper, immutable MSI input handles may survive unrelated metadata
mutations only under fixed owner-derived execution/cache roots. Deny writes and
deletion for the whole scope and validate namespace and file identity at every
checkpoint/reuse. Native callback phases exclude the managed Installer cache.
Installed registration, ACL, Foundation/Core bytes, SCM and health remain fresh.
Retained original MSI media in the fixed package-digest archive directories may
use that same immutable-input rule outside native callbacks; it does not apply
to any mutable archive metadata or installed payload.
