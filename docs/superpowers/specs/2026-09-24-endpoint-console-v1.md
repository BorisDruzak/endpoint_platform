# Endpoint Console v1 — русскоязычная административная консоль Endpoint Platform

Repository: `BorisDruzak/endpoint_platform`

## SPEC

### 1. Goal

Разработать **Endpoint Console v1** — единую русскоязычную административную web-консоль Endpoint Platform для управления полным жизненным циклом пользовательских устройств.

Console должна объединить существующие возможности Endpoint Platform:

* Devices;
* Device Context;
* Enrollment;
* установку Windows Agent;
* Agent Releases;
* Updates / Rollouts / Rollback;
* Operations;
* Module Platform;
* Audit.

Целевой пользователь — системный администратор.

После реализации администратор должен иметь возможность выполнять штатную эксплуатацию Endpoint Platform через один web-интерфейс без необходимости обращаться к PostgreSQL, вручную вызывать API или использовать SSH для обычных операций.

Целевой административный URL:

```text
https://endpoint.sosnadmin.local/admin
```

---

# 2. Current Context

Перед любыми изменениями обязательно исследовать актуальный репозиторий.

Не использовать этот документ как замену repo discovery.

На момент постановки задачи в Endpoint Platform уже существуют следующие архитектурные компоненты:

```text
Endpoint Platform
├── Device identity
├── Enrollment
├── Gateway WSS
├── Device Context
├── Inventory / Session telemetry
├── Operations
├── Windows / ALT Agent
├── Agent update control plane
├── Windows universal setup
├── Module Platform
├── Module capability catalog
├── Audit
└── Service SDK/API
```

Windows Agent на исследованном baseline достиг версии `3.2.63`, однако Codex обязан определить текущую версию из актуального `main`, а не полагаться на это число.

Существующий временный UI:

```text
/admin/enrollment
```

является небольшой dependency-free HTML/JS поверх Enrollment API и должен рассматриваться как временная административная поверхность, подлежащая интеграции в новую Console.

Endpoint Platform является единственным control plane агента.

`web_ovpn` и Helpdesk являются отдельными consumers и не должны становиться частью Endpoint Console.

---

# 3. Mandatory repository discovery

До составления implementation plan Codex обязан:

1. Прочитать корневой `AGENTS.md`.
2. Прочитать актуальный `PLANS.md`.
3. Проверить `git status`.
4. Определить актуальный HEAD `main`.
5. Определить текущий Alembic schema head.
6. Исследовать:

   * `endpoint_server/main.py`;
   * `endpoint_server/auth/`;
   * `endpoint_server/context/`;
   * `endpoint_server/enrollment/`;
   * `endpoint_server/updates/`;
   * `endpoint_server/operations/`;
   * `endpoint_server/modules/`;
   * `endpoint_server/audit/`;
   * `endpoint_server/db/models/`;
   * `endpoint_contracts/`;
   * `contracts/openapi/`;
   * существующие tests.
7. Проверить текущие публичные и admin routes.
8. Определить, существует ли уже canonical frontend stack.
9. Найти существующие CSS/UI conventions, если они появились после постановки задачи.
10. Проверить существующие auth/CSRF/session invariants.

После исследования самостоятельно сформировать **repo-grounded implementation plan**.

Не начинать реализацию UI до завершения этого анализа.

---

# 4. Product boundary

Endpoint Console должна быть административной поверхностью самого Endpoint Platform.

Основная навигация:

```text
Endpoint Platform

Главная
Устройства
Установка и регистрация
Релизы и обновления
Операции
Модули
Аудит
```

Console должна использовать существующие domain services и persistence.

Не создавать второй параллельный control plane.

---

# 5. Language requirement

## 5.1 Mandatory Russian UI

Весь пользовательский интерфейс Console обязан быть на русском языке.

Это относится к:

* меню;
* названиям страниц;
* кнопкам;
* формам;
* подсказкам;
* подтверждениям;
* ошибкам;
* empty states;
* фильтрам;
* статусам;
* breadcrumbs;
* onboarding;
* уведомлениям.

Внутренние enum/code значения не должны использоваться как основной UI-текст.

Например:

```text
WAITING_APPROVAL
```

отображать как:

```text
Ожидает подтверждения
```

```text
rolled_back
```

отображать как:

```text
Выполнен откат
```

Технический код допустимо показывать как вторичную информацию для диагностики.

Использовать локаль `ru-RU` для дат и времени.

---

# 6. Frontend architecture

Сначала проверить repository conventions.

Если отдельного canonical frontend в Endpoint Platform по-прежнему нет, создать:

```text
webapp/
```

с:

* React;
* TypeScript;
* Vite.

Frontend должен компилироваться в статический production bundle.

Node.js не должен требоваться для production runtime.

Production browser surface должна обслуживаться существующей инфраструктурой Endpoint/FastAPI/Nginx.

Не использовать CDN-зависимости для runtime Console.

---

# 7. Security architecture

## 7.1 Browser authentication

Использовать существующую admin-session модель:

```text
endpoint_admin_session
```

и существующий CSRF механизм.

Не создавать второй механизм login/session без доказанной необходимости.

## 7.2 Browser must never receive service credentials

Запрещено:

```text
Browser
  ↓
service bearer
  ↓
/api/v1/*
```

Console должна работать так:

```text
Browser
   │
   │ admin session + CSRF
   ▼
/api/admin/*
   │
   ▼
Endpoint domain services
```

Не выдавать браузеру:

* service token;
* Agent credential;
* enrollment claim;
* request capability;
* device bearer;
* private certificate;
* raw authentication header.

## 7.3 Safe projections

Console должна получать только необходимые безопасные administrative projections.

Не использовать UI как способ показать raw Agent payload.

---

# 8. Main page

Route:

```text
/admin
```

Создать operational dashboard.

Основные показатели:

```text
Всего устройств

В сети

Не в сети

Устройства с устаревшим контекстом

Запросы регистрации, требующие решения

Активные обновления

Ошибки обновлений

Активные операции
```

Также показать:

### Требует внимания

Примеры:

```text
PC-BUH-04
Ошибка обновления

PC-KDN-07
Контекст устарел

DESKTOP-XXX
Требуется проверка регистрации
```

### Распределение версий агента

Пример:

```text
3.2.63    98
3.2.62    17
3.2.61     8
Другие     5
```

Не hardcode версии.

---

# 9. Devices

Route:

```text
/admin/devices
```

Главная рабочая таблица устройств.

Минимальные колонки:

* состояние online/offline;
* display name / hostname;
* текущий пользователь;
* ОС;
* версия ОС;
* версия Agent;
* CPU/RAM кратко;
* последняя связь;
* свежесть Context;
* текущее состояние update;
* действия.

Фильтры:

```text
Поиск

Состояние:
Все
В сети
Не в сети

ОС:
Windows
ALT Linux

Версия агента

Контекст:
Актуален
Устарел

Обновление:
Нет
В процессе
Ошибка
```

Фильтрация должна выполняться эффективно и не создавать N+1 queries.

---

# 10. Device detail

Route:

```text
/admin/devices/{device_id}
```

Header:

```text
PC-KDN-07

В сети

Пользователь:
ivanova.aa

Windows 11
Agent 3.x.x

Последняя связь:
...
```

Вкладки:

```text
Обзор
Контекст
Изменения
Операции
Обновления
Модули
Аудит
```

---

# 11. Device Overview

Показать безопасную техническую информацию.

### Система

* hostname;
* platform;
* OS;
* version;
* build;
* architecture.

### Оборудование

* manufacturer;
* model;
* serial;
* product UUID;
* CPU;
* RAM;
* memory modules, если доступны.

### Накопители

Для каждого physical device:

* model;
* media type;
* bus type;
* size.

### Сеть

* interface;
* IP;
* MAC там, где projection разрешает его показывать администратору.

### Session

* текущий login;
* interactive session presence.

Не отображать secrets.

---

# 12. Device Context

Вкладка:

```text
Контекст
```

Профили:

```text
baseline_v1
health_v1
network_v1
inventory_v1
session_v1
```

Для каждого показывать:

* состояние;
* дата последнего сбора;
* свежесть;
* snapshot ID;
* semantic hash при необходимости;
* безопасную нормализованную projection.

Действие:

```text
Обновить данные
```

с выбором разрешённого profile.

Использовать существующий collection lifecycle и idempotency.

Не создавать отдельный context mechanism.

---

# 13. Context changes

Вкладка:

```text
Изменения
```

Использовать существующий semantic diff.

Поддержать как минимум текущие change codes:

```text
RAM_CHANGED
STORAGE_CHANGED
HOSTNAME_CHANGED
OS_CHANGED
HARDWARE_CHANGED
NETWORK_ADAPTER_CHANGED
```

Показывать человеку понятное изменение.

Пример:

```text
19 сентября 2026

Оперативная память
8 ГБ → 16 ГБ
```

Не показывать пользователю только технический diff code.

---

# 14. Installation & Enrollment

Основной раздел:

```text
Установка и регистрация
```

Route:

```text
/admin/enrollment
```

Вкладки:

```text
Установщик
Кампании
Запросы регистрации
```

Интегрировать существующую Enrollment Admin функциональность.

Не создавать новый enrollment lifecycle.

---

# 15. Installer page

Показать текущий Windows Setup release:

```text
Endpoint Agent для Windows

Версия агента
Версия установщика

Файл:
EndpointAgentSetup-<version>-x64.exe

SHA-256

Подпись

Издатель

Source revision
```

Actions:

```text
Скачать установщик

Копировать команду тихой установки
```

Пример:

```text
EndpointAgentSetup-<version>-x64.exe --quiet
```

Не hardcode actual version.

---

# 16. Installation lifecycle visualization

На странице установщика визуально показать существующий процесс:

```text
EndpointAgentSetup.exe
        ↓
Проверка текущего состояния
        ↓
CLEAN / VALID / REPAIRABLE / CONFLICTED
        ↓
MSI
        ↓
Enrollment Request
        ↓
AUTO / MANUAL
        ↓
Claim
        ↓
Provisioning
        ↓
EndpointAgent service
        ↓
Gateway WSS
        ↓
Device Context
        ↓
Готово
```

Русифицировать пользовательские подписи.

Технические состояния допустимо показывать вторичным текстом.

---

# 17. Installer Release Registry

Исследовать текущую release/publishing infrastructure.

Console требуется безопасная серверная projection установочных релизов.

Если такого persistent registry нет, добавить минимальную immutable metadata-модель для Windows Setup releases.

Не хранить binary в PostgreSQL.

Binary должен оставаться в существующем/выбранном HTTPS artifact store.

Минимальные metadata:

```text
version
agent_version

artifact_url
filename

setup_sha256
msi_sha256

source_commit
msi_source_commit

authenticode_status
authenticode_publisher

msi_authenticode_status
msi_authenticode_publisher

created_at
retired_at
```

Если repo уже имеет другой canonical artifact ownership mechanism, использовать его вместо создания дубликата.

Unsigned release должен явно отображаться:

```text
Только для тестирования
```

Production-approved signed artifact:

```text
Подпись проверена
```

---

# 18. Enrollment Campaigns

Сохранить существующую domain model.

UI карточка кампании:

```text
Windows — рабочие станции администрации

Режим:
AUTO

Разрешённые сети:
192.168...

Допустимые установщики:
...

Использовано:
31 / 200

Действует до:
...

Состояние:
Активна
```

Создание/редактирование должно использовать существующие policy contracts.

Если Installer Release Registry реализован, `allowed_installer_releases` выбирать из известных релизов, а не только вводить вручную.

---

# 19. Enrollment Requests

Показать очереди:

```text
Ожидают подтверждения
Требуют проверки
Отклонены
Завершены
```

Request card должна включать безопасные уже существующие evidence:

* hostname;
* platform;
* manufacturer;
* model;
* serial;
* MAC evidence;
* source IP;
* installer release;
* status;
* reason;
* created time.

Действия:

```text
Одобрить
Отклонить
```

Claims, capabilities и credentials не показывать.

---

# 20. Enrollment Request detail

Показывать lifecycle:

```text
Создан
↓
Проверен
↓
Автоматически одобрен / Ожидает решения
↓
Claim сформирован
↓
Регистрация устройства
↓
Ожидание WSS
↓
Завершено
```

Показать:

* campaign;
* operator decision;
* device UUID после регистрации;
* completion state.

Не показывать raw claim.

---

# 21. Releases & Updates

Route:

```text
/admin/updates
```

Вкладки:

```text
Релизы агента
Развёртывания
История
```

---

# 22. Agent releases

Список immutable UpdateBuild records.

Для каждого:

* version;
* platform;
* channel;
* SHA-256;
* size;
* artifact name;
* release notes;
* created date;
* количество устройств на версии, если projection позволяет определить это безопасно.

Не позволять редактировать immutable manifest.

---

# 23. Update admin read API

Текущий update admin API преимущественно mutation-oriented.

Добавить безопасные admin read projections, если их ещё нет:

```text
GET /api/admin/updates/builds

GET /api/admin/updates/builds/{build_id}

GET /api/admin/updates/rollouts

GET /api/admin/updates/rollouts/{rollout_id}
```

Rollout detail должен содержать bounded target projections и summary counts.

Не возвращать внутренние secrets.

---

# 24. Creating rollout

UI wizard:

```text
Версия

Тип:
Canary
Массовое обновление

Устройства

Причина
```

Перед созданием показать точный список targets.

Не обходить существующее правило:

```text
bulk requires completed canary
```

---

# 25. Rollout detail

Показать:

```text
Версия
Mode
Status
Created
Started
Completed

Targets:
Assigned
Requested
Scheduled
Applied
Failed
Rolled back
Cancelled
```

Русские подписи.

Actions только через существующие lifecycle operations:

```text
Приостановить
Продолжить
Создать откат
```

Если explicit manual completion остаётся доступен domain layer, UI должен учитывать auto-completion при terminal target state и не требовать от оператора ненужного ручного действия.

---

# 26. Rollback

Rollback всегда создаётся как новый rollout.

Никогда:

* не переписывать предыдущий rollout;
* не изменять immutable build;
* не подменять версию существующего release.

UI должен ясно показывать:

```text
Откат с 3.x.y на 3.x.z
```

и triggering rollout.

---

# 27. Operations

Route:

```text
/admin/operations
```

Глобальный журнал Endpoint Operations.

Фильтры:

* period;
* device;
* capability/type;
* status.

Показывать:

* время;
* устройство;
* тип;
* статус;
* source/owner;
* duration;
* completion.

---

# 28. Operation detail

Обычная diagnostic operation:

```text
Сбор диагностики

Устройство
Capability
Создано
Доставлено
Запущено
Завершено

Safe result
```

Module operation:

```text
Проверка Directum
network.directum.check@1.0.0

1. DNS
Успешно

2. Ping
Успешно

3. TCP 443
Ошибка
```

Использовать существующие safe result projections.

Не отдавать browser raw Agent command/result payload.

---

# 29. Admin Operations API

Если browser-compatible admin read/action facade отсутствует, добавить:

```text
GET /api/admin/operations

GET /api/admin/operations/{operation_id}
```

и необходимые admin actions.

Не дублировать business logic из service API.

Admin facade должен вызывать тот же domain layer.

---

# 30. Modules

Route:

```text
/admin/modules
```

Вкладки:

```text
Модули
Возможности агента
Лаборатория
```

---

# 31. Capability Catalog

Console должна отображать canonical Endpoint module capability registry.

На baseline ожидается закрытый catalog с capabilities наподобие:

```text
dns.resolve
network.ping
tcp.connect
route.get
adapter.list
system.service_status
```

Не hardcode этот список во frontend.

Получать его с backend.

Показывать:

* русское display name;
* capability ID;
* supported platforms;
* minimum Agent version;
* risk;
* consent requirement;
* parameter descriptors.

---

# 32. Critical Module Platform preflight

Перед разработкой Module Workbench проверить согласованность:

```text
MODULE_CAPABILITY_REGISTRY
```

с persistence constraints.

На исследованном baseline существует потенциально критический drift:

canonical catalog знает:

```text
dns.resolve
network.ping
tcp.connect
route.get
adapter.list
system.service_status
```

но CHECK constraint `endpoint_operation_steps.capability` может разрешать только:

```text
dns.resolve
network.ping
tcp.connect
```

Codex обязан проверить актуальный `main`.

Если drift существует:

1. добавить forward-only Alembic migration;
2. синхронизировать DB constraint с поддерживаемым module-step capability set;
3. добавить regression test;
4. исключить возможность повторного silent drift.

Предпочтительно сделать test, который сравнивает persistence-supported capabilities с canonical registry либо с явно определённым canonical executable subset.

Не изменять старые migrations.

---

# 33. Module Workbench

Console не должна содержать Python/PowerShell editor.

Модуль — declarative recipe.

Создание модуля:

```text
Название

Module key

Version

Platforms
```

Inputs:

```text
host      string
port      integer
```

Steps добавляются из Capability Catalog.

Пример UI:

```text
1. DNS resolve

target:
input.host

family:
ipv4
```

Следующий:

```text
2. TCP connect

target:
input.host

port:
input.port
```

UI должен генерировать существующий строгий `EndpointRecipeModuleSpecV1`.

Не добавлять frontend-only recipe language.

---

# 34. Current recipe constraints

Console обязана уважать текущие backend limits.

На исследованном baseline:

* максимум 8 inputs;
* максимум 8 steps;
* только последовательное выполнение;
* только input/literal bindings;
* без branching;
* без loops;
* без expressions;
* без output chaining;
* без shell;
* без Python;
* без PowerShell;
* без arbitrary executable;
* без dynamic imports.

Не расширять recipe language в рамках Endpoint Console v1.

---

# 35. Module lifecycle

UI должен отражать существующий lifecycle:

```text
Черновик
    ↓
Проверен
    ↓
Лабораторные испытания
    ↓
Испытания приняты
    ↓
Опубликован
```

Дополнительные terminal lifecycle states:

```text
Устарел
Отозван
```

Не имитировать state transitions во frontend.

Endpoint backend остаётся authority.

---

# 36. Module version history

Для каждого ModuleDefinition показать версии:

```text
1.0.0    published
1.1.0    validated
2.0.0    draft
```

Добавить backend read projection для списка всех versions, если его сейчас нет.

Существующий `GET /api/v1/modules/{module_key}` может возвращать только latest version и не является достаточной operator projection.

---

# 37. Validation

Action:

```text
Проверить модуль
```

Показать:

* succeeded / failed;
* error codes;
* warning codes;
* validator version;
* completed time.

Русифицировать известные ошибки в UI, сохраняя технический code вторичным текстом.

---

# 38. Module Lab

После успешной validation позволить выбрать совместимое test Device.

Пример:

```text
Windows

WIN-LAB-01

Запустить испытание
```

Показать step results.

Использовать существующий lab-operation mechanism.

Live-test evidence должно оставаться Endpoint-derived.

Не позволять UI вручную формировать fake lab evidence.

---

# 39. Accept Labs / Publish

После успешных platform tests:

```text
Принять испытания
```

затем:

```text
Опубликовать 1.0.0
```

Использовать текущие server lifecycle gates.

Не добавлять bypass кнопок.

---

# 40. Running modules from Device page

Вкладка:

```text
Модули
```

на Device Detail должна показывать только:

* published modules;
* совместимые с Device platform;
* capabilities которого поддерживаются данным Agent;
* удовлетворяющие minimum Agent version и feature gates.

Не показывать несовместимый module как обычную запускаемую action.

Для несовместимого модуля допустимо показать:

```text
Недоступен

Требуется Agent >= X
```

---

# 41. Module version vs Agent version invariant

Документировать и покрыть тестами следующий принцип:

> Создание новой ModuleVersion не требует выпуска новой версии Endpoint Agent, если используемые capabilities уже поддерживаются целевым Agent runtime.

Новая Agent version требуется только при изменении/добавлении runtime capability либо его wire/behavior contract.

Module definition и ModuleVersion остаются серверными immutable recipes.

Они не устанавливаются на endpoint как Python/package/plugin.

---

# 42. Update vs Modules invariant

Update subsystem предназначен для доставки:

```text
Agent Runtime
+
новых Agent capabilities
```

Update subsystem не должен становиться generic module/plugin delivery system.

Запрещено в рамках Console v1 создавать:

```text
modules_packages downloaded from server
dynamic Python modules
dynamic shell scripts
dynamic PowerShell
generic runtime plugin loader
```

Module execution остаётся:

```text
Server Recipe
     ↓
typed primitive commands
     ↓
Gateway WSS
     ↓
Agent capabilities
```

---

# 43. Audit

Route:

```text
/admin/audit
```

Добавить read-only administrative API, если его нет:

```text
GET /api/admin/audit/events
```

Требования:

* pagination;
* bounded page size;
* фильтры.

Фильтры:

```text
Период
Actor
Action
Object kind
Object ID
Request ID
```

Показывать:

* created time;
* actor;
* action;
* object;
* sanitized details.

AuditEvent остаётся immutable.

Никаких update/delete actions для audit.

---

# 44. Cross-links

Console должна позволять переход:

```text
Device
→ Operation

Device
→ Rollout

Device
→ Audit

Enrollment Request
→ Device

Rollout
→ Device

Module
→ Module Operation

Audit Event
→ соответствующий объект
```

Не хранить для этого duplicate business state, если связь уже есть в Endpoint persistence.

---

# 45. Admin authorization

Исследовать существующую AdminUser scopes модель.

Существующий:

```text
updates:write
```

сохранить.

Для Console v1 разрешено добавить необходимые granular scopes, например:

```text
context:collect
operations:write
modules:write
modules:publish
```

только если это соответствует текущей auth architecture.

Не менять authorization model без необходимости.

Read-only administrative pages могут оставаться доступными authenticated administrator, если это соответствует существующей модели.

Enrollment mutations пока допустимо оставить под текущим `require_admin`, если отдельное разделение scope не требуется для поставки Console v1.

---

# 46. API design rules

Новые `/api/admin/*` routes:

* используются browser Console;
* используют admin session;
* CSRF защищает mutations;
* не используют browser-supplied service bearer;
* возвращают bounded typed DTO;
* не возвращают ORM models напрямую;
* не возвращают secrets;
* имеют pagination для потенциально больших списков;
* используют domain services, а не дублируют business logic.

Если existing service API projection уже подходит, допускается извлекать общую projection/service функцию и использовать её обеими поверхностями.

---

# 47. Performance constraints

Не создавать:

* N+1 DB queries;
* отдельный запрос Context на каждую строку Device list;
* отдельный update query для каждого Device;
* unrestricted Audit listing;
* unrestricted Operations history.

Списковые pages должны поддерживать bounded pagination/filtering.

Dashboard должен использовать агрегированные queries/projections.

---

# 48. UX requirements

Console предназначена для ежедневной работы системного администратора.

Обязательные состояния:

```text
loading
empty
error
stale
permission denied
offline
```

Не скрывать ошибку backend как пустой список.

Если данные устарели, показывать это явно.

Например:

```text
Данные получены 2 часа назад
```

а не отображать их как текущие.

Dangerous actions:

* rollout;
* rollback;
* module publish;
* enrollment deny;

должны иметь явное подтверждение.

---

# 49. Visual direction

Интерфейс должен быть плотным административным desktop-first UI.

Не делать marketing landing page.

Основные паттерны:

* sidebar;
* header;
* cards;
* compact tables;
* badges;
* tabs;
* drawers/dialogs;
* timeline;
* detail panels.

Приоритет:

1. читаемость;
2. скорость поиска информации;
3. техническая прозрачность;
4. единообразие.

Поддержать адекватную работу на стандартном desktop monitor.

---

# 50. Accessibility

Минимум:

* keyboard navigation;
* semantic forms;
* labels;
* focus state;
* usable contrast;
* buttons are actual buttons;
* actions not represented only by colour.

---

# 51. Non-goals

Не реализовывать в Endpoint Console v1:

* Helpdesk UI;
* `web_ovpn` functionality;
* remote shell;
* arbitrary terminal;
* arbitrary PowerShell;
* arbitrary Python;
* generic command runner;
* file manager;
* software distribution platform;
* Remote Desktop;
* Remote Assist redesign;
* LLM;
* AI agent;
* automatic ticket generation;
* dynamic plugin system;
* arbitrary module package delivery;
* второй Agent WebSocket;
* browser access to raw Device credential;
* browser access to raw service token.

---

# 52. Compatibility invariants

Console work must not break:

* Agent Gateway WSS;
* Device identity;
* existing enrollment Setup;
* current Update protocol;
* update rollback;
* `web_ovpn` Endpoint SDK;
* Helpdesk Endpoint contracts;
* existing `/api/v1/*` service contracts;
* existing OpenAPI artifacts;
* existing strict TLS assumptions.

Changes to public service contracts must be additive unless a separately proven bug repair requires otherwise.

---

# 53. Acceptance Criteria

Endpoint Console v1 считается функционально завершённой, если администратор через русский web-интерфейс может выполнить следующую цепочку:

```text
Войти в Endpoint Console
        ↓
Посмотреть состояние fleet
        ↓
Открыть список устройств
        ↓
Открыть конкретный Device
        ↓
Посмотреть inventory/context/session
        ↓
Посмотреть изменения устройства
        ↓
Запросить refresh Context
        ↓
Открыть установочный релиз
        ↓
Управлять Enrollment Campaign
        ↓
Одобрить Manual Enrollment Request
        ↓
Увидеть зарегистрированное устройство
        ↓
Посмотреть Agent releases
        ↓
Создать canary rollout
        ↓
Посмотреть состояние targets
        ↓
Выполнить rollback при необходимости
        ↓
Посмотреть Operations
        ↓
Создать ModuleVersion
        ↓
Validate
        ↓
Lab execution
        ↓
Accept labs
        ↓
Publish
        ↓
Запустить published module на Device
        ↓
Посмотреть step results
        ↓
Просмотреть связанные Audit events
```

Без SQL, SSH и ручных HTTP API вызовов для этих штатных действий.

---

# 54. Module-specific Acceptance Criteria

Обязательно доказать:

1. Создание нового declarative module поверх существующих capabilities не меняет `AGENT_VERSION`.
2. Module recipe не копируется и не устанавливается в Agent filesystem как executable code.
3. Agent получает только typed primitive command.
4. Новый unsupported capability не может выполниться.
5. Module compatibility учитывает minimum Agent version.
6. DB persistence не расходится с canonical capability catalog.
7. Lab evidence нельзя сфабриковать через Console API.
8. Publish невозможен до выполнения существующих lifecycle gates.

---

# 55. Security Acceptance Criteria

Проверить негативными тестами:

* unauthenticated `/admin` access;
* invalid admin session;
* CSRF failure;
* admin without mutation scope;
* browser cannot access service-only functionality через cookie вместо service bearer;
* browser response does not leak service token;
* Enrollment responses do not leak claims;
* Audit response не содержит secret fields;
* update metadata не раскрывает protected credential material;
* raw Agent command/result payload не появляется в Console;
* module UI не может отправить arbitrary capability ID;
* frontend не может обойти backend module state machine.

---

# 56. Verification Requirements

Codex обязан выполнять проверки инкрементально, а не только в конце.

Минимальный final gate:

## Backend

```text
focused pytest for every modified subsystem
contract tests
context tests
enrollment tests
update tests
operation tests
module tests
audit tests
architecture guards
PostgreSQL migration tests
```

## Contracts

```text
python tools/contracts/generate_contract_artifacts.py --check
```

или актуальная canonical команда репозитория.

## Python

```text
compileall
git diff --check
```

и repo-standard lint/checks.

## Frontend

```text
npm install / npm ci according to repo policy
typecheck
unit tests
production build
```

## Browser

Добавить browser E2E проверки минимум для:

1. login;
2. dashboard;
3. devices list;
4. device detail;
5. context refresh;
6. enrollment queue;
7. update rollout view;
8. module authoring;
9. module validation/lab/publish;
10. audit filtering.

Использовать реальный backend contract, а не shallow mock-only acceptance.

---

# 57. Russian UI verification

Добавить regression guard, который проверяет основные Console pages на отсутствие случайных пользовательских английских labels.

Допустимыми исключениями являются:

* технические identifiers;
* capability IDs;
* schema/version codes;
* ОС/бренды;
* raw module keys.

Основные action labels и navigation должны быть русскими.

---

# 58. Documentation

После реализации обновить:

* `PLANS.md`;
* relevant architecture docs;
* deployment/runbook Console;
* Windows enrollment runbook при изменении operator flow;
* Module Platform docs;
* CODEMAP/docs согласно repository rules.

Документировать:

```text
/admin
```

как canonical Endpoint operator surface.

Старый `/admin/enrollment` не должен оставаться отдельным конкурирующим UI.

Он должен либо стать маршрутом новой Console, либо безопасно redirect'иться в соответствующий раздел после browser regression verification.

---

# EXECUTION

## 59. General execution rules

Codex должен использовать agent-first execution.

### Сначала исследование

Не начинать с генерации десятков файлов.

Сначала:

* repo discovery;
* dependency mapping;
* API inventory;
* DB schema inventory;
* tests;
* deployment architecture.

### Затем implementation plan

Сформировать собственный конкретный implementation plan, основанный на текущем репозитории.

Implementation plan должен разбить работу на независимые reviewable phases.

---

# 60. Recommended release train

Фактическое разбиение скорректировать после repo discovery, но ориентироваться на следующие этапы.

## Phase 0 — Canon and invariant repair

* актуализировать понимание `main`;
* проверить capability catalog / DB drift;
* исправить drift additive migration;
* regression test;
* при необходимости актуализировать `PLANS.md`.

Не смешивать эту миграцию с огромным frontend commit.

---

## Phase 1 — Console foundation

* frontend project;
* production bundling;
* admin login/session integration;
* CSRF client;
* router;
* layout;
* Russian localization;
* error handling;
* frontend testing foundation.

Pages:

```text
/admin/login
/admin
```

---

## Phase 2 — Dashboard + Devices

Backend:

* admin fleet projections;
* Device list;
* Device detail;
* Context;
* Context history/diff;
* Context refresh.

Frontend:

* dashboard;
* Device table;
* Device page;
* tabs.

После Phase 2 Console уже должна быть полезна для эксплуатации.

---

## Phase 3 — Installation + Enrollment

* Installer Release projection/registry;
* installer page;
* installation lifecycle;
* Campaign UI;
* Enrollment Request queue;
* approve/deny;
* request detail;
* интеграция существующего `/admin/enrollment`.

---

## Phase 4 — Releases + Updates

* builds read API;
* rollouts read API;
* rollout detail;
* create canary/bulk;
* pause/resume;
* rollback;
* target states;
* Device update tab.

---

## Phase 5 — Operations

* global operation list;
* operation detail;
* Device operation history;
* context operation;
* module operation step detail;
* queued cancel where supported.

---

## Phase 6 — Module Workbench

* capability catalog;
* module list;
* module versions;
* recipe editor;
* validation;
* validation history;
* lab device selection;
* lab execution;
* live test evidence;
* accept labs;
* publish;
* deprecate;
* revoke only if current backend actually supports it or add it as a separately validated lifecycle change;
* Device compatible modules;
* module execution.

Не придумывать state transition, которого нет в domain model/API.

---

## Phase 7 — Audit

* paginated admin Audit API;
* filters;
* Audit UI;
* object cross-links.

---

## Phase 8 — Production hardening

* permissions;
* negative security tests;
* Playwright;
* frontend build;
* backend full relevant suites;
* migrations;
* OpenAPI;
* docs;
* production deployment verification.

---

# 61. Incremental implementation rule

Каждый phase должен:

1. иметь failing/acceptance tests до или вместе с реализацией;
2. проходить focused verification;
3. не оставлять полуработающий parallel architecture;
4. быть reviewable отдельно;
5. сохранять production feature safety.

Не делать один гигантский commit всей Console.

---

# 62. Final report required from Codex

После завершения предоставить:

## Repository state

* starting SHA;
* ending SHA;
* branch;
* migration head.

## Implemented

По подсистемам:

```text
Console foundation
Devices
Context
Enrollment
Installer
Updates
Operations
Modules
Audit
```

## API

Полный список добавленных/изменённых admin routes.

## Database

Все migrations и их назначение.

## Frontend

Структура и production build.

## Security

Какие auth/CSRF/RBAC/redaction guards проверены.

## Tests

Точные команды и результаты.

## Browser verification

Какие реальные сценарии пройдены.

## Remaining risks

Явно перечислить всё, что:

* не реализовано;
* feature-gated;
* требует production acceptance;
* требует Windows fleet validation;
* требует отдельного следующего этапа.

Не объявлять Console production-ready, если release/deployment/browser gates фактически не пройдены.
