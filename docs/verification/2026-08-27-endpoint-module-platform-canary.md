# Endpoint Module Platform staging canary — 2026-08-27

## Итог

План завершён в изолированном staging-контуре. Версия
`network.canary.check@1.0.0` прошла реальные лабораторные операции на ALT Linux
и Windows, была переведена в `lab_accepted`, затем в `published`.

Продакшен не изменялся. После проверки все временные разрешения для сетевых
проб были восстановлены до исходного состояния, а staging-службы остались
активны.

## Цели и границы

Целью было проверить сквозной жизненный цикл Endpoint Module Platform:

1. подготовить допустимый рецепт `network.canary.check@1.0.0`;
2. выполнить ограниченные `dns.resolve`, `network.ping` и `tcp.connect` на
   выделенных ALT и Windows агентах;
3. записать immutable live-test evidence для `linux_amd64` и
   `windows_amd64`;
4. принять лабораторные результаты и опубликовать модуль;
5. снять временную конфигурацию canary и проверить состояние служб.

Проверялись только staging Endpoint Platform, staging Helpdesk и выделенные
агенты. Рабочие production-сервисы, их данные и конфигурация не затрагивались.

## Подготовка

- Рецепт использует только разрешённые каталогом примитивы и строго типизированные
  входы `target: string` и `port: integer`.
- Для модульного адаптера Helpdesk добавлено отдельное service credential поле;
  диагностический credential не используется для module API.
- Endpoint execution и network primitives были включены только на время canary.
- На ALT на время проверки были разрешены staging CIDR и `CAP_NET_RAW` через
  временный systemd drop-in. На Windows на время проверки был задан machine-level
  allowlist той же staging подсети.
- Временные изменения основывались на заранее созданных точных backup-файлах.

## Фактические лабораторные операции

| Платформа | Операция | Результат |
| --- | --- | --- |
| `linux_amd64` | `91b74333-e3da-43b5-872e-e62d17296b57` | `dns.resolve`, `network.ping` и `tcp.connect` к staging HTTPS/443 — `succeeded`; live-test записан как `passed`. |
| `windows_amd64` | `1e23a730-553b-47cd-b86d-2ed597bc077c` | `dns.resolve`, ping без потерь и TCP/443 — `succeeded`; live-test записан как `passed`. |

После двух passing evidence Endpoint Platform вернул:

1. `POST .../accept-labs` → `lab_accepted`;
2. `POST .../publish` → `published`.

Финальное чтение версии подтвердило state `published`, оба supported platform и
неизменённый ограниченный рецепт.

## Исправление, найденное во время Windows canary

Первая Windows операция `e392108f-e72f-44a7-a968-2558c889f0f8` реально
выполнила все сетевые шаги, но сервис передал в Gateway hello платформу
`linux_amd64`. Причина была в том, что runtime наследовал platform из
Linux-only compatibility hello.

Исправление в `pc_agent/runtime/application.py` теперь формирует native
platform при создании hello (`windows_amd64` на Windows, `linux_amd64` на
Linux). Добавлен тест Windows-варианта hello. Для доставки изменения на
Windows был подготовлен и установлен проверяемый MSI `3.2.31` с versioned
runtime selector и release sidecar; служба после установки была `Running`.

Первая запись сохранена как immutable историческое evidence, поэтому её нельзя
и не следует переписывать. Она не использовалась как Windows-доказательство:
последующая операция `1e23a730-553b-47cd-b86d-2ed597bc077c` корректно
зафиксирована сервером как `windows_amd64` и именно она закрыла Windows gate.

## Проверки

- `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py -q` —
  `33 passed`.
- `python -m pytest tests/packaging/test_initial_runtime_contract.py -q` —
  `9 passed`.
- `python -m pytest pc_agent/tests/windows/test_context_profiles.py -q` —
  `3 passed`.
- `python -m pytest pc_agent/tests/ -q` с исключением двух независимых
  модулей, чьи build-helper scripts отсутствуют в этой ветке —
  `936 passed, 8 skipped`.
- Проверены manifest и staged runtime tree для Windows MSI; повторная
  проверяемая MSI-сборка завершилась успешно.
- После rollback Endpoint API `/healthz` вернул database-backed `ok`; Endpoint
  service, worker и Helpdesk staging service были `active`.
- ALT agent и Windows `EndpointAgent` после rollback были `active`/`Running`.

## Исходный код и release evidence

| Commit | Назначение |
| --- | --- |
| `63ffb717705f0ebe83de29559da3877c85472431` | Native Gateway platform в hello агента. |
| `352a5f320831458d8b1f232d364a0adcabdb4d51` | Версия Windows canary `3.2.31`. |
| `b2c790ee784209c90ff0ec3a87f5aa81622f0ae2` | Approved immutable Windows runtime manifest. |
| `334107fc7d0544bc8750fe876c4dd47270ae1569` | Воспроизводимый runtime tree fingerprint. |
| `863383c0f7c2a77bed185079947e867cac8533ca` | Golden Windows context-profile для `3.2.31`. |

Установленный Windows MSI selector зафиксировал runtime `3.2.31` и source
revision `334107fc7d0544bc8750fe876c4dd47270ae1569`; последующий commit меняет
только тестовый golden fixture и не меняет runtime payload.

## Rollback и конечное состояние

Восстановлены точные staging backup-конфигурации Endpoint и Helpdesk. С ALT
агента сняты временные `AmbientCapabilities` и сетевой drop-in. На Windows
удалён machine-level `ENDPOINT_AGENT_NETWORK_PROBE_ALLOWED_CIDRS`; служба
перезапущена и работает.

Модуль остаётся опубликованным в staging намеренно: это итоговая проверяемая
запись жизненного цикла, а не временный configuration flag.

## Остаточные замечания

- Immutable ошибочно классифицированная первая Windows live-test запись
  остаётся в аудите; корректная Windows evidence записана отдельной операцией
  и использована при приемке.
- Scoped module service credential остаётся защищённым root-only staging
  ресурсом. Для окончательного закрытия отдельного staging-окружения требуется
  штатная процедура отзыва или ротации credential, а не удаление файла без
  revoke.
- Два orphaned agent-package теста, импортировавшие намеренно исключённый из
  Endpoint Helpdesk `scripts/`, удалены перед полным CI. Они не могли
  выполняться в минимальном Endpoint checkout и не покрывали Endpoint runtime.
