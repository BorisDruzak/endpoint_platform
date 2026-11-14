# STAB-14 — Базовая линия выпуска от 14 ноября 2026

## Сервер production

- Каталог по `current` — `endpoint-platform-ed643cddf0f5-setup205-observer`.
- Исходная ревизия сервера — `ed643cddf0f5896311ab927328da980848e562fd`.
- Восстановленный снимок источников — `5bdb4a6f319628dff135919a2b6f7e819b8f4b22` в ветке `codex/endpoint-production-setup205-baseline`.
- Поверх исходной ревизии в production обнаружены два изменения. Контракт `endpoint_contracts/setup_updates.py` соответствует `cb078a6a8e69c47a7d28a8f83f1f14e1a375978b`. Правка `endpoint_server/setup_updates/service.py` восстановлена из релизного worktree и закреплена в `7b1b29d3b5486f043e6eed2eb051e9a1d050def8` вместе с регрессионным тестом.
- Все 319 файлов исходного payload из `git archive` восстановленного снимка совпали по именам и SHA-256 с production. Сравнение охватывает `endpoint_server`, `endpoint_contracts`, `browser_sensor`, `alembic.ini`, `requirements-server.txt` и четыре Python-файла `tools`, перечисленные в `build_console_server_archive.ps1`. Кеши Python исключены. SHA-256 списка `sha256sum`, отсортированного по имени, — `fc70f54afdbf832fc7218912e4acbecf604e386cb39775e6acadcf2f6af33e7a`.
- Список SHA-256 файлов `webapp/dist` совпал в исходном и активном каталогах production. SHA-256 списка — `943b3509ff6f7da1c002cbe095e398f756e961e07b31780e07c86eb64ea40b8f`. Хеш списка файлов не является хешем исходного `.tar.gz`.
- Зависимости production: Python 3.12.3, SHA-256 вывода `venv/bin/python -m pip list --format=freeze` — `5f4198b7fbd93e8664beda6293cc48d096406fb19ac7a53e7a18c628ce7a4491`, SHA-256 `requirements-server.txt` — `b0509446c698d9bd8d4e9a3a3f684623e2bbaf82c81b3df765e8f4fba52391ae`.
- Фактический `alembic_version` и `alembic heads` восстановленного снимка — `0051_staging_linux_worktime`. Рабочая ветка исправлений включает отдельную миграцию `0052_inventory_installation` из staging. При будущей подготовке деплоя потребуется проверить её отдельно.

## Установочные артефакты

- Реестр production для Windows Setup 3.2.205 указывает `f0d1d7cf2f9b59052f35bd0ba0188f8e49cc9649`. SHA-256 Setup EXE — `e4acd9c00630b1c468a1b4d8ab1db07134d9160fa07b3cd3036f6c51692bef4a`. SHA-256 MSI — `689e1d9dc0dcbd0e1943e98f27cfa88cc36fe99dbf9316e58e54d4292a1fc26f`. Значения прочитаны из реестра. Staging использует другой EXE, что отражено в [staging release](../releases/windows-3.2.205-staging.json). SHA `c9a46030` указывает на состояние рабочего дерева с отчётом о staging, его использовали как базу разработки.
- ALT native 3.2.183 — `21fc543af8d4b8b24df83f29a27e4e2eeb86c268`. Подписанные RPM, kit и manifest SHA-256 перечислены в [Linux native release](../releases/linux-3.2.183-native.json). Артефакты использованы как историческое свидетельство выпуска.

## Проверка и выпуск

На исходной ветке два добавленных случая observer 1.0.11 упали с `SetupConflict`. После восстановления правки выборка `tests/server/test_setup_target_recovery.py tests/server/test_setup_update_service.py tests/server/test_setup_fleet_policy.py` дала 188 passed на рабочей ветке и 187 passed на восстановленном серверном снимке. Оба запуска на Python 3.12.14.

GitHub Actions не вернуло запусков для `ed643cddf0f5896311ab927328da980848e562fd` и `c9a46030b77109d7462651e934f0f798af685409`. Для следующей публикации остаются обязательными CI receipt на точном SHA и сохранение хеша того серверного архива, который будет развёрнут. Проверки production выполнялись в режиме чтения.
