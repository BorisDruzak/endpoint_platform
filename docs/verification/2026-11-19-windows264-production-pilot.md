# Windows Setup 3.2.264. Пилот на A2-MUNSLU-N

## Результат за первые сутки

С 19 ноября 14:22:46 до 20 ноября 14:22:46 по Екатеринбургу A2-MUNSLU-N выполнил все 258 запрошенных проверок `health_v1`. Все результаты пришли до конца окна через исходную сессию .264. Новых WSS-сессий не было. Максимальный интервал между успешными запросами с учётом границ окна составил 360,43 с, 95-й перцентиль времени от запроса до завершения — 4,25 с. В 22:50 Gateway всё ещё видел свежую связь через ту же сессию и подтверждение установки № 8. [Суточная квитанция](C:/endpoint-platform-wix-build/stability-publication-preflight-20261118/windows264-first-24h-20261120T175008.json) · [Запрос к журналам доставки](C:/endpoint-platform-wix-build/stability-publication-preflight-20261118/windows264-first-24h-20261120T175008.sql)

## Какие устройства совпали с профилем пилота

20 ноября в 22:52 по Екатеринбургу за предшествующие 24 часа связь была у 23 Windows-карточек. У семи последнее подтверждённое событие установки содержало точный MSI .205 и нативный код 0. Для шести из семи удалось сопоставить имя из инвентаризации с единственным включённым объектом компьютера в Active Directory. Одна машина совпала с рабочим пилотом по редакции Windows 11 IoT Enterprise LTSC и базовой сборке 26100. В момент проверки она была вне связи.

У четырёх из семи одновременно были свежие Core и готовый Observer 1.0.11, совпадали версии .205 и отсутствовала конкурирующая операция. Из них две машины работали на Windows 10 Pro 19045, одна — на Windows 11 Enterprise LTSC 26100, у одной редакцию установить не удалось. На Enterprise LTSC раньше проверялся локальный Setup, после которого Core на VM130 остановился примерно через час. Поэтому для прямого назначения через Console сейчас подтверждены профиль и готовность одновременно у **0 из 7**. [Сверка Endpoint и каталога без имён устройств](C:/endpoint-platform-wix-build/stability-qualification-cohorts-20261119/windows264-operational-cohort-20261120T175221Z.json) · [Границы прогона VM130](2026-11-19-stab15-windows11-264-staging-preflight.md)

## Первые 12 часов после подключения

С 19 ноября 14:22:46 до 20 ноября 02:22:46 по Екатеринбургу Gateway получил
успешные результаты всех 128 запросов здоровья на A2-MUNSLU-N. Для каждого
результата запись доставки указывает на исходную WSS-сессию .264. Новых
сессий в этом окне не было. Наибольший интервал между запросами с учётом
границ окна составил 360,43 с. 95-й перцентиль времени от запроса до
завершения составил 4,224 с.
После конца окна Gateway получил очередной heartbeat той же сессии.
Карточка сохранила событие установки № 8 с нативным кодом 0.
[Квитанция за 12 часов](C:/endpoint-platform-wix-build/stability-publication-preflight-20261118/windows264-first-12h.json)
· [Запрос к журналам доставки](C:/endpoint-platform-wix-build/stability-publication-preflight-20261118/windows264-first-12h.sql)

## Установка и первые наблюдения

После обновления на карточке A2-MUNSLU-N зарегистрирован установленный Windows Support 1.1.9. В 11:44:21 UTC 19 ноября сервер видел собственный отчёт компонента от 11:44:11 и ACK 8 для .264. Политика доступа была отключена, туннель закрыт, подтверждённого операторского входа нет. Это проверка работы компонента после обновления на данном Windows 11. [Квитанция Support](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/support-readiness-20261119.json)

Для сценария чистой установки на Windows 10 build 19045 Setup .264 использует системный OpenSSH из Windows Features on Demand. Проверка на рабочей станции подтвердила Authenticode обоих артефактов. Среди 249 записей таблицы File точного MSI отсутствуют отдельные двоичные файлы OpenSSH и CAB для установки этой возможности. В тестах обработки зависимости на точном исходнике 78 проверок прошли и 3 пропущены. Чистая установка на 19045 с работающим Support требует отдельного нативного прогона. [Квитанция проверки зависимости](C:/endpoint-platform-wix-build/setup-stability-candidate-264/support-fod-local-gate-20261119.json)

19 ноября 2026 года production Console применила подписанный Setup 3.2.264 на одной карточке A2-MUNSLU-N `13f38b93-cc73-4130-b58c-41f534b1893e`. Active Directory указывает Windows 11 IoT Enterprise LTSC, а инвентаризация Endpoint подтверждает имя, сборку 26100 и x86_64. До назначения карточка имела Foundation и Core 3.2.205, Observer 1.0.11, свежую WSS и подтверждённое событие установки № 7. [AD](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/os-directory.json) · [Исходное состояние](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/trusted-login-preflight.json)

Манифест подписанного EXE зарегистрирован в каталоге Full Setup под UUID `c35e3605-60ba-4e63-9aab-9843bc3a2e73`. Административная ссылка получена из авторизованного каталога Console. Скачанный по ней EXE прошёл проверку SHA-256 и Authenticode. Серверный файл доступен сервису, размер 177 728 264 байта, SHA-256 `7c278545e6ea37e38f55d9aa954c2622f5767aba789f225551c8fb445e1749a4`. Публичная публикация кандидата выключена. [Импорт](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/setup264-operator-registration-trusted.json) · [Скачать через Console](https://endpoint.sosnadmin.local/api/admin/console/installer/releases/f2c56512-a460-4b74-bbe6-b774be65fc8a/download) · [Проверка файла](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/authorized-download-readonly.json) · [Проверка скачанного EXE](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/verified-operator-download-bytes.json)

Одно назначение `b3fab3e0-3532-432f-a6fd-cbc48a032836` и одна попытка `290cc8a8-f5a6-41b5-9d94-be32c6345eba` отработали с нативным кодом 0. Gateway принял ACK № 8 с точным MSI 3.2.264 и ссылкой на событие № 7. На той же карточке открылась новая WSS `5f1b1eaa-277b-4955-a9a9-a2d5b8f5691d`, Foundation и Core подтвердили 3.2.264. В 09:27:23 UTC назначение стало `applied / setup_post_restart_confirmed` после 182,121 секунды наблюдения. Нативное подтверждение зафиксировало сохранение идентичности и восстановление пользовательских компонентов. [Итог назначения](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/a2-264-terminal.json)

После переподключения Observer 1.0.13 и UserSensor сообщили готовность со свежими отметками времени. Уже имевшийся сбор `health_v1` завершился на новой сессии. Других назначений 3.2.264 не было, fleet-политика осталась выключенной. [Пассивная проверка health](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/a2-264-health-passive-initial.json)

Начиная с принятия назначения, серверный наблюдатель сделал 137 пассивных срезов за 70 минут. После порога в 10:37:23 UTC он видел свежий heartbeat той же WSS `5f1b1eaa-277b-4955-a9a9-a2d5b8f5691d` и ACK № 8. Разрывов сессии и пропусков опроса не зафиксировано. Измерение относится к WSS на Gateway. Uptime Windows отдельно не измерялся. [Наблюдения и нативные квитанции](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/a2-264-native-and-70min-evidence.zip)

Сервер создал квалификацию `99fc17e9-6af5-40ba-bd4c-51078142ffa1` в 10:38:54 UTC, срок действия до 19 декабря 2026 года 10:38:54 UTC. Код `native0_sensor_source_verified` привязывает точный хеш Setup, исходную Foundation 3.2.205 и принятое назначение с указанной попыткой. Нативное доказательство относится к одной карточке Windows 11 IoT Enterprise LTSC 26100 x86_64. Общим production-релизом остаётся 3.2.205. Кандидат 3.2.264 остаётся закрытым, без AUTO-кампаний. Fleet-политика ревизии 21 выключена, её целевая версия 3.2.205. Массовый запуск требует отдельного решения. [Квитанция квалификации](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/production-qualified-264.json)

Предпросмотр охвата Console проверил 53 карточки без создания назначений. Готовы 6, актуальна 1, ожидают 3, заблокированы 24, свободных слотов 0. Подписанный EXE по прямой ссылке доступен в авторизованной Console. [Предпросмотр](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/console-preview.jpg) · [Показания Console](C:/endpoint-platform-wix-build/setup-stability-candidate-264/production-pilot-a2/console-coverage.txt) · [Проверенное скачивание Setup](https://endpoint.sosnadmin.local/api/admin/console/installer/releases/f2c56512-a460-4b74-bbe6-b774be65fc8a/download)
