# Yandex Browser Sensor: диагностика установки на test-agent-win

Дата: 2026-09-25. Тестовая машина: `test_agent_win@192.168.101.120`.
Исходный `origin/main`: `26e1383ff294197bf6d0265d2e9f84e220dcce20`.
Ветка: `codex/yandex-browser-sensor-diagnostics`.

## Вывод

Первый сбой находится на границе принятия политики браузером. Yandex Browser
показывает локальную машинную `ExtensionInstallForcelist`, но в тестовом
контексте добавляет к идентификатору расширения префикс `[BLOCKED]` и сообщает
`ExtensionInstallForcelist[0]. Некорректный идентификатор расширения`.
Расширение не устанавливается, а браузер не запрашивает Endpoint XML или CRX.
По диагностической классификации это категория **A: ошибка политики**:
запись видна в браузере, но отвергнута при проверке значения. Категория B
требует статуса `OK`, которого здесь нет.

Это поведение согласуется с документированным ограничением Yandex: в Windows
`ExtensionInstallForcelist` и `ExtensionSettings` с принудительной установкой
работают только при задании внутри домена или через Консоль управления. VM
находится в `WORKGROUP`; страница политик сообщает `Не управляется`. Прямой
доменный или консольный тест на этой VM невозможен, поэтому работающую
альтернативную схему здесь не объявляем проверенной.

На ранее проверенной рабочей станции, согласно переданному исходному описанию,
эта политика имела статус `OK`, а не ошибку. Поэтому результат данной VM не
доказывает причину прежнего случая и не заменяет его отдельную диагностику.

## Исходное состояние VM

| Свойство | Наблюдение |
| --- | --- |
| ОС | Windows 11 Enterprise LTSC, версия `10.0.26100`, build `26100` |
| Компьютер | `DESKTOP-9ST5HO2`, `WORKGROUP`, `PartOfDomain=False` |
| Пользователь | `DESKTOP-9ST5HO2\test_agent_win`, не доменный |
| Yandex Browser | `C:\Program Files\Yandex\YandexBrowser\Application\browser.exe`, `26.8.0.1774` |
| Выпуск | `26.8.0.1774 corp (64-bit)` на `browser://help`: бесплатный выпуск Браузера для организаций, не `corp-ext` |
| Установленный пакет | `Yandex (All Users)`, издатель `Yandex`, версия `26.8.0.1774` |
| Chrome | Не обнаружен среди установленных пакетов; для этого теста не требовался |
| Начальные политики Yandex | HKLM/HKCU `SOFTWARE\Policies\YandexBrowser` отсутствовали; `browser://policy` показывал `Политики не заданы` |
| Начальные расширения | В обычном профиле был `Extension for CAdES Browser PlugIn` (`epebfcehmdedogndhlcacafjaacknbcm`); Endpoint Sensor отсутствовал |
| Native Messaging | Регистрации Endpoint в `HKLM/HKCU\SOFTWARE\Chromium\NativeMessagingHosts` не было; существующие Microsoft host в Google Chrome сохранены |

Тест выполнялся в отдельном профиле `%TEMP%\endpoint-yandex-diagnostic\gui-baseline`.
Обычный профиль и его расширение не редактировались. До эксперимента были
сохранены снимки `browser://version`, `browser://policy` и
`browser://extensions`; `browser://help` снят позднее для определения выпуска.

## Артефакты с VM

Оба URL запрошены вручную с VM **до** применения политики. `curl` без `-k`,
с `--ssl-revoke-best-effort`: цепочка CA и имя хоста проверены
(`ssl_verify_result=0`); сетевой источник списка отзыва был недоступен
Schannel, поэтому проверка отзыва была best effort. Это только проверка
доступности артефактов, не доказательство установки браузером.

| Артефакт | HTTP | Content-Type | Длина | SHA-256 |
| --- | --- | --- | ---: | --- |
| `update.xml` | 200 | `application/xml` | 299 | `B46F5D994732F588FB5904BC8FDBD9A40224F92409B47D84C1D4A31E12C7ED27` |
| `sensor.crx` | 200 | `application/x-chrome-extension` | 5735 | `0885655086E322D5C13BD90CF4895A8BBC772F28C102C0180447430123392279` |

XML ссылается на `kkkoaifoohdbdaccmnnoagedifflbide`, версию `0.1.0`
и `https://endpoint.sosnadmin.local/api/v1/browser-sensor/releases/0.1.0/sensor.crx`.
DNS на VM разрешает `endpoint.sosnadmin.local` в `192.168.100.19`.

## Контролируемый тест существующего механизма

В `2026-09-25T14:23:21Z` на VM создана единственная запись `REG_SZ`:

```text
HKLM\SOFTWARE\Policies\YandexBrowser\ExtensionInstallForcelist
1 = kkkoaifoohdbdaccmnnoagedifflbide;https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml
```

После `Повторно загрузить политики` и повторно после полного перезапуска
изолированного браузера (`2026-09-25T14:26:18Z`) `browser://policy` показывал:

| Поле | Значение |
| --- | --- |
| Политика | `ExtensionInstallForcelist` |
| Источник | `Платформа` |
| Объект применения | `Локальный компьютер` |
| Уровень | `Обязательная` |
| Фактическое значение | `[BLOCKED]kkkoaifoohdbdaccmnnoagedifflbide;https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml` |
| Ошибка | `ExtensionInstallForcelist[0]. Некорректный идентификатор расширения` |
| Управление браузером | `Не управляется`; регистрации домена нет |

`browser://extensions` после перезапуска по-прежнему содержал только CAdES,
без Endpoint Browser Sensor. В production Nginx access log от
`192.168.101.120` для `/api/v1/browser-sensor/` были лишь ручные XML и CRX
запросы `curl/8.21.0` в `14:21:42Z`; после применения политики автоматических
запросов от VM не было. В browser NetLog тестового профиля не было строк с
`endpoint.sosnadmin.local` или `browser-sensor`.

| Граница | Доказательство | Результат |
| --- | --- | --- |
| Выпуск Yandex определён | `browser://help`: `26.8.0.1774 corp` | PASS |
| Политика присутствует | HKLM значение и строка в `browser://policy` | PASS |
| Политика принята без ошибки | `[BLOCKED]`, ошибка идентификатора | FAIL: первый сбой |
| Автоматический XML | Access log: только ручной `curl` до политики; NetLog: 0 совпадений | FAIL |
| XML принят браузером | Нет автоматического запроса | Не достигнуто |
| Автоматический CRX | Access log: только ручной `curl` до политики | Не достигнуто |
| CRX установлен | `browser://extensions`: Endpoint отсутствует | Не достигнуто |
| Extension ID в runtime | Endpoint отсутствует | Не достигнуто |
| Native host запущен | Расширение отсутствует | Не достигнуто |
| Bridge Hello | Расширение отсутствует | Не достигнуто |
| Heartbeat | Расширение отсутствует | Не достигнуто |

## Документация и поддерживаемый путь

- [Yandex: ExtensionInstallForcelist](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist): на Windows политика работает только внутри домена или через Консоль управления; допускает `extension_id;update_url` и XML для закрытого контура.
- [Yandex: ExtensionSettings](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-settings): то же ограничение домена/Консоли; поле `override_update_url` поддерживается. Поэтому локальная замена `ExtensionInstallForcelist` на `ExtensionSettings` на этой WORKGROUP VM не является обоснованным следующим экспериментом.
- [Yandex: определение выпуска](https://browser.yandex.ru/support/browser-corporate/ru/support/troubleshooting): метка `corp` на `browser://help` означает бесплатный выпуск для организаций, `corp-ext` — расширенный.
- [Yandex: настройка Windows-политик](https://browser.yandex.ru/support/browser-corporate/ru/deployment/windows/setting-policy): описаны доменные/локальные политики и Консоль управления; одних записей в локальном реестре для этой политики недостаточно.

Минимальная документированная архитектура для Yandex — внешнее управление
через подлинную доменную GPO либо доступную Консоль управления с тем же ID,
URL и подписанным Sensor `0.1.0`; режим Endpoint должен быть
`external_managed`. Доменная GPO на этой VM не тестировалась, поскольку VM
не входит в домен и изменение доменных политик вне задачи. Не утверждаем,
что переход в домен сам по себе или конкретная GPO уже доказали установку.
Следующий приёмочный тест должен показать всю цепочку
`GPO/Console → XML → CRX → installation → Native Messaging → heartbeat`
на выделенной управляемой VM. Публикация в магазине и изменение Endpoint
кода по этим данным не обоснованы.

## Изменения и восстановление

Код Endpoint, Agent, Browser Bridge, Sensor и production не изменялись.
Созданная запись политики и оба созданных раздела HKLM удалены после
сверки точного значения и отсутствия чужих записей. Временные задания,
изолированный профиль и временные файлы VM удалены. Исходный процесс Yandex
и CAdES-расширение сохранены. Версия Agent не повышалась.
