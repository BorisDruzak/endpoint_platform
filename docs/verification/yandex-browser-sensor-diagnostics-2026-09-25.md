# Yandex Browser Sensor: диагностика установки на test-agent-win

Дата: 2026-09-25. Тестовая машина: `test_agent_win@192.168.101.120`.
Исходный `origin/main`: `26e1383ff294197bf6d0265d2e9f84e220dcce20`.
Ветка: `codex/yandex-browser-sensor-diagnostics`.

## Вывод

Первый эксперимент выявил ошибку **конкретного способа записи** локальной
машинной `ExtensionInstallForcelist`: нумерованное значение `1 = ID;URL`
отображается с префиксом `[BLOCKED]` и ошибкой
`ExtensionInstallForcelist[0]. Некорректный идентификатор расширения`.
В этом варианте браузер не запрашивает Endpoint XML или CRX.

Последующий эксперимент по [официальной инструкции о файле](https://browser.yandex.ru/support/browser-corporate/ru/settings/policy-in-file-config)
изменил практический вывод. На той же `WORKGROUP` VM корневое строковое
значение политики со ссылкой `_FILE_` получило статус `OK`; браузер сам
запросил XML и CRX и установил Endpoint Browser Sensor `0.1.0`. Прямой JSON
в том же корневом значении и `_FILE_` в нумерованном элементе ошибку не
устранили. Детали и границы вывода приведены ниже.

В документации Yandex для Windows по-прежнему указано, что принудительная
установка расширений работает внутри домена или через Консоль управления.
Поэтому успешное наблюдение на неуправляемой VM не доказывает, что такой
вариант поддерживается в любой версии и годится для производственного
развёртывания без подтверждения вендора. Native Messaging и heartbeat не
проверялись: Agent на VM не установлен.

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
- [Yandex: настройка Windows-политик](https://browser.yandex.ru/support/browser-corporate/ru/deployment/windows/setting-policy): описаны доменные/локальные политики, Консоль управления и формы записи в реестр.
- [Yandex: настройка политик через файл](https://browser.yandex.ru/support/browser-corporate/ru/settings/policy-in-file-config): `ExtensionInstallForcelist` поддерживает LIST-файл и ссылку `[ {"_FILE_": {"name": "путь"} } ]` вместо значения политики.

Для домена и Консоли управления остаётся документированный путь. Файловый
вариант на локальной WORKGROUP VM показал установку, но статус его поддержки
для такого окружения следует уточнить у Yandex. В любом варианте полный
приёмочный тест ещё должен показать цепочку
`policy → XML → CRX → installation → Native Messaging → heartbeat`.
Публикация в магазине по этим данным не требуется.

## Дополнительный тест: политика через JSON-файл

На той же VM с Yandex Browser `26.8.0.1774 corp` создан временный файл
`C:\Users\test_agent_win\AppData\Local\Temp\endpoint-yandex-file-policy\forcelist.json`:

```json
["kkkoaifoohdbdaccmnnoagedifflbide;https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"]
```

Вместо нумерованного подраздела создано **корневое** значение `REG_SZ`
`HKLM\SOFTWARE\Policies\YandexBrowser\ExtensionInstallForcelist`:

```json
[{"_FILE_":{"name":"C:/Users/test_agent_win/AppData/Local/Temp/endpoint-yandex-file-policy/forcelist.json"}}]
```

Тестовый браузер запущен с новым изолированным профилем. `browser://policy`
показал разрешённый список `ID;URL`, источник `Платформа`, локальный компьютер,
обязательный уровень и статус **`OK`**. При этом браузер остался
`Не управляется`, а компьютер — в `WORKGROUP`. В `14:38:10Z` браузер запросил
`update.xml`, в `14:38:11Z` — `sensor.crx`; оба ответа имели HTTP 200 в Nginx
access log, User-Agent `YaBrowser/26.8.0.0`. В изолированном профиле появилась
папка расширения `kkkoaifoohdbdaccmnnoagedifflbide\0.1.0_0`, а страница
расширений показала `Endpoint Browser Sensor`. Это подтверждает принятие
политики, загрузку и установку CRX, но не работу Native Messaging.

Контрольные варианты запускались в других чистых профилях после удаления
предыдущего значения политики:

| Вариант | `browser://policy` | Запрос XML/CRX | Установка |
| --- | --- | --- | --- |
| Корневой `REG_SZ` с `_FILE_` и LIST-файлом | `OK` | Да, оба HTTP 200 | Да, `0.1.0` |
| Корневой `REG_SZ` с прямым JSON-списком `ID;URL` | `[BLOCKED]`, ошибка ID | Нет | Нет |
| Нумерованное `...\ExtensionInstallForcelist\1` со строкой `_FILE_` | Ошибка ID | Нет | Нет |

Следовательно, текущую схему Agent с владением одним нумерованным элементом
нельзя исправить простой заменой `ID;URL` на `_FILE_`. Рабочий вариант владеет
значением **всей** политики; до реализации необходимо определить, как сохранять
чужие элементы списка, обновлять файл и восстанавливать прежнее значение.
Пробный файл был в `%TEMP%` только для диагностики. Для постоянной установки
потребуется стабильный защищённый путь с доступом браузера к чтению.

Машинная политика затронула и обычный запущенный профиль: Sensor успел
установиться туда. После удаления тестового значения и перезапуска обычного
браузера Sensor из него исчез. Проверено: корневой раздел тестовой политики,
временные профили и задания отсутствуют; папка Sensor отсутствует, исходное
CAdES-расширение сохранено. Production и Endpoint Agent не менялись.

## Изменения и восстановление

Код Endpoint, Agent, Browser Bridge, Sensor и production не изменялись.
Созданные значения политики и разделы HKLM удалены после сверки точного
значения и отсутствия чужих записей. Временные задания, изолированные
профили и временные файлы VM удалены. Обычный браузер перезапущен;
его профиль и CAdES-расширение сохранены. Версия Agent не повышалась.

## Проверка обновлённого Agent 3.2.75 на той же VM

После отдельного запроса оператора собран MSI `3.2.75` из исходной ревизии
`bcb7d88b73eb60e411883a9dd5519c618b48f78e`. SHA-256 MSI:
`cb7fc440961e77f8600445f4ec0228fddf11ae6e55a3fdf61e1b6fd6266a1312`;
он совпал с release sidecar локально и после передачи по SSH. Canary-установщик
завершился успешно. Он поставил и запустил `EndpointBrowserPolicy` и
зарегистрировал Native Messaging host. Ранее выбранный runtime 3.2.67 не
принадлежал MSI, поэтому установщик штатно сохранил его выбор. После сверки
маркера MSI и SHA-256 исполняемого файла селектор переключён атомарно на
`3.2.75` с резервной копией прежнего значения. Агент запустился, выпустил
canary status с `release.version=3.2.75` и строгим WSS/TLS к
`endpoint.sosnadmin.local`. Сборщик и валидатор Windows preflight дали
`READY`.

На VM не было назначенной серверной политики `agent_managed`. Для проверки
браузера корневой указатель и LIST-файл временно созданы вручную по точному
формату Agent; это **не** доказательство живого вызова Browser Policy helper.
В изолированном профиле `browser://policy` показал обязательный машинный
`ExtensionInstallForcelist` со статусом `OK`. Появился каталог Sensor
`0.1.0_0`, но страница сведений расширения показывала `ВЫКЛ`. Попытки
переключить его через интерфейс не изменили состояние. Активный service worker,
процесс `EndpointBrowserBridge.exe` и heartbeat не подтверждены.

Это согласуется с [документацией Яндекса](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist):
на Windows принудительная установка работает только при задании политики
в домене или через Консоль управления. Тестовая VM состоит в `WORKGROUP`.
Следовательно, успешные статус политики и скачивание CRX не подтверждают
работоспособность схемы на этой VM. Полную цепочку следует испытывать на
доменной либо зарегистрированной в Консоли тестовой машине.

Временный указатель и файл удалены после сравнения с точными ожидаемыми
значениями. Изолированный профиль и задания удалены. Обычный браузер
перезапущен: Sensor исчез из его профиля, исходное CAdES-расширение осталось.
Agent `3.2.75`, его службы и штатная регистрация Native Messaging сохранены;
production Endpoint не менялся.
