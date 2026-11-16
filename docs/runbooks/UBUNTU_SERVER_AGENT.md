# Отдельный клиент Endpoint для Ubuntu Server

Целевая платформа пилота — Ubuntu Server 24.04 LTS, amd64, systemd. Первые роли — `endpoint_platform` и `openvpn`. Перечень служб, томов и локальных проверок приведён в [серверном профиле](SERVER_AGENT_HEALTH.md).

Клиент использует общий код серверных проверок и существующий обмен `health_v1` с Endpoint Platform. Пакет `endpoint-agent-ubuntu` устанавливает фоновый Core в `/usr/lib/endpoint-agent-ubuntu`, служба называется `endpoint-agent-ubuntu.service`. Состояние регистрации и данные агента хранятся в `/var/lib/endpoint-agent-ubuntu` и сохраняются при обновлении и удалении пакета.

Для стенда Debian 12 amd64 соберите Core на Debian 12 с Python 3.12 и передайте
сборщику `--target debian12`. Пакет `endpoint-agent-debian` использует
собственный unit и каталог состояния, требует glibc 2.36 и объявляет
конфликт с Ubuntu-пакетом. Для установки на Proxmox требуются подписанный
APT-канал и адресная регистрация узла.

Версией Core управляет DEB. Служба использует `--package-managed-updates`, поэтому Core не запрашивает задания на обновление из общего канала Linux.

Сборка выполняется на Ubuntu 24.04 amd64 с Python 3.12 из чистого Git checkout
в отдельном виртуальном окружении без системных Python-пакетов.
На Ubuntu системный `pkg_resources` может попасть в анализ PyInstaller и
вызвать ошибку импорта при запуске уже замороженного Core.
PyInstaller сохраняет ревизию исходников в Core. Сборщик DEB сверяет её и
версию с выводом `endpoint-agent --print-build-identity` перед упаковкой.
Новые пакеты записывают в DEB и подписанный индекс APT поля
`X-Endpoint-Source-Revision`, `X-Endpoint-Python-Version` и
`X-Endpoint-PyInstaller-Version`. В той же записи `Packages` находятся
`Version` и `SHA256` точного пакета. У ранее выпущенных DEB эти поля могут
отсутствовать. Для отката используйте оригинальные пакеты.

```sh
python3.12 -m venv ../endpoint-linux-build-venv
../endpoint-linux-build-venv/bin/python -m pip install -r requirements/build-linux.txt
../endpoint-linux-build-venv/bin/python -m PyInstaller --noconfirm pc_agent/pyinstaller_endpoint_core_linux.spec
dist/endpoint-agent/endpoint-agent --print-build-identity
../endpoint-linux-build-venv/bin/python tools/build_ubuntu_agent_deb.py --core dist/endpoint-agent --output dist/ubuntu \
  --version 3.2.192 --source-revision "$(git rev-parse HEAD)"
```

1. Проверьте свободное место на хосте с учётом распаковки и отката, затем установите DEB через `apt install ./endpoint-agent-ubuntu_3.2.192-1ubuntu1_amd64.deb`.
2. Положите сертификат CA Endpoint в `/etc/endpoint-agent-ubuntu/ca.crt`. Задайте `ENDPOINT_AGENT_SERVER_ROLE=endpoint_platform` или `openvpn` в `/etc/endpoint-agent-ubuntu/site.conf`. При необходимости там же задайте `ENDPOINT_AGENT_FALLBACK_ORIGIN=https://endpoint.sosnadmin.local:8443`. Подключите файл в `[Service]` через `EnvironmentFile=/etc/endpoint-agent-ubuntu/site.conf` в `/etc/systemd/system/endpoint-agent-ubuntu.service.d/site-environment.conf` и выполните `systemctl daemon-reload`. Пакетный `agent.conf` сохраняйте в состоянии поставки, чтобы обновление могло применить новые значения по умолчанию без диалога dpkg.
3. Подготовьте для этого хоста выданные контроллером файлы `device-credential` и `enrollment-identity.json`. Поместите их в каталог состояния с владельцем и группой `endpoint-agent-ubuntu` и правами `0600`. Для первого пилота OpenVPN используйте команду ниже. Сервис DEB 3.2.192 запускается с готовой парой идентичности.
4. Выполните `systemctl enable --now endpoint-agent-ubuntu.service`. В карточке устройства проверьте свежесть профилей контекста и результаты серверной роли. Для отката установите предыдущий DEB, затем убедитесь, что контроллер видит прежнюю идентичность и нужную версию.

## Пилот OpenVPN на 192.168.100.30

Из корня репозитория на рабочей станции запустите проверку и отправьте запрос с OpenVPN.

```powershell
python -m tools.provision_ubuntu_server_pilot --check
python -m tools.provision_ubuntu_server_pilot --request
```

Команда проверяет SSH-ключ хоста `openvpn-100-30`, CA production и SHA-256 точного пакета. В уже авторизованной Console откройте «Установка и регистрация» → «Запросы регистрации» и одобрите запрос Ubuntu DEB от `192.168.100.30` с выведенным UUID. Затем выполните:

```powershell
python -m tools.provision_ubuntu_server_pilot --collect
```

Одобрение создаёт кампанию на один хост и одну установку. Хост получает claim напрямую от контроллера, временный сервис записывает защищённую пару файлов до установки DEB. После установки команда включает роль `openvpn`, резервный вход на порту 8443 и постоянный сервис. Сверьте выведенный UUID с карточкой в Console.

Если команда прервалась после выдачи claim, запустите её с `--finish` для продолжения с существующими файлами. Проверьте состояние кампании и устройства перед выдачей нового claim. Идентичность, уже полученная от контроллера, сохраняется для продолжения установки.

Для контроллера `192.168.100.19` используйте те же шаги с параметром `--target endpoint`. После установки Console должна принять роль `endpoint_platform` и результат HTTP 200 от локального API.

Для канала обновлений соберите подписанный репозиторий из новой и предыдущей версий. Публикуйте полученное дерево целиком под отдельным HTTPS-путём. Настройте источник APT для `noble main` с `Signed-By`, указывающим только на проверенный публичный ключ издателя. Перевыпускайте подписанный индекс до истечения семидневного `Valid-Until`. Перед установкой сверьте `apt-cache policy endpoint-agent-ubuntu` и версию кандидата. Для явного отката укажите предыдущую версию и `--allow-downgrades`.

При ручном обновлении или откате опубликованного DEB сначала остановите
работающую службу и дождитесь `ActiveState=inactive` и `MainPID=0`.
Выполните выбранную операцию APT, затем запустите службу и проверьте свежую
WSS-сессию с ожидаемой версией на прежней карточке. Сохраните состояние
службы, если она уже была остановлена или замаскирована. Этот порядок
исключает замену исполняемого файла в момент чтения встроенного архива
PyInstaller работающим Core.

В новых DEB входящий `preinst` ставит временный запрет запуска systemd
до распаковки и сохраняет состояние службы для `postinst`. При прерывании
установки проверьте `dpkg --audit`: для `unpacked` или `half-configured`
завершите настройку командой `dpkg --configure` для пакета. Для
`half-installed` повторите установку того же проверенного DEB. Если
установка прервалась и dpkg вернул старый пакет без поддержки запрета,
повторите установку нового проверенного DEB, чтобы штатно снять запрет.
При откате на уже опубликованный DEB используйте ручную остановку выше.

Production-источник — `https://endpoint.sosnadmin.local/downloads/ubuntu`. Публичный ключ `endpoint-ubuntu-apt.gpg` имеет отпечаток `D132784F1C7F0D78BDA2842FDE5739F7FD0AFEBE` и SHA-256 `a1718e6b042501c3a3fde1662a6c5302b6d1ced454e6230d59617d5e18c25aa8`. Ключ находится в отдельном хранилище GnuPG на рабочей станции издателя. На HTTPS-сервер переносятся подписанный индекс, проверенные пакеты и публичный ключ.

На Ubuntu 24.04 привяжите доверие к этому источнику через `Signed-By: /etc/apt/keyrings/endpoint-ubuntu-apt.gpg` и укажите сертификат CA только для хоста Endpoint:

```text
Acquire::https::endpoint.sosnadmin.local::CaInfo "/etc/apt/keyrings/endpoint-ubuntu-ca.crt";
```

Соберите дерево по команде ниже во временной директории на рабочей станции издателя. Сборщик подписывает `dists/noble/InRelease` указанным ключом. Перед публикацией проверьте подпись через `gpgv` с публичным ключом издателя, контрольную сумму `Packages` из подписанного индекса и SHA-256 обоих DEB. Публикуйте дерево в `/srv/endpoint-platform-distribution/ubuntu` с владельцем `root`. После публикации подтвердите выбор кандидата и скачивание обеих версий на пилотном хосте.

```sh
python tools/release/build_ubuntu_apt_repository.py \
  --deb /release/endpoint-agent-ubuntu_3.2.191-1ubuntu1_amd64.deb \
  --deb /release/endpoint-agent-ubuntu_3.2.192-1ubuntu1_amd64.deb \
  --signing-fingerprint "$ENDPOINT_APT_SIGNING_FINGERPRINT" --output /release/ubuntu-apt
```

### Продление подписанного индекса

За продление отвечает издатель Endpoint APT с доступом к действующему ключу
подписи. Издатель планирует перевыпуск на четвёртый день после подписи.
На пилотном узле `openvpn-100-30` таймер `endpoint-apt-expiry.timer` запускает
проверку обоих опубликованных индексов ежедневно в 08:30 UTC. При остатке срока
до трёх дней, недоступности источника, ошибке подписи или дате выпуска в будущем
служба завершится с кодом 1 и запишет ошибку для каждого проблемного индекса.
Проверить состояние таймера и последние ошибки можно на пилотном узле.

```sh
systemctl list-timers endpoint-apt-expiry.timer
journalctl -u endpoint-apt-expiry.service -p err
```

Для уведомления издателя импортируйте
[`endpoint-apt-expiry.zabbix.yaml`](../../deploy/server/endpoint-apt-expiry.zabbix.yaml)
в Zabbix 7.0 и привяжите шаблон `Endpoint APT expiry by Zabbix agent 2`
только к узлу-проверяющему `openvpn`. При импорте создайте недостающие
объекты и обновите существующие объекты шаблона. Оставьте «Удалить
отсутствующие» выключенным.

Активные проверки Agent 2 каждые пять минут читают результат последнего
запуска, время его завершения и состояние таймера. Шаблон предупреждает
об ошибке службы, неактивном таймере, отсутствии завершения за 26 часов
или отсутствии данных о завершении за 20 минут. После перезагрузки
время завершения может быть нулевым до первого запуска службы.
Определите причину ошибки по журналу. Записи содержат канал и ошибку
проверки подписанного индекса.

Подключите события с тегом `component=endpoint-apt` на узле `openvpn`
к действующему дежурному каналу издателя. В «Последних данных» проверьте
наличие всех трёх значений. Для приёмки на тестовом объекте подтвердите
переход в проблему после контролируемой ошибки и получение уведомления
издателем, затем подтвердите восстановление после успешного результата.
До этого рабочая доставка считается непроверенной.
[Шаблоны Zabbix 7.0](https://www.zabbix.com/documentation/7.0/en/manual/xml_export_import/templates) ·
[Выражения триггеров](https://www.zabbix.com/documentation/7.0/en/manual/config/triggers/expression).

Проверку также можно запустить вручную.

```sh
sh tools/release/check_endpoint_apt_expiry.sh
```

На рабочей станции издателя подготовьте отдельную копию текущего опубликованного
дерева, включая исходный `InRelease`. Сохраните SHA-256 этого файла до
продления и выполните команду в контексте действующего хранилища GnuPG.
Согласуйте продление с выпуском пакетов, чтобы операции публикации
не выполнялись одновременно.

```sh
python tools/release/build_ubuntu_apt_repository.py --renew /release/ubuntu-apt \
  --keyring /release/endpoint-ubuntu-apt.gpg \
  --signing-fingerprint D132784F1C7F0D78BDA2842FDE5739F7FD0AFEBE
```

Проверка охватывает `ubuntu/noble` и `debian/bookworm`. Для Debian
добавьте `--codename bookworm` к командам сборки и продления, укажите дерево
Debian и пакеты `endpoint-agent-debian`. Место публикации —
`/srv/endpoint-platform-distribution/debian`.

Для регулярного запуска издателем замените `--renew` на `--renew-if-due`.
Перед каждым запуском берите актуальный снимок опубликованного дерева.
При остатке более трёх дней команда проверит подпись, индексы и пакеты
и завершится успешно с сообщением `Verified repository: renewal not due`.
При остатке не более трёх дней команда выпустит подписанный индекс
на семь дней и выведет новый срок `Valid-Until`. Ошибка проверки прерывает
операцию. Для публикации используйте результат с сообщением
`Renewed Valid-Until`.

Режимы продления проверяют подпись, размеры и SHA-256 индексов и пакетов,
обновляют `Date` и `Valid-Until` и повторно проверяют новую подпись.
Перенесите готовый подписанный `InRelease` на сервер публикации.
Передайте команде публикации SHA-256, сохранённый до продления.

```sh
python tools/release/build_ubuntu_apt_repository.py \
  --publish-renewal /srv/endpoint-platform-distribution/ubuntu \
  --from-inrelease /release/renewed-noble.InRelease \
  --expected-inrelease-sha256 "$EXPECTED_INRELEASE_SHA256" \
  --keyring /release/endpoint-ubuntu-apt.gpg \
  --signing-fingerprint D132784F1C7F0D78BDA2842FDE5739F7FD0AFEBE
```

Команда использует публичный ключ издателя. Она сверяет подписи обоих
индексов, исходный хеш и SHA-256 опубликованных индексов и DEB. В новом
индексе могут измениться только `Date` и `Valid-Until`. После проверок
команда обновляет `Release` и атомарно заменяет `InRelease`. Если
хеш опубликованного `InRelease` изменился, начните с актуального
снимка. Для Debian укажите каталог Debian и `--codename bookworm`.
После публикации выполните проверку выше, `apt-get update` и
`apt-cache policy` для `endpoint-agent-ubuntu` или `endpoint-agent-debian`
с обычными настройками APT на пилотном узле соответствующего канала.

### Переход на другой ключ издателя

Сначала добавьте открытый ключ нового издателя в keyring, указанный
в `Signed-By` у клиентов. Сохраните прежний ключ в том же keyring.
Проверьте обычный APT с этим набором ключей на действующем индексе и
на копии индекса с новой подписью. Клиент с одним прежним ключом
отклонит новый индекс.

Подготовьте продление с обоими открытыми ключами в `--keyring` и
закрытым ключом нового издателя в рабочем хранилище GnuPG.

```bash
python3 tools/release/build_ubuntu_apt_repository.py \
  --prepare-renewal /mirror/endpoint/ubuntu --output /release/endpoint-apt/prepared \
  --codename noble --keyring /release/endpoint-apt-transition.gpg \
  --signing-fingerprint "$old_fingerprint" --successor-fingerprint "$new_fingerprint"
```

Команда проверяет текущий InRelease прежним ключом, подписывает
продление новым и сохраняет результат в подкаталоге
`noble/successor-<новый отпечаток>/<SHA-256 исходного InRelease>/`.
Для канала Debian используйте `--codename bookworm` и его зеркало.

При публикации продления также передайте `--successor-fingerprint`
в дополнение к `--signing-fingerprint`.
Первый параметр закрепляет новый ключ, второй закрепляет подпись
текущего опубликованного индекса. Для этой проверки укажите keyring
с обоими открытыми ключами. Команда сохраняет проверку исходного
SHA-256, дат, подписанных индексов и байтов DEB. После проверок
клиентов и публикации установите новый отпечаток в проверке срока
и у издателя. Проверяйте подписи и Valid-Until обычным APT.

### Регулярная подготовка подписи на Linux-хосте издателя

Разместите проверенную копию сборщика по пути
`/opt/endpoint-apt-publisher/build_ubuntu_apt_repository.py`.
Установите `endpoint-apt-prepare-renewal@.service` и одноимённый
`.timer` из `deploy/server` в `~/.config/systemd/user` учётной
записи издателя. Для каждого канала создайте файл `noble.env` или
`bookworm.env` в `~/.config/endpoint-apt-publisher`. Ниже приведена конфигурация для Ubuntu.

```ini
ENDPOINT_APT_REPOSITORY=/mirror/endpoint/ubuntu
ENDPOINT_APT_OUTPUT=/release/endpoint-apt/prepared
ENDPOINT_APT_KEYRING=/release/endpoint-ubuntu-apt.gpg
ENDPOINT_APT_FINGERPRINT=D132784F1C7F0D78BDA2842FDE5739F7FD0AFEBE
GNUPGHOME=/path/to/approved/publisher-keyring
```

`ENDPOINT_APT_REPOSITORY` должен указывать на актуальное опубликованное
дерево, доступное учётной записи издателя на чтение. Рабочий каталог
`ENDPOINT_APT_OUTPUT` находится отдельно и доступен ей на запись.
Для `bookworm.env` укажите зеркало Debian и публичный ключ издателя
для этого канала. Сверьте запуск от учётной записи издателя до
включения таймеров.

При смене ключа укажите в файле канала
`ENDPOINT_APT_SUCCESSOR_FINGERPRINT` с полным отпечатком нового
издателя. Оставьте в `ENDPOINT_APT_FINGERPRINT` отпечаток
действующего InRelease. Укажите оба открытых ключа в
`ENDPOINT_APT_KEYRING` и хранилище с новым закрытым ключом в
`GNUPGHOME`. Явный `--successor-fingerprint` имеет приоритет
при ручной подготовке. При публикации передайте его явно.

После подтверждённой публикации нового индекса обновите зеркало,
укажите новый отпечаток в `ENDPOINT_APT_FINGERPRINT` и удалите
`ENDPOINT_APT_SUCCESSOR_FINGERPRINT` из файла канала.

```sh
systemctl --user daemon-reload
systemctl --user start endpoint-apt-prepare-renewal@noble.service endpoint-apt-prepare-renewal@bookworm.service
systemctl --user enable --now endpoint-apt-prepare-renewal@noble.timer endpoint-apt-prepare-renewal@bookworm.timer
```

Таймеры работают каждые шесть часов UTC через пользовательский экземпляр
systemd. Для обслуживания без входа пользователя настройте запуск этого
экземпляра после загрузки хоста. При остатке не более трёх дней служба
создаёт `<выход>/<канал>/<исходный-sha256>/InRelease`. При повторном
запуске она сверяет и возвращает готовый действующий индекс для того же
исходного хеша. Если индекс успел истечь до публикации, подготовка
сохраняет его и выпускает новый в подкаталоге `after-<прежний Valid-Until в UTC>`.
Для `--publish-renewal` возьмите точный путь из вывода подготовки
и исходный SHA-256 из родительского каталога этой серии. Команда
публикации по-прежнему отклоняет просроченные кандидаты.
Службы подготовки читают опубликованное
дерево и записывают файлы в отдельный каталог. Оба журнала издателя
проверяются через `journalctl --user -u 'endpoint-apt-prepare-renewal@*.service'`.
