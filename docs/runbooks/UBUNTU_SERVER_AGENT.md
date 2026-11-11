# Отдельный клиент Endpoint для Ubuntu Server

Целевая платформа пилота — Ubuntu Server 24.04 LTS, amd64, systemd. Первые роли — `endpoint_platform` и `openvpn`. Перечень служб, томов и локальных проверок приведён в [серверном профиле](SERVER_AGENT_HEALTH.md).

Клиент использует общий код серверных проверок и существующий обмен `health_v1` с Endpoint Platform. Пакет `endpoint-agent-ubuntu` устанавливает фоновый Core в `/usr/lib/endpoint-agent-ubuntu`, служба называется `endpoint-agent-ubuntu.service`. Состояние регистрации и данные агента хранятся в `/var/lib/endpoint-agent-ubuntu` и сохраняются при обновлении и удалении пакета.

Версией Core управляет DEB. Служба использует `--package-managed-updates`, поэтому Core не запрашивает задания на обновление из общего канала Linux.

Сборка выполняется на Ubuntu 24.04 amd64 с Python 3.12. Укажите ревизию исходников, из которых собран Core.

```sh
python -m pip install -r requirements/build-linux.txt
python -m PyInstaller --noconfirm pc_agent/pyinstaller_endpoint_core_linux.spec
python tools/build_ubuntu_agent_deb.py --core dist/endpoint-agent --output dist/ubuntu \
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

Production-источник — `https://endpoint.sosnadmin.local/downloads/ubuntu`. Публичный ключ `endpoint-ubuntu-apt.gpg` имеет отпечаток `D132784F1C7F0D78BDA2842FDE5739F7FD0AFEBE` и SHA-256 `a1718e6b042501c3a3fde1662a6c5302b6d1ced454e6230d59617d5e18c25aa8`. Ключ находится в отдельном хранилище GnuPG на рабочей станции издателя. На HTTPS-сервер переносятся подписанный индекс, проверенные пакеты и публичный ключ.

На Ubuntu 24.04 привяжите доверие к этому источнику через `Signed-By: /etc/apt/keyrings/endpoint-ubuntu-apt.gpg` и укажите сертификат CA только для хоста Endpoint:

```text
Acquire::https::endpoint.sosnadmin.local::CaInfo "/etc/apt/keyrings/endpoint-ubuntu-ca.crt";
```

Соберите дерево по команде ниже во временной директории. Для production подпишите файл `dists/noble/Release` ключом издателя на его рабочей станции и замените `dists/noble/InRelease`. Перед публикацией проверьте подпись через `gpgv` с указанным публичным ключом, контрольную сумму `Packages` из подписанного индекса и SHA-256 обоих DEB. Публикуйте дерево в `/srv/endpoint-platform-distribution/ubuntu` с владельцем `root`. После публикации подтвердите выбор кандидата и скачивание обеих версий на пилотном хосте.

```sh
python tools/release/build_ubuntu_apt_repository.py \
  --deb /release/endpoint-agent-ubuntu_3.2.191-1ubuntu1_amd64.deb \
  --deb /release/endpoint-agent-ubuntu_3.2.192-1ubuntu1_amd64.deb \
  --signing-fingerprint "$ENDPOINT_APT_SIGNING_FINGERPRINT" --output /release/ubuntu-apt
```
