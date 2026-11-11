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
2. Положите сертификат CA Endpoint в `/etc/endpoint-agent-ubuntu/ca.crt`. В `/etc/endpoint-agent-ubuntu/agent.conf` задайте `ENDPOINT_AGENT_SERVER_ROLE=endpoint_platform` или `openvpn`. Оставьте штатный HTTPS origin контроллера.
3. Подготовьте для этого хоста выданные контроллером файлы `device-credential` и `enrollment-identity.json`. Поместите их в каталог состояния с владельцем и группой `endpoint-agent-ubuntu` и правами `0600`. Эта версия принимает готовую пару идентичности. Автоматическая регистрация по одноразовому claim требует отдельной поддержки Ubuntu.
4. Выполните `systemctl enable --now endpoint-agent-ubuntu.service`. В карточке устройства проверьте свежесть профилей контекста и результаты серверной роли. Для отката установите предыдущий DEB, затем убедитесь, что контроллер видит прежнюю идентичность и нужную версию.

Для канала обновлений соберите подписанный репозиторий из новой и предыдущей версий. Публикуйте полученное дерево целиком под отдельным HTTPS-путём. Настройте источник APT для `noble main` с `Signed-By`, указывающим только на проверенный публичный ключ издателя. Перевыпускайте подписанный индекс до истечения семидневного `Valid-Until`. Перед установкой сверьте `apt-cache policy endpoint-agent-ubuntu` и версию кандидата. Для явного отката укажите предыдущую версию и `--allow-downgrades`.

```sh
python tools/release/build_ubuntu_apt_repository.py \
  --deb /release/endpoint-agent-ubuntu_3.2.191-1ubuntu1_amd64.deb \
  --deb /release/endpoint-agent-ubuntu_3.2.192-1ubuntu1_amd64.deb \
  --signing-fingerprint "$ENDPOINT_APT_SIGNING_FINGERPRINT" --output /release/ubuntu-apt
```
