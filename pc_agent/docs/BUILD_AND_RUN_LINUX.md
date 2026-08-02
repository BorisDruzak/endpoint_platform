# Сборка и запуск агента на Linux (launcher + обновления)

Агент собирается через PyInstaller: **launcher** (один исполняемый файл) и **agent** (onedir). Launcher запускает текущую версию из `install_root/versions/<ver>/`, при выходе с кодом 42 или наличии `pending_update.json` применяет обновление (см. [SELF_UPDATE.md](SELF_UPDATE.md)).

## Сборка (из корня репозитория)

Требуется Python 3.12 и PyInstaller в venv агента:

> **Historic Helpdesk/GUI only.** The following launcher and agent build is
> not a supported path for a new Endpoint core RPM; use the headless-core
> package instructions at the end of this document instead.

```bash
cd /var/chat_bot/pc_client
# HISTORIC HELPDESK/GUI ONLY: do not use the following specs for new RPM/core packages.
./pc_agent/venv/bin/pip install pyinstaller   # если ещё не установлен
./pc_agent/venv/bin/pyinstaller pc_agent/pyinstaller_launcher_linux.spec --noconfirm
./pc_agent/venv/bin/pyinstaller pc_agent/pyinstaller_agent_linux.spec --noconfirm
```

Результат:
- `dist/launcher` — бинарник launcher
- `dist/pc_agent/` — onedir (исполняемый `pc_agent` и каталог `_internal`)

## Layout установки (install_root + data_root)

По умолчанию:
- **install_root:** `~/.local/opt/pcclient-agent` (или `PC_AGENT_INSTALL_ROOT`)
- **data_root:** `~/.local/share/pcclient-agent` (или `PC_AGENT_DATA_DIR`)

Структура install_root:
- `launcher` — исполняемый файл
- `current.json` — `{"version":"3.0.0","previous":null}`
- `versions/3.0.0/` — содержимое `dist/pc_agent/` (исполняемый `pc_agent` и `_internal/`)

Пример разложения (для теста в `.run`):

```bash
INSTALL=".run/agent_install"
DATA=".run/agent_data"
mkdir -p "$INSTALL/versions/3.0.0"
cp dist/launcher "$INSTALL/launcher" && chmod +x "$INSTALL/launcher"
cp -r dist/pc_agent/* "$INSTALL/versions/3.0.0/"
echo '{"version":"3.0.0","previous":null}' > "$INSTALL/current.json"
```

## Подготовка data_root и токен

1. Создать identity с UUID устройства:
   ```bash
   mkdir -p "$DATA"
   echo '{"uuid":"<UUID>"}' > "$DATA/identity.json"
   ```
   UUID можно сгенерировать: `python3 -c "import uuid; print(uuid.uuid4())"`

2. Сервер должен быть запущен. Запросить provisioning через connection request либо получить manual token от authenticated admin:
   ```bash
   curl -s -X POST http://127.0.0.1:8666/api/connection_request \
     -H "Content-Type: application/json" \
     -d '{"device_id":"<UUID>","hostname":"linux-agent"}'
   ```
   Manual policy returns pending `request_id` and `poll_secret`; keep them secret while polling status. Accept-all policy can return `"token": "..."` immediately.
   В ответе: `"token": "..."`.

3. Один раз запустить агент с переменной `AUTH_TOKEN`, чтобы токен сохранился в БД агента (`storage.db`):
   ```bash
   PC_AGENT_DATA_DIR="$DATA" PC_AGENT_INSTALL_ROOT="$INSTALL" \
   PC_AGENT_WS_URL=ws://127.0.0.1:8666/ws PC_AGENT_API_URL=http://127.0.0.1:8666/api \
   AUTH_TOKEN="<полученный_токен>" \
   "$INSTALL/versions/3.0.0/pc_agent"
   ```
   После сообщения «Токен из ENV сохранен в БД агента» и handshake можно остановить (Ctrl+C). Дальше launcher будет брать токен из БД.

## Запуск через launcher

```bash
PC_AGENT_DATA_DIR="$DATA" PC_AGENT_INSTALL_ROOT="$INSTALL" \
PC_AGENT_WS_URL=ws://127.0.0.1:8666/ws PC_AGENT_API_URL=http://127.0.0.1:8666/api \
"$INSTALL/launcher" --data-dir "$DATA" --install-root "$INSTALL" --no-gui
```

Launcher читает `current.json`, запускает `versions/<version>/pc_agent` с нужными env; при выходе 42 или наличии `pending_update.json` выполняет установку обновления и перезапуск. Для headless Linux-стендов используйте `--no-gui`: launcher передаст агенту `--no-gui`, и агент не будет поднимать GUI даже если в `settings.yaml` включён `ui.autostart_gui`.

## Проверка «агент онлайн»

- В логах агента: `✅ Получен handshake_ack от сервера` — подключение успешно.
- Список устройств и статус online: `GET /api/devices` (требует UI-авторизации, например токен после `POST /api/ui_login`).

## Краткая последовательность (E2E)

1. Запустить сервер: `python3 scripts/run_server.py`
2. Собрать launcher и агент (команды выше), разложить в `install_root`, создать `data_root` и `identity.json`
3. Request provisioning through `POST /api/connection_request` or ask an authenticated admin to issue a manual token; unauthenticated `POST /api/login` is not supported.
4. Один раз запустить бинарник агента с `AUTH_TOKEN=...` для сохранения токена в БД
5. Запускать агент через launcher; проверять handshake в логах

Остановка сервера: `python3 scripts/stop_server.py`.

## Запуск «прямо из dist» (без отдельного install_root)

Если нужно запустить лаунчер из каталога `dist/` после сборки:

1. Подготовить layout в `dist/`:
   ```bash
   cd /var/chat_bot/pc_client
   mkdir -p dist/versions/3.0.0
   cp -r dist/pc_agent/* dist/versions/3.0.0/
   echo '{"version":"3.0.0","previous":null}' > dist/current.json
   mkdir -p dist/data
   ```

2. Запуск (из корня репозитория или из dist):
   ```bash
   PC_AGENT_DATA_DIR="$(pwd)/dist/data" PC_AGENT_INSTALL_ROOT="$(pwd)/dist" \
   PC_AGENT_WS_URL=ws://127.0.0.1:8666/ws PC_AGENT_API_URL=http://127.0.0.1:8666/api \
   ./dist/launcher --data-dir dist/data --install-root dist --no-gui
   ```

Либо запустить бинарник агента напрямую с GUI (без лаунчера):
   ```bash
   PC_AGENT_DATA_DIR=dist/data PC_AGENT_WS_URL=ws://127.0.0.1:8666/ws PC_AGENT_API_URL=http://127.0.0.1:8666/api \
   ./dist/pc_agent/pc_agent --gui
   ```

## GUI не отображается

- **DISPLAY:** при SSH или без графической сессии проверьте `echo $DISPLAY`; при необходимости экспортируйте `DISPLAY=:0` или запускайте с локального X/Wayland.
- **Плагины Qt (xcb):** при запуске из собранного бинарника (`dist/pc_agent/pc_agent`) Qt может не найти платформенный плагин. Задайте путь к плагинам PySide6 перед запуском:
  ```bash
  export QT_PLUGIN_PATH="/var/chat_bot/pc_client/pc_agent/venv/lib64/python3/site-packages/PySide6/Qt/plugins"
  ./dist/pc_agent/pc_agent --gui
  ```
  (путь замените на свой к venv или системной установке PySide6/Qt/plugins).
- **Лаунчер и --gui:** Linux-лаунчер по умолчанию передаёт агенту `--gui`. Если окно не появляется, проверьте логи агента (в data_root или консоль при прямом запуске `pc_agent --gui`).
Security update 2026-05-23: unauthenticated `POST /api/login` is no longer an agent provisioning path. For new installs use the connection-request flow, or have an authenticated admin issue a manual token through the server UI/API. Manual connection-request polling requires the server-returned `request_id` and `poll_secret`.

## Historic Helpdesk/GUI offline release bundle for ALT Linux

This section is retained only to reproduce historic Helpdesk/GUI artifacts.
It is not a route for a new Endpoint core RPM. Build these historic release
bundles only on Linux with the same Python 3.12 environment used for
PyInstaller. The builder requires an explicit legacy acknowledgement before it
runs `pyinstaller_launcher_linux.spec` and `pyinstaller_agent_linux.spec`:

```bash
cd /var/chat_bot/pc_client
./pc_agent/venv/bin/python -m pc_agent.build_linux_release_bundle \
  --build --legacy-helpdesk-gui --version 3.2.1 --output /tmp/endpoint-agent-releases
```

The result is the transient directory
`/tmp/endpoint-agent-releases/endpoint-agent-3.2.1/`. It contains only
`launcher`, `pc_agent/` (including `pc_agent/pc_agent` and its onedir
contents), and `manifest.json`. Do not commit this output or store a CA,
claim credential, token, server URL, or agent configuration in it.

PyInstaller may create file symlinks inside its temporary `dist/pc_agent/`
tree (for example Qt runtime libraries). The release builder accepts only a
payload link that resolves to a regular file inside that same `pc_agent/` tree,
then copies its bytes into an ordinary file at the same bundle path. The final
bundle therefore contains no symlinks; a top-level, dangling, directory, cyclic
or out-of-tree link aborts the build.

To assemble already-built output without invoking PyInstaller, pass its
directory explicitly. `--revision` records the reviewed source revision; when
omitted, the builder records `git rev-parse HEAD` from the repository.

```bash
./pc_agent/venv/bin/python -m pc_agent.build_linux_release_bundle \
  --source /path/to/dist --revision "$(git rev-parse HEAD)" \
  --version 3.2.1 --output /tmp/endpoint-agent-releases
```

`manifest.json` is schema version 1. It records the bounded release version,
source revision, and sorted SHA-256 plus POSIX mode for every regular payload
file. Inspect it before handing the bundle to the installer:

```bash
python3 -m json.tool \
  /tmp/endpoint-agent-releases/endpoint-agent-3.2.1/manifest.json
```

## Headless Endpoint Agent core packages

New RPM packages must install `requirements/build-linux.txt` and build only
`pc_agent/pyinstaller_endpoint_core_linux.spec`:

```bash
python -m pip install -r requirements/build-linux.txt
python -m PyInstaller --noconfirm pc_agent/pyinstaller_endpoint_core_linux.spec
python tools/build_linux_agent.py --channel canary
```

This artifact starts `pc_agent/runtime/main.py` and contains no Qt, Helpdesk
UI, or Remote Assist assets. The inherited `pyinstaller_agent_linux.spec` and
`pc_agent/requirements.txt` files are legacy compatibility inputs only; they
must not be used for a new RPM package.

The PyInstaller output is `dist/endpoint-agent/`, with the core executable at
`dist/endpoint-agent/endpoint-agent`. The release builder consumes that
reviewed onedir tree and writes a deterministic
`endpoint-agent-linux_amd64-VERSION.tar.gz` plus a local immutable sidecar
manifest under `dist/release/linux_amd64/CHANNEL/VERSION/`. The sidecar records
the build identifier, version, source revision, platform, channel, archive
type/name, SHA-256, and size. It intentionally has no download URL: artifact
publication and conversion to the server's `UpdateBuildManifestV1` are a later
release operation. This build step does not create an RPM or install files on
a host. The builder canonicalizes PyInstaller's generated
`_internal/base_library.zip` member order and ZIP metadata before hashing the
final tar, so two clean builds of the same checkout produce identical release
bytes; changed embedded module bytes still produce a different immutable
artifact.
