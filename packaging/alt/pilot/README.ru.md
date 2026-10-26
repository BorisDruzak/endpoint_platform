# ALT 11/KDE: подписанный комплект 3.2.155-1

Core и User Sensor: **3.2.155-alt5**. Исправленный CUPS:
`cups-browsed 2.1.1-alt1.endpoint2`. В комплекте также vendor RPM для отката,
оба source RPM, обе заплатки и рецепт пересборки. Core и User Sensor собраны из общей Windows/Linux версии 3.2.155;
CUPS сохранён из ранее квалифицированного комплекта. Собственные RPM имеют
RSA/SHA256 подписи header и payload. Vendor RPM
сохраняют исходные подписи и закреплённые SHA-256. CUPS устанавливается отдельной
транзакцией ОС, а не через runtime OTA агента.

Издатель: **Endpoint Platform RPM Release Signing 2026**.
Полный отпечаток публичного ключа:
`BC24 B8EE 43DB B05A 748E 11A4 343B 5DA7 4837 0631`.
Ключ: `endpoint-rpm-release.asc`. Закрытый ключ, пароль, CA, credential, identity
и enrollment claim в дистрибутив не входят.

Основной контроллер: `https://endpoint.sosnadmin.local`. Используйте
`production-config.example.yaml` и `production.conf`. Для отдельного стенда
оставлены явно названные staging-шаблоны; они не являются production-настройкой.

## Проверка до распаковки

Сверьте полный отпечаток по доверенному каналу отдельно от скачанных файлов.
Не доверяйте новому ключу только потому, что он лежит рядом с архивом.
Скопируйте дистрибутив в root-owned каталог под `/root` выбранного ALT ПК.
Команды ОС выполняйте в root-сеансе через `su -`; членство в wheel не означает
sudo-доступа. Не меняйте sudoers ради установки.

```bash
install -d -m 0700 /root/endpoint-rpm-check
gpg --homedir /root/endpoint-rpm-check --import endpoint-rpm-release.asc
gpg --homedir /root/endpoint-rpm-check --fingerprint BC24B8EE43DBB05A748E11A4343B5DA748370631
# Сначала сравните полный отпечаток с доверенным значением.
gpg --homedir /root/endpoint-rpm-check --verify endpoint-alt-pilot-3.2.155-1.tar.gz.sig endpoint-alt-pilot-3.2.155-1.tar.gz
sha256sum --check endpoint-alt-pilot-3.2.155-1.tar.gz.sha256
tar -xzf endpoint-alt-pilot-3.2.155-1.tar.gz
cd endpoint-alt-pilot-3.2.155-1
gpg --homedir /root/endpoint-rpm-check --verify ../endpoint-alt-pilot-3.2.155-1.manifest.sig pilot-manifest.json
python3 verify-kit.py check --expected-manifest-sha256 <ПРОВЕРЕННЫЙ_SHA256_MANIFEST>
python3 verify-kit.py check --expected-manifest-sha256 <ПРОВЕРЕННЫЙ_SHA256_MANIFEST> --test-hostname <ПРОВЕРЕННОЕ_ИМЯ_ПК>
```

Helper проверяет SHA-256, создаёт временную изолированную RPM DB с одним
закреплённым ключом и проверяет подписи header и payload собственных RPM.
Успешных digest недостаточно. Постоянное доверие системной RPM DB не меняется.
Нужен штатный RPM ALT. Никакие пакеты или службы этой проверкой не устанавливаются.

Для clean-install требуются ALT 11/x86_64, KDE Plasma 6, Qt 6.11 и KF6.
Принятый RPM собран с Qt 6.11.2/KF6 6.30. Зависимости ставятся штатным ALT APT из
доверенных репозиториев; не обходите RPM dependencies. Старую регистрацию,
состояние или оставшиеся systemd overrides нельзя стирать ради «чистого» результата.
Обновление существующего устройства выполняется отдельно с сохранением состояния.

## Установка и CUPS

Запишите версии пакетов, состояние служб и checksum конфигурации. Сохраните
root-only копии `/etc/cups/cupsd.conf` и `/etc/cups/cups-browsed.conf`. Не меняйте
ACL, AD/SSSD, discovery-фильтры, корпоративные GPO или MaxClients. При наличии
заданий печати дождитесь завершения; чужие задания не отменяйте.

После независимой проверки отпечатка импортируйте публичный ключ в системную
RPM DB. Для нового ПК из каталога комплекта:

```bash
rpm --import endpoint-rpm-release.asc
rpm --checksig --verbose endpoint-agent-3.2.155-alt5.x86_64.rpm endpoint-agent-user-sensor-3.2.155-alt5.x86_64.rpm cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm
rpm -Uvh --test endpoint-agent-3.2.155-alt5.x86_64.rpm endpoint-agent-user-sensor-3.2.155-alt5.x86_64.rpm cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm
```

Остановите только работавший cups-browsed и проверьте отсутствие заданий через
`lpstat -o`. При отказе от установки восстановите его прежнее состояние.
Выполните ту же RPM-транзакцию без `--test`, затем:

```bash
systemctl start cups.service cups-browsed.service
```

Не используйте `--nodeps` или `--replacefiles`. Не понижайте неизвестную/более
новую версию CUPS. Если исправленный пакет уже стоит, исключите его из обычной
транзакции. Перевод установленной той же версии unsigned в signed требует отдельно
проверенной операции `--replacepkgs`, сохраняющей состояние; это не обход clean gate.

## Настройка и регистрация

Используйте native RPM процедуру; legacy installer/finalizer не применяется.
Общая инструкция RPM: `/usr/share/doc/endpoint-agent/README.md`.
До выдачи claim проверьте штатное DNS-разрешение контроллера и HTTPS с переданной
CA. Не заменяйте HTTPS origin адресом IP и не отключайте TLS.
Не копируйте credential/identity/config/claim другого ПК. Fingerprint снимайте
от сервисной учётной записи: root может видеть другие DMI-компоненты.

```bash
runuser -u endpoint-agent -- /opt/endpoint-agent/versions/3.2.155/endpoint-agent/endpoint-agent --print-hardware-fingerprint
getent hosts endpoint.sosnadmin.local
```

Выдайте уникальные config и одноразовый claim через доверенный операторский канал.
Production config создаётся по production-шаблону с уникальным installation ID.
Для staging выбирайте staging-шаблоны и staging-контроллер явно; не перенаправляйте
существующую регистрацию на production копированием конфигурации.

```bash
install -d -o root -g root -m 0755 /etc/endpoint-agent
install -o root -g root -m 0600 /root/pilot-private/config.yaml /etc/endpoint-agent/config.yaml
install -o root -g root -m 0600 /root/pilot-private/ca.crt /etc/endpoint-agent/ca.crt
install -d -o root -g root -m 0700 /etc/credstore
# Операторский канал пишет claim через stdin в фиксированный root:root 0600 файл.
# Не вставляйте claim в shell, argv, логи или общий архив.
test -s /etc/credstore/endpoint-enrollment-claim
install -d -o root -g root -m 0755 /etc/systemd/system/endpoint-agent.service.d
install -o root -g root -m 0644 production.conf /etc/systemd/system/endpoint-agent.service.d/production.conf
systemctl daemon-reload
systemctl start endpoint-agent-update.path endpoint-agent.service
systemctl is-active endpoint-agent.service
```

После проверки постоянных credential/identity и нового Device удалите только
одноразовый claim по штатной процедуре и перезапустите службу. Запуск должен
проходить без claim. При ошибке не стирайте частичное состояние: сохраните диагностику.
После reboot проверьте тот же Device, WSS, Context/diagnostic, Policy APPLIED
и автозапуск User Sensor после реального входа в KDE.

Общая Browser Policy загружает подписанное расширение с утверждённого feed
`https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml`.
На отдельном стенде .191 проверены Yandex ADMIN, native READY и свежие heartbeat
в staging. Пользовательские профили в комплект не входят. Физические USB и печать
на реальном принтере остаются отложенными пользователем испытаниями.

## Откат и пересборка CUPS

Для возврата vendor cups-browsed остановите discovery и проверьте
`rpm -Uvh --oldpackage --test cups-browsed-2.1.1-alt1.x86_64.rpm`. Затем выполните
команду без `--test`, сравните конфигурацию с резервной копией и восстановите
прежнее состояние службы. Старый пакет имеет известные утечки; откат не означает
устранение проблемы. Если его раньше не было, не называйте установку восстановлением.

Удаление Endpoint RPM сохраняет регистрацию. Purge не входит в эту процедуру.
На отдельном ALT worker установите BuildRequires source RPM и выполните
`bash rebuild-cups.sh` непривилегированным пользователем в новом каталоге.
Source RPM содержит vendor spec и обе заплатки; параметры vendor сохранены.
Результат пересборки требует отдельной квалификации и подписи. Закрытый ключ
на worker не передаётся. Подпись меняет RPM-байты: новый подписанный набор требует
новой ревизии комплекта и новых закреплённых digest, не перезаписи старого архива.
