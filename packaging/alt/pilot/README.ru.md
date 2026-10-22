# ALT 11/KDE: комплект для отдельного staging-пилота

Версия Agent: **3.2.127-alt5**, Core и User Sensor устанавливаются вместе.
Комплект сохраняет уже проверенные бинарные файлы. Он не публикует stable-релиз,
не изменяет контроллер; сборщик и проверка не обращаются к production.
Предусмотренный контроллер Agent: `https://endpoint-staging.sosnadmin.local`.
Шаблон config и фиксированный drop-in включены в архив как
`staging-config.example.yaml` и `staging.conf`. Шаблон требует уникального
installation ID; секретов и CA в нём нет.

В комплекте есть исправленный `cups-browsed 2.1.1-alt1.endpoint2`, исходный
vendor RPM для отката, оба source RPM, две проверенные заплатки и рецепт пересборки.
Исправление CUPS — отдельный пакет ОС; оно не является частью runtime OTA Agent.

Это unsigned-кандидаты для операторской проверки на тестовом стенде. SHA-256
проверяет сохранность принятых файлов, но не заменяет подпись издателя. Перед
обычным распространением RPM передаются во внешнюю среду подписи; закрытые ключи
не должны попадать в комплект, репозиторий или на сборочный worker.

## Проверка до установки

Получите архив, его внешний SHA-256 и SHA-256 `pilot-manifest.json` по доверенному
каналу отдельно от тестового ПК. Сверьте архив **до распаковки**. На выбранном
тестовом ALT ПК скопируйте проверенные файлы в root-owned каталог под `/root`,
распакуйте архив и перейдите в его каталог. Не выполняйте это на production.

```bash
sha256sum --check endpoint-alt-pilot-3.2.127-1.tar.gz.sha256
tar -xzf endpoint-alt-pilot-3.2.127-1.tar.gz
cd endpoint-alt-pilot-3.2.127-1
python3 verify-kit.py check --expected-manifest-sha256 <ПРОВЕРЕННЫЙ_SHA256>
sudo python3 verify-kit.py check --expected-manifest-sha256 <ПРОВЕРЕННЫЙ_SHA256> \
  --test-hostname <ПРОВЕРЕННОЕ_ИМЯ_ТЕСТОВОГО_ПК>
```

Последняя команда только проверяет ALT 11/x86_64, отсутствие прежней регистрации,
идентичность RPM и `rpm --test`. Она ничего не устанавливает и не запускает.
Если есть старая установка или её состояние, остановитесь: не удаляйте их ради
«чистой» проверки. Если не хватает зависимостей, установите их штатным ALT APT из
доверенных репозиториев на этом тестовом ПК и повторите проверку. Для Print Sensor
также нужен работающий локальный CUPS; User Sensor требует KDE Plasma 6 и
Qt 6.11 (принятый RPM собран с Qt 6.11.2/KF6 6.30). Не обходите зависимости RPM.

## Явная установка и CUPS

Запишите исходные версии RPM, активность служб и контрольные суммы конфигурации.
Сохраните root-only копии `/etc/cups/cupsd.conf` и `cups-browsed.conf`, если они есть.
Не меняйте ACL, AD/SSSD, фильтры обнаружения, пользовательские GPO или MaxClients.
При наличии заданий печати дождитесь завершения; не отменяйте чужие задания.

Если `cups-browsed` уже работает, штатно остановите **только его**, проверьте
отсутствие заданий через `lpstat -o` и обязательно восстановите службу при отказе
от дальнейшей установки. Это освобождает соединения, потерянные старой версией.
Затем явно установите три проверенных пакета одной RPM-транзакцией:

```bash
sudo rpm -Uvh --test endpoint-agent-3.2.127-alt5.x86_64.rpm \
  endpoint-agent-user-sensor-3.2.127-alt5.x86_64.rpm \
  cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm
sudo rpm -Uvh endpoint-agent-3.2.127-alt5.x86_64.rpm \
  endpoint-agent-user-sensor-3.2.127-alt5.x86_64.rpm \
  cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm
sudo systemctl start cups.service cups-browsed.service
```

Не используйте `--nodeps`, `--replacefiles`, отключение проверки TLS или
массовый запуск. Не заменяйте неизвестную/более новую версию CUPS этим пакетом.
Если исправленный пакет уже установлен, исключите его из RPM-транзакции.
Agent до защищённой настройки остаётся незарегистрированным; это ожидаемо.

## Регистрация только в staging

Используйте только native RPM процедуру ниже; legacy installer/finalizer для
этого комплекта не применяется. Общая инструкция также устанавливается RPM в
`/usr/share/doc/endpoint-agent/README.md`. CA, installation ID и одноразовый claim
доставляются отдельно, для конкретного hardware fingerprint и нового Device.
Fingerprint снимайте после установки именно от сервисной учётной записи,
поскольку root может видеть другие DMI-компоненты:

```bash
sudo runuser -u endpoint-agent -- /opt/endpoint-agent/versions/3.2.127/endpoint-agent/endpoint-agent --print-hardware-fingerprint
getent hosts endpoint-staging.sosnadmin.local
```

До выпуска claim проверьте разрешение staging-имени из среды службы и HTTPS
с переданной CA. DNS домена может возвращать NXDOMAIN раньше запасного DNS;
исправление записи или согласованная настройка DNS — отдельный входной параметр
стенда. Не меняйте AD/DNS инфраструктуру автоматически, не подменяйте HTTPS origin
адресом IP и не отключайте проверку TLS. Пока имя недоступно, не запускайте enrollment.

Не копируйте credential, identity, config или claim эталонной машины. В архиве
их нет. Укажите канонический staging origin в root-owned config и установите
root-owned drop-in для `endpoint-agent.service` по точному пути
`/etc/systemd/system/endpoint-agent.service.d/staging.conf`:

```ini
[Service]
Environment=ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT=staging
Environment=CANARY_ENVIRONMENT=staging
Environment=CANARY_APPROVED=true
Environment=ENDPOINT_AGENT_ORIGIN=https://endpoint-staging.sosnadmin.local
```

Config и CA: фиксированные пути `/etc/endpoint-agent/config.yaml` и `ca.crt`,
root:root 0600. Claim: `/etc/credstore/endpoint-enrollment-claim`, root:root 0600;
доставляется через stdin, без секрета в аргументах, логах или общем архиве.
В root-сеансе из каталога комплекта, после отдельного получения проверенных
`config.yaml` и `ca.crt`, выполните:

```bash
install -d -o root -g root -m 0755 /etc/endpoint-agent
install -o root -g root -m 0600 /root/pilot-private/config.yaml /etc/endpoint-agent/config.yaml
install -o root -g root -m 0600 /root/pilot-private/ca.crt /etc/endpoint-agent/ca.crt
install -d -o root -g root -m 0700 /etc/credstore
# Отдельный операторский канал пишет уникальный claim в фиксированный файл
# через stdin с владельцем root:root и режимом 0600. Не вставляйте claim в shell.
test -s /etc/credstore/endpoint-enrollment-claim
install -d -o root -g root -m 0755 /etc/systemd/system/endpoint-agent.service.d
install -o root -g root -m 0644 staging.conf /etc/systemd/system/endpoint-agent.service.d/staging.conf
systemctl daemon-reload
systemctl start endpoint-agent-update.path endpoint-agent.service
systemctl is-active endpoint-agent.service
```

Проверьте постоянные credential/identity штатной проверкой установленной службы
и свежую регистрацию отдельного Device в staging. Затем удалите только одноразовый
claim и перезапустите службу; повторный запуск должен пройти без него. Не удаляйте
claim при неудавшейся регистрации и не копируйте его для повторного Device.

## Приёмка и откат

Подтвердите отдельный Device, свежую WSS-связь, Context/diagnostic, Policy APPLIED,
штатный вход KDE и автозапуск User Sensor, Yandex ADMIN/native heartbeat,
Print READY и ровно одно новое тестовое событие. После reboot проверьте сохранность
регистрации и автоматический запуск. Физический USB и печать на реальный принтер
фиксируются отдельно; контейнерный тест не заменяет проверку отдельного ПК.

Существующая общая Browser Policy использует утверждённый публичный feed
`https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml` для подписанного
расширения. Это отдельный источник артефакта, а не staging Gateway. Если граница
испытаний запрещает даже чтение production, не запускайте управляемый браузер для
автоматической загрузки расширения и не объявляйте свежий ADMIN/native heartbeat
проверенным. Смена этого закреплённого feed требует отдельного изменения runtime
и повторной квалификации; данный комплект его не подменяет.

Для возврата исходного `cups-browsed 2.1.1-alt1` остановите discovery, проверьте
`rpm -Uvh --oldpackage --test cups-browsed-2.1.1-alt1.x86_64.rpm`, затем выполните
ту же команду без `--test`, сравните конфигурацию с root-only резервной копией
и верните прежнее состояние службы. Если пакета до пилота не было, не называйте
его установку «восстановлением». Старый пакет имеет известные утечки, поэтому
откат не означает исправность CUPS; при необходимости снимите устройство с пилота.

Штатное удаление обоих Endpoint RPM сохраняет регистрацию. Purge состояния —
отдельное решение, не часть этой инструкции. При частичном отказе RPM не стирайте
identity и конфигурацию: сохраните диагностику и восстановите службу discovery.

## Пересборка CUPS

На отдельном ALT worker установите штатные BuildRequires source RPM. Запустите
`bash rebuild-cups.sh` как непривилегированный пользователь из нового рабочего
каталога. Source RPM уже содержит vendor spec и обе заплатки; флаги vendor сохранены.
Сравнивайте исходники и поведение; новый build time может изменить бинарный SHA-256.
