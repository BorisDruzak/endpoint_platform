# Endpoint Agent 3.2.277 для ALT Workstation K 11.4

Подписанный комплект `endpoint-alt-pilot-3.2.277-1` содержит Core и UserSensor
`3.2.277-alt6.x86_64`, нативный Setup и публичный ключ издателя. Исходная
ревизия агента — `ca68540ebf91a41cdb510e0727eaeef7e3b1e02b`.

На ALT Workstation K 11.4 x86_64 проверены чистая установка с первой
регистрацией и переход `3.2.183-alt6 → 3.2.277-alt6 → 3.2.183-alt6`
с сохранением регистрации. Используйте комплект в пределах согласованного
пилота или кампании регистрации для этого профиля.

## Проверка комплекта

Сверьте отпечаток `BC24B8EE43DBB05A748E11A4343B5DA748370631` по доверенному
каналу. Выполните блок без прав root в каталоге, доступном для записи только
оператору. Он проверяет архив, внешний манифест, подписи и байты обоих RPM
перед запуском Setup.

```sh
(
  set -eu
  umask 077
  kit=endpoint-alt-pilot-3.2.277-1
  archive_sha=179e49b9b93540a51fe8384128f75ef9962bd5a6b27604da4cd2d64416d553cb
  manifest_sha=710b4491b63808458e31e93e54edb23ed033f67ee9eecd017483ea8c13494002
  publisher_sha=12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c
  printf '%s  %s\n' \
    "$publisher_sha" endpoint-rpm-release.asc \
    "$archive_sha" "$kit.tar.gz" \
    a552b1f4b7cf821aa84f265378205f010a6ead5c28ef5c0df47e37d1c4f72902 "$kit.tar.gz.sig" \
    "$manifest_sha" "$kit.manifest.json" \
    554bdfd10e69a205678ab5bd3693ee25798ca0665880890b67149b5a0901382f "$kit.manifest.json.sig" |
    sha256sum -c -
  trust=$(mktemp -d)
  trap 'rm -f -- "$trust/publisher.gpg"; rmdir -- "$trust"' EXIT
  gpg --homedir "$trust" --batch --no-options --dearmor --output "$trust/publisher.gpg" endpoint-rpm-release.asc
  gpgv --homedir "$trust" --keyring "$trust/publisher.gpg" "$kit.tar.gz.sig" "$kit.tar.gz"
  gpgv --homedir "$trust" --keyring "$trust/publisher.gpg" "$kit.manifest.json.sig" "$kit.manifest.json"
  printf '%s  %s\n' "$archive_sha" "$kit.tar.gz" | cmp - "$kit.tar.gz.sha256"
  printf '%s  %s\n' "$manifest_sha" "$kit.manifest.json" | cmp - "$kit.manifest.json.sha256"
  test ! -e "$kit"
  test ! -L "$kit"
  tar --no-same-owner -xzf "$kit.tar.gz"
  cmp "$kit.manifest.json" "$kit/native-kit-manifest.json"
  cd "$kit"
  printf '%s  %s\n' \
    3503c605ce194cb8ec1048960a7972ef3784ec6e3bc065ea84defb1932c46a3c endpoint-agent-3.2.277-alt6.x86_64.rpm \
    40495e695eb74bb45b8e21ee21a7d57538b6859aaed497a5a46f651a6778943f endpoint-agent-user-sensor-3.2.277-alt6.x86_64.rpm \
    9eba50c40a7712ebcd8e01debf6765bc55daf50dbb679a8b491250659ee115c3 endpoint-agent-setup \
    "$publisher_sha" endpoint-rpm-release.asc |
    sha256sum -c -
  printf '%s\n' 'Комплект 3.2.277 проверен'
)
```

## Чистая установка

Получите у оператора конфигурацию с уникальным `installation_id` и CA
своего Gateway. Настройте штатный HTTPS origin и проверьте имя сервера,
доверие к CA и готовность кампании принять точную пару RPM. Запустите из
проверенного распакованного каталога в административной оболочке.

```sh
./endpoint-agent-setup install \
  --core-rpm ./endpoint-agent-3.2.277-alt6.x86_64.rpm \
  --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.277-alt6.x86_64.rpm \
  --public-key ./endpoint-rpm-release.asc
```

При ожидании допуска оператор подтверждает эту заявку в штатной Console.
После допуска завершите исходную установку командой `./endpoint-agent-setup reconcile`.

## Обновление зарегистрированного устройства

Сверьте исходную карточку, действующий Gateway и возможность отката.
Для этого маршрута оба установленных RPM должны быть `3.2.183-alt6.x86_64`
без epoch. Сохраните текущие конфигурацию, CA и защищённое состояние устройства.

```sh
(
  set -eu
  format='%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n'
  test "$(LC_ALL=C rpm -q --qf "$format" endpoint-agent)" = '(none):3.2.183-alt6.x86_64'
  test "$(LC_ALL=C rpm -q --qf "$format" endpoint-agent-user-sensor)" = '(none):3.2.183-alt6.x86_64'
  rpm -V endpoint-agent endpoint-agent-user-sensor
  ./endpoint-agent-setup upgrade \
    --core-rpm ./endpoint-agent-3.2.277-alt6.x86_64.rpm \
    --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.277-alt6.x86_64.rpm \
    --public-key ./endpoint-rpm-release.asc
)
```

## Приёмка и восстановление

Проверьте `rpm -V` для обоих пакетов, работающие службы, принятое нативное
событие установки и свежий WSS прежней карточки при обновлении. После входа
пользователя проверьте отчёты UserSensor и Support и применённую политику.
Проверка CUPS `2.4.20-alt2` проводится через Gateway на выделенной очереди
с полномочиями только для нужных операций.

Код Setup `21` требует сверки журнала исходной попытки. При подтверждённом
нативном выходе `0` восстановите связь и дождитесь подтверждения события.
`reconcile` завершает исходную операцию. Если исход RPM неизвестен, сохраните
журнал и передайте операцию на восстановление. Установка поверх такого
состояния удерживается до подтверждения исхода.

Для отката исправной `.277` к `.183` используйте проверенный исходный
подписанный комплект `.183` и его Setup с командой `upgrade`. Проверьте
новое событие на прежней карточке, свежий WSS и сохранность журнала CUPS.
