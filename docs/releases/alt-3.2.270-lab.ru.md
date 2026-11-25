# ALT Workstation K 11.4. Стендовый комплект 3.2.270

Подписанные RPM предназначены для одного зарегистрированного стендового ПК x86_64. Прямое обновление с 3.2.183-alt6 и возврат на неё проверены на 11.4 с обновлёнными пакетами p11. Для сетевого прогона в лабораторном Gateway должны быть зарегистрированы точные пары обоих выпусков. Используйте прежний адрес Gateway, его CA и действующие настройки стенда. Заранее подготовьте проверенный комплект .183 для возврата.

## Проверка файлов

Получите инструкцию и отпечаток издателя из доверенного источника. Отпечаток ключа выпуска — `BC24B8EE43DBB05A748E11A4343B5DA748370631`. Откройте каталог комплекта, доступный для записи только оператору. Блок проверяет ключ, подписи и точные байты этого выпуска, затем распаковывает его в новый подкаталог. Дождитесь строки `Комплект 3.2.270 проверен`.

```sh
(
  set -eu
  kit=endpoint-alt-pilot-3.2.270-1
  printf '%s  %s\n' 12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c endpoint-rpm-release.asc | sha256sum -c -
  trust=$(mktemp -d)
  trap 'rm -f -- "$trust/publisher.gpg"; rmdir -- "$trust"' EXIT
  gpg --homedir "$trust" --batch --no-options --dearmor --output "$trust/publisher.gpg" endpoint-rpm-release.asc
  gpgv --homedir "$trust" --keyring "$trust/publisher.gpg" "$kit.tar.gz.sig" "$kit.tar.gz"
  gpgv --homedir "$trust" --keyring "$trust/publisher.gpg" "$kit.manifest.sig" "$kit.manifest.json"
  printf '%s  %s\n' f94fabcf7255cf422caa8ffcf1b845d322d85306878ab427b2a001a42451e55e "$kit.tar.gz" | sha256sum -c -
  printf '%s  %s\n' 77fc6fe485e735d6458e174e25ccf87c6ee83145bb3214791b92fda17c02386f "$kit.manifest.json" | sha256sum -c -
  sha256sum -c "$kit.tar.gz.sha256"
  sha256sum -c "$kit.manifest.json.sha256"
  test ! -e "$kit"
  test ! -L "$kit"
  tar -xzf "$kit.tar.gz"
  cmp "$kit/native-kit-manifest.json" "$kit.manifest.json"
  printf '%s\n' 'Комплект 3.2.270 проверен'
)
```

## Переход с .183 на .270

На согласованном ПК проверьте, что предыдущая установка завершена, Core и Support работают, а Gateway видит исходную карточку. После успешной проверки файлов выполните блок из каталога комплекта в административной оболочке с настройками стенда.

```sh
(
  set -eu
  cd endpoint-alt-pilot-3.2.270-1
  for package in endpoint-agent endpoint-agent-user-sensor; do
    test "$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}' "$package")" = 3.2.183-alt6.x86_64
  done
  rpm -V endpoint-agent endpoint-agent-user-sensor
  rc=0
  ./endpoint-agent-setup upgrade \
    --core-rpm ./endpoint-agent-3.2.270-alt6.x86_64.rpm \
    --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.270-alt6.x86_64.rpm \
    --public-key ./endpoint-rpm-release.asc || rc=$?
  printf 'Setup вернул %d\n' "$rc"
  exit "$rc"
)
```

При коде 0 проверьте обе версии RPM, результат `rpm -V endpoint-agent endpoint-agent-user-sensor` и подтверждение установки .270 на исходной карточке. После обычной перезагрузки проверьте новую сессию Core и свежий отчёт Support. Код 21 требует проверки журнала исходной операции. Если RPM завершился с кодом 0 и событие ждёт отправки, восстановите связь и выполните `./endpoint-agent-setup reconcile` из распакованного комплекта .270.

## Возврат на .183

После подтверждённого обновления проверьте подпись комплекта .183 и перейдите в его распакованный каталог. Выполните штатное понижение версии его собственным Setup.

```sh
./endpoint-agent-setup upgrade \
  --core-rpm ./endpoint-agent-3.2.183-alt6.x86_64.rpm \
  --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.183-alt6.x86_64.rpm \
  --public-key ./endpoint-rpm-release.asc
```

Проверьте код 0, обе версии RPM и подтверждённое событие .183 на той же карточке. После обычной перезагрузки проверьте Core и Support.
