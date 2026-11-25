# ALT Workstation K 11.4. Стендовый комплект 3.2.274

Локальный подписанный кандидат для ALT Workstation K 11.4 x86_64 с обновлёнными пакетами p11. Комплект можно проверить без сети и прав root. На изолированном стенде подтверждены прямые переходы с пар RPM 3.2.183-alt6, 3.2.265-alt6 и 3.2.270-alt6 на 3.2.274-alt6 с сохранением регистрации. Штатный возврат с 3.2.274-alt6 на 3.2.265-alt6 также проверен.

## Проверка комплекта

Получите эту инструкцию и отпечаток издателя по доверенному каналу. Отпечаток ключа выпуска — `BC24B8EE43DBB05A748E11A4343B5DA748370631`. Выполните блок в каталоге скачанных файлов, доступном для записи только оператору. При ошибке остановитесь. Успешная проверка завершится строкой `Комплект 3.2.274 проверен`.

```sh
(
  set -eu
  kit=endpoint-alt-pilot-3.2.274-1
  umask 077
  printf '%s  %s\n' \
    12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c endpoint-rpm-release.asc \
    6a674fd49cdde461d8b9a486760dfae75d6c869f3a8f53f1fadabfb538db2a87 "$kit.tar.gz" \
    df22f098b8e88dd113b65a3cd39f35ced636f201ed786903ed1d8d8fe98e66fa "$kit.tar.gz.sig" \
    43000138764b317166b93b1dacee6e50e9a6630d9d13093cd78ecfc1964b9364 "$kit.manifest.json" \
    0d72cfd1fc7a7974da0a06a239a096ff938b0a6fb853e216921d8ecce85eae23 "$kit.manifest.json.sig" |
    sha256sum -c -
  trust=$(mktemp -d)
  trap 'rm -f -- "$trust/publisher.gpg"; rmdir -- "$trust"' EXIT
  gpg --homedir "$trust" --batch --no-options --dearmor --output "$trust/publisher.gpg" endpoint-rpm-release.asc
  gpgv --homedir "$trust" --keyring "$trust/publisher.gpg" "$kit.tar.gz.sig" "$kit.tar.gz"
  gpgv --homedir "$trust" --keyring "$trust/publisher.gpg" "$kit.manifest.json.sig" "$kit.manifest.json"
  printf '%s  %s\n' 6a674fd49cdde461d8b9a486760dfae75d6c869f3a8f53f1fadabfb538db2a87 "$kit.tar.gz" |
    cmp - "$kit.tar.gz.sha256"
  printf '%s  %s\n' 43000138764b317166b93b1dacee6e50e9a6630d9d13093cd78ecfc1964b9364 "$kit.manifest.json" |
    cmp - "$kit.manifest.json.sha256"
  test ! -e "$kit"
  test ! -L "$kit"
  tar --no-same-owner -xzf "$kit.tar.gz"
  cmp "$kit.manifest.json" "$kit/native-kit-manifest.json"
  cd "$kit"
  printf '%s  %s\n' \
    f22203823dbc28c038eaf9b1e0b248a808277a8b5df1cdacd13cc122a1d87d13 endpoint-agent-3.2.274-alt6.x86_64.rpm \
    14c6688e03d0795e774c4bdd2a7852c848c19c66276a111fb8cecc7e5f30d7d1 endpoint-agent-user-sensor-3.2.274-alt6.x86_64.rpm \
    d646affc77a9e527808519a2fb3adbcf5e354c349ca43306c6316a8dcbb8dec0 endpoint-agent-setup \
    12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c endpoint-rpm-release.asc |
    sha256sum -c -
  printf '%s\n' 'Комплект 3.2.274 проверен'
)
```

## Обновление на изолированном стенде

Этот шаг выполняется отдельно от проверки файлов. Используйте согласованный стендовый ПК, его прежние Gateway и CA и заранее подготовленную точку восстановления. Core и User Sensor должны иметь одинаковые epoch, версию, релиз и архитектуру. Допустимы только пары `3.2.183-alt6.x86_64`, `3.2.265-alt6.x86_64` и `3.2.270-alt6.x86_64` без заданного epoch. Для подтверждения установки в лабораторном Gateway должна быть зарегистрирована точная подписанная пара .274. Выполните блок из каталога скачанных файлов в административной оболочке.

```sh
(
  set -eu
  cd endpoint-alt-pilot-3.2.274-1
  evra_format='%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n'
  core=$(LC_ALL=C rpm -q --qf "$evra_format" endpoint-agent)
  sensor=$(LC_ALL=C rpm -q --qf "$evra_format" endpoint-agent-user-sensor)
  if [ "$core" != "$sensor" ]; then
    printf 'Разные версии RPM: Core %s, User Sensor %s\n' "$core" "$sensor" >&2
    exit 1
  fi
  case "$core" in
    '(none):3.2.183-alt6.x86_64'|'(none):3.2.265-alt6.x86_64'|'(none):3.2.270-alt6.x86_64') ;;
    *)
      printf 'Исходная пара RPM не поддерживается: %s\n' "$core" >&2
      exit 1
      ;;
  esac
  rpm -V endpoint-agent endpoint-agent-user-sensor
  ./endpoint-agent-setup upgrade \
    --core-rpm ./endpoint-agent-3.2.274-alt6.x86_64.rpm \
    --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.274-alt6.x86_64.rpm \
    --public-key ./endpoint-rpm-release.asc
)
```

Проверьте версии обоих RPM, `rpm -V endpoint-agent endpoint-agent-user-sensor` и подтверждение установки .274 на исходной карточке. Код Setup 21 требует проверки журнала операции. Если транзакция RPM завершилась с кодом 0 и её событие ожидает отправки, восстановите связь. Дождитесь подтверждения на исходной карточке. При необходимости выполните `./endpoint-agent-setup reconcile` из распакованного комплекта. После штатной перезагрузки проверьте свежую сессию Core и отчёт Support.
