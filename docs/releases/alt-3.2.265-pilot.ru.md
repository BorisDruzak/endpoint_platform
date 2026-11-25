# Обновление Endpoint на ALT Workstation K 11.4 x86_64

Комплект 3.2.265-alt6 предназначен для локального обновления уже зарегистрированного устройства с парой RPM 3.2.183-alt6. До запуска сверьте устройство и исходный выпуск с назначенным пилотом. Для подтверждения установки нужен Gateway, в котором зарегистрированы исходная карточка и точная пара .265. Сохраните подписанный комплект .183 для операторского возврата.

### Проверка комплекта

В каталоге с восемью файлами дистрибутива откройте оболочку администратора. Используйте каталог, доступный для записи только root. Сверьте отпечаток издателя по принятому в организации независимому источнику. Для этого выпуска отпечаток равен `BC24B8EE43DBB05A748E11A4343B5DA748370631`.

```sh
set -eu
kit=endpoint-alt-pilot-3.2.265-1
printf '%s  %s\n' 12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c endpoint-rpm-release.asc | sha256sum -c -
trust=$(mktemp -d)
chmod 700 "$trust"
gpg --homedir "$trust" --batch --no-options --import endpoint-rpm-release.asc
fingerprint=$(gpg --homedir "$trust" --batch --no-options --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr"{print $10; exit}')
test "$fingerprint" = BC24B8EE43DBB05A748E11A4343B5DA748370631
gpg --homedir "$trust" --batch --no-options --verify "$kit.tar.gz.sig" "$kit.tar.gz"
gpg --homedir "$trust" --batch --no-options --verify "$kit.manifest.sig" "$kit.manifest.json"
sha256sum -c "$kit.tar.gz.sha256"
sha256sum -c "$kit.manifest.json.sha256"
test ! -e "$kit"
tar -xzf "$kit.tar.gz"
cmp "$kit/native-kit-manifest.json" "$kit.manifest.json"
python3 - "$kit" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

kit_dir = Path(sys.argv[1])
manifest = json.loads((kit_dir / "native-kit-manifest.json").read_bytes())
for name, expected in manifest["files"].items():
    data = (kit_dir / name).read_bytes()
    if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
        raise SystemExit(f"Файл не совпал с подписанным манифестом: {name}")
PY
```

### Обновление одного устройства

В той же оболочке проверьте исходные пакеты и запустите Setup из проверенного комплекта.

```sh
cd "$kit"
test "$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}' endpoint-agent)" = 3.2.183-alt6.x86_64
test "$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}' endpoint-agent-user-sensor)" = 3.2.183-alt6.x86_64
rpm -V endpoint-agent endpoint-agent-user-sensor
./endpoint-agent-setup upgrade \
  --core-rpm ./endpoint-agent-3.2.265-alt6.x86_64.rpm \
  --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.265-alt6.x86_64.rpm \
  --public-key ./endpoint-rpm-release.asc
```

При коде 0 проверьте версии обоих RPM и результат `rpm -V endpoint-agent endpoint-agent-user-sensor`. В Console на прежней карточке должны появиться подтверждённое событие установки и новая сессия Core .265. После обычной перезагрузки проверьте связь контрольной командой.

При коде 21 сохраните журнал исходной операции. При ожидающей доставке восстановите доступ к Gateway и выполните штатную команду `./endpoint-agent-setup reconcile` из каталога проверенного комплекта .265. При неизвестном результате нативной установки сохраните исходную операцию для разбирательства.

### Операторский возврат

После завершённого обновления отдельно проверьте подписанный комплект .183 по инструкции к этому выпуску. Из каталога распакованного комплекта .183 вызовите его Setup с двумя RPM и ключом издателя из этого же комплекта.

```sh
./endpoint-agent-setup upgrade \
  --core-rpm ./endpoint-agent-3.2.183-alt6.x86_64.rpm \
  --user-sensor-rpm ./endpoint-agent-user-sensor-3.2.183-alt6.x86_64.rpm \
  --public-key ./endpoint-rpm-release.asc
```

При коде 0 выполните обычную перезагрузку и проверьте оба RPM, подтверждение события возврата и новую сессию Core .183 на прежней карточке.
