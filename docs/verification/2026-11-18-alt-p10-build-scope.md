# Граница нативной сборки Endpoint для ALT 10 p10

[Руководство](../runbooks/ALT_AGENT_INSTALL.md) квалифицирует
подписанную нативную пару для ALT 11/KDE. В исходнике конечной 3.2.248
`7bd7086a4650c9c9abd2218b2b9bbd0633235302` штатный
[build-rpm.sh](../../packaging/alt/build-rpm.sh) имеет общий режим Core
и режим `--with-user-sensor` для Plasma 6. CMake в режиме UserSensor
требует Qt6 от 6.4 и KF6IdleTime от 6.0. Собранная пара 3.2.248
использовала CPython 3.12.13, Qt 6.11.2 и KF6IdleTime 6.30.0.

В [официальном каталоге p10 x86_64](https://download.basealt.ru/pub/distributions/ALTLinux/p10/branch/x86_64/RPMS.classic/)
проверены 20 048 имён RPM. В нём есть Qt 6.4.2, Qt 5.15.16 и
KF5IdleTime 5.116.0. KF6IdleTime и CPython 3.12 в этом каталоге
отсутствуют. Штатный Python — 3.9.20, glibc — 2.32. Состав
[KWorkstation 10.4](https://download.basealt.ru/pub/distributions/ALTLinux/p10/images/kworkstation/alt-kworkstation-10.4-install-x86_64.iso.txt)
также указывает на KF5.

На чистом p10 подписи точной пары 3.2.248 прошли проверку.
`rpm -U --test` завершился с кодом 2. Core требует символы
GLIBC 2.33–2.38 и другие ABI библиотек сборки. UserSensor требует
KF6IdleTime и Qt 6.11. Штатного профиля и готового toolchain для
p10 нет. Для полной пары понадобится собственная сборочная среда
с CPython 3.12 на ABI p10 и отдельная адаптация UserSensor к
Plasma 5/KF5 либо квалифицированный перенос KF6. Core-only не покрывает
приёмку рабочей станции с UserSensor. Сборку p10 в этой проверке
не запускали. Подписанная пара 3.2.248 сохранена.

Квитанции `p10-transaction.json` и `p10-build-catalog.json`
сохранены в `C:/endpoint-platform-wix-build/stab15-alt-p10-248-20261118`.

## Совместимость подписанной 3.2.254

В отдельной временной базе RPM проверены закреплённая подпись и хеши финальных [Core и UserSensor 3.2.254](2026-11-18-stab15-alt-native-254-core-recovery.md). После нормализации полные списки RPM Requires обоих пакетов совпали со списками 3.2.248. Core использует символы GLIBC вплоть до 2.38 при glibc 2.32 в проверенном p10. UserSensor требует `Qt_6.11` и `libKF6IdleTime.so.6`. В зафиксированном каталоге p10 доступны Qt 6.4.2 и KF5IdleTime 5.116.0.

Подписанная пара 3.2.254 несовместима с этим штатным профилем p10. Вывод основан на фактических требованиях обоих RPM и сохранённом инвентаре p10. Нативный `rpm -U --test` на p10 с кодом 2 относится к 3.2.248. После удаления одноразового стенда образ p10 для нового прогона 3.2.254 отсутствовал. Квитанции `C:/endpoint-platform-wix-build/stab15-alt-p10-254-20261118/receipts.sha256`, SHA-256 `7624e1b4537a7a71e0f8e0d699d38e117746dc0ceef10cdfe160c529d7a4f951`.
