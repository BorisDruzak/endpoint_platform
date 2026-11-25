# Допуск Server 2012 R2 к сетевой проверке 3.2.245

Из чистого снимка VM144 `stab15-clean-wmf51` создан отдельный полный
клон VM190 без сетевого адаптера. Проверка в работающей гостевой ОС
подтвердила Windows Server 2012 R2, сборку 9600, WMF 5.1.14409.1005,
отсутствие служб Endpoint и данных Endpoint в ProgramData.

Лицензия клона `ServerDatacenterEval` в канале `TIMEBASED_EVAL`
показала `LicenseStatus=5` и `GracePeriodRemaining=0`. Клон не прошёл
условие допуска по действующей лицензии. Setup не запускался. Сетевой
переход 3.2.205 → 3.2.245, WSS и Observer на этой ОС остаются без
отдельной квитанции.

Ранее VM170 на Server 2012 R2 подтвердила Authenticode, preflight
и нативную установку точных байтов 3.2.245 до этапа регистрации.
Сетевой переход, WSS и Observer на VM174 относятся к Windows 10.
Обе проверки описаны в
[квалификации Windows Setup 3.2.245](2026-11-18-windows-setup-245-qualification.md).

VM190, её диск, неподключённый ISO, отдельные API, worker, БД
и временные каталоги удалены. Исходная VM144 сохранена выключенной,
исходные сервисы VM142 активны. Квитанции
`windows2012r2-license-admission.json`, `client-cleanup.txt`,
`provider-cleanup.txt` и `pve-cleanup.txt` сохранены в
`C:/endpoint-platform-wix-build/stab15-win2012r2-205-245-20261118`.
