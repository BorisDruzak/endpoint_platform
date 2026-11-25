# STAB-15. Windows Setup 3.2.250 на Windows 10

## Переход из 3.2.237 с автоматическим откатом без сети

На временном клоне VM199 от остановленной VM143 проверен точный
подписанный Setup 3.2.250, source 060e0abf0dba48b236dfa12a136e3065ccaa767f.
SHA-256 EXE dda28b96ba5211277d00f8c656a5d195968575745c48d4a013da5200c4a6981e,
MSI d9e4a501927401fce92dc9c476b32ff7aba22c47e7abcc9c8ece65aeef7b2b2e.
Windows 10 Enterprise Evaluation build 19045, LicenseStatus 1,
физических NIC нет. Предпроверка дала exit 0 / READY_FOR_SETUP_UPGRADE.
Исходные Core и Foundation 3.2.237, source c9383198278e77cae79cb70bf23eca73812e5301,
MSI-кэш d366dd0f6ecfba677d78275579616f7b41fec6a917ad1a76a0c5775fe3cc284a.

Один штатный запуск --quiet создал операцию
3c8d9312-e1c2-4fdb-a94d-e31312377f19. В trial Core и MSI 3.2.250
совпали с точными source и SHA-256. Записано installed, sequence 10,
native exit 0, pending без ACK. Из-за отсутствия WSS Setup вернул
67 / ROLLED_BACK / CANDIDATE_ROLLED_BACK. Журнал terminal rolled-back,
sequence 6. Восстановлены Core, точный MSI 3.2.237 и службы. Событие
восстановления sequence 11 осталось pending. После штатной перезагрузки
сверены исходные MSI, source и состояние служб. До, в trial, после
отката и перезагрузки совпали байты, file ID и SDDL четырёх приватных
файлов. VM199 и её диск, отдельный ISO и каталог переноса удалены.

Отдельная VM200 из VM143/pre-stab206-native подтвердила работающий QGA,
лицензированную Evaluation, установленную 3.2.192 и четыре файла
исторической идентичности. Чистого исходного профиля этот снимок не дал.
VM200 и её диск удалены, исходный снимок сохранён.

Квитанции в C:/endpoint-platform-wix-build/setup-stability-candidate-250.

| Квитанция | SHA-256 |
| --- | --- |
| guest199-preflight.json | ec34086907b989ed518be0a3dae121fe8e02d34c7948d7df6526d486b24ac40e |
| guest199-trial.json | aa1fd12f3b76efc83712b5984495a7257b0ddb8e06429aaa3aeb5377d3e53156 |
| guest199-rollback-state.json | 695c5ed29fbe2d67e442da5c0e62c358ab3b051c9bb467a9fd368195d0735d52 |
| guest199-reboot-state.json | bc73071aa812d964b2c393e770eb675811f67b2973671ceace41e255d95240eb |
| guest200-clean-source-census.json | de1c4e6197784006c739a9b30a3bda03d05cd3dd281b2649da8377db00f3b6ac |

## Изолированный последовательный переход .205 → .245 → .250

VM203 строго изолирована на мосту без uplink и default route. Чистый
снимок VM147 до Endpoint, Windows 10 Enterprise Evaluation build 19045,
LicenseStatus 5, GracePeriodRemaining 0. Windows и QGA работали. Лицензия
и часы не изменялись. Для Authenticode в клон импортирован канонический
открытый CA, после чего оба EXE подтвердили подпись, метку времени и
ожидаемый SHA-256. Gateway использовал свой лабораторный TLS CA.

Подписанный лабораторный .205 wrapper SHA-256
1900f0ce296ed19b94a78529478d121f6da7e4e6f94ef5cbe3438a1140404c16
содержал точный .205 MSI 689e1d9dc0dcbd0e1943e98f27cfa88cc36fe99dbf9316e58e54d4292a1fc26f.
Установка и одноразовая регистрация завершились 06:29:21 UTC кодом 0.
Принят ACK sequence 1, WSS и Observer 1.0.11 ready. Временный допуск
отозван. На той же карточке cf5d9c79-62c6-4cc9-a63a-6a012ff24eeb точный
переход на .245 завершён applied 06:39:42 UTC, native 0, 181,397 с soak
и ACK sequence 2. Новый Observer 1.0.13 ready. Private4 совпали по
байтам, NTFS file ID и SDDL.

Для .250 назначение d91bed2c-7b9e-4326-a389-9f7d2cb0164e, попытка
3683009b-4ceb-47e1-929b-38de27c24850. Нативная операция
ffdfee32-3c33-4267-b768-5a7bc9482b61 достигла accepted sequence 5.
Фактически установлены точный MSI 3.2.250 и Core source 060e0abf...
Private4 совпали. На той же карточке появился WSS .250, через него
прошли запланированные network, session и health collections. Однако
в 06:46:53 UTC внешний Setup вернул 21 / MSI_EVIDENCE_FAILED. Локальное
событие установки sequence 3 осталось pending. Сервер сохранил исходную
попытку recovery_required / native_exit_requires_recovery.

Application Installer Event 1001, record 482, фаза
restore-staged-companions, зафиксировал RECOVERY_REQUIRED на
native_setup_observer.py:203. Установленный Observer 1.0.13 из .245
имеет SHA-256 b504a8fb96ead642262494b53327c0c5a01da49a0285d9190c0364da72e399aa.
В .250 тот же Observer 1.0.13 с неизменённым исходным текстом имеет другой
Authenticode-конверт, SHA-256
cae24f8e9097239e7f9d0b53e103056252977c3218638a6fc1fb919be33b1d38.
Проверка неизменяемого каталога версии сравнивает полные подписанные
байты и отказала. Следующее событие launcher 483 зафиксировало
OWNER_AUTH_FAILED. Событий Core 255 с диагностикой runtime в этом окне
не обнаружено. Службы Core и BrowserPolicy работали. Отдельный сервис
Support отсутствовал на исходной лабораторной установке.

Документированное восстановление запускает точный защищённый Setup
для исходной операции. Для accepted оно повторяет provision_packaged_observer
(native_setup_continuation.py:386) и встретит то же расхождение
неизменяемого Observer. Ветка серверного recovered target в 44d96b5cce41
также исключает 1.0.13. Состояние закреплено за исходным владельцем.
Ремонт, остановка службы и повтор установки не выполнялись.

| Квитанция | SHA-256 |
| --- | --- |
| guest203-clean-source-census.json | eaba86cfc1eb2ef27171e9160b17e184e543f5781926dd936feae2eb99fc58ac |
| guest203-signed-media-final.json | 11ff6d6d2173f0d1709aa8f6c0379750b0efa58d57cda19588e19d2492e38637 |
| guest203-accepted245.json | 852a1755cac6f9a1e86377207ede818a303ee2dbcc76dc6c8b4487dba3a63f26 |
| guest203-held250.json | 179efb289c4fe255c92e5adfd8fe11ad8b91d167b0a0bebe4b8cbcfa9b62347b |
| guest203-held250-observer-proof.json | 537df5c7118a2a757064acf087aaae1c2c731d5a71083b137a84ea22f47ff82e |
| online-lab/target245-terminal.json | d77512e7bbf6056d234d7b0b2549e3b11a8b9095df8768511eb1d50bdd332b59 |
| online-lab/target250-terminal.json | 4b881569bb2c4510ff8ee0447394b87e0846cc8d21eae3a350f8da0b4fda6004 |

После проверки SHA-256 трёх квитанций held закрытый стенд VM203 разобран. Виртуальная машина, её диск и исходный ISO удалены. SHA-256 файла guest203-cleanup.log — 42a77bb137e6f0a8ed8b8e713132e868ba80ad200414a5d9d840fddfbf5bf019.
