# STAB-15. Изолированная проверка Windows Setup 3.2.252

VM204 создана из неизменённого чистого снимка
VM147 «stab15-win147-229-clean». Windows 10 Enterprise Evaluation, build
19045, LicenseStatus 5, GracePeriodRemaining 0. Перед подключением
подтверждено отсутствие NIC, MSI, служб, файлов и идентичности Endpoint.
Состояние лицензии и часы не менялись.

У VM204 один интерфейс 192.0.2.204 на vmbr144, без маршрута по умолчанию.
Имя лабораторного Gateway разрешалось только в 192.0.2.150 и давало HTTPS
200 с проверкой цепочки. Своя БД, новая одноразовая регистрация по
единственному адресу. После регистрации закрыта выдача нового устройства.

Штатный подписанный лабораторный Setup 3.2.205 имеет SHA-256
1900f0ce296ed19b94a78529478d121f6da7e4e6f94ef5cbe3438a1140404c16.
Его MSI SHA-256
689e1d9dc0dcbd0e1943e98f27cfa88cc36fe99dbf9316e58e54d4292a1fc26f,
Core source f0d1d7cf2f9b59052f35bd0ba0188f8e49cc9649. Setup запущен
в 07:02:27Z, завершился в 07:04:36Z с exit 0 и доставкой seq1.
Core и Browser Policy запущены, Updater в Manual/Stopped в этом профиле.
Сверено наличие четырёх защищённых файлов. Квитанция фиксирует сводный
отпечаток байтов, ID файлов и SDDL без вывода содержимого.

Квитанции в C:/endpoint-platform-wix-build/setup-stability-candidate-252/guest.

| Файл | SHA-256 |
| --- | --- |
| guest204-clean-source-census.json | b9196b52c0256435f49d03c864cb51b27433e30dfa6858e1ad5f8d8ac0d40152 |
| guest204-signed-source-media.json | 816c390c7255d5633b4f1ce515a5ad3f9281a0df1d73df0fe0393eb7e4aef239 |
| guest204-isolated-network-final.json | 34433f74a2d2772df2c628b3c7249c7244abbd30ca69017b7cf2c533d24faec1 |
| guest204-source205-terminal.json | 7e26e9ab54a52922981cc7418f5865c82147c3977dbb15df5a6bb80bb0b4ada8 |
| guest204-source205-latest.json | 1a1db349e8887a53288b158f74ce29eeb2bc80c4d0ca41e2e52e686e04a2d0be |

## Принятый исходный Setup 3.2.245

Штатное назначение 6ff01ab3-abcc-47a6-9caa-2ed46b73e11b, попытка
a6cb40d0-cd1c-466a-aa7a-95b7103b0d38, одна новая карточка
67dbe556-aea9-471c-a218-1691dfa44c3d. Точный Setup SHA-256
06f6f93ea766e083f328606745497a397cbd6cfd39f49fb204670489ce0b0d5f.
Обычные стадии доведены до UPDATED/SERVICE_RUNNING/exit 0 в 07:11:20Z,
native accepted seq5, событие установки seq2 доставлено. Остались
прежние байты, ID и права четырёх защищённых файлов. Provider зафиксировал
applied в 07:14:20Z с 181,519 секунды непрерывного наблюдения WSS.
Промежуточное локальное событие 1001 recover-native-continuation
RECOVERY_REQUIRED в 07:11:01Z сохранилось для разбора. Setup завершился
успешно самостоятельно, без запуска восстановления оператором.

Установленный и вложенный в .245 Observer 1.0.13 прошли проверку
SHA-256 b504a8fb96ead642262494b53327c0c5a01da49a0285d9190c0364da72e399aa
и Authenticode. Локальные SHA-256 квитанций:

- guest204-source245-terminal.json — 255e1152ff65260eed9485770752821c3f170386ba4e382b2a10d881c1c700f6.
- guest204-source245-observer.json — 39825c0d3c3b3e14f70c1e59ca8c88d25f17888e1140b3bb328c5ec7e3b58af7.

## Переход с .245 на .252

Назначение 1ec3647f-dc6a-4b1d-a1c3-707b4f64e50a. Исходник .252
c62f1d07b63e8b7ec803d465573cff0c77ad1190, Setup SHA-256
bb3c4dee922bd2b5d6341ef8e124aaeead44a8fe4578dec1ede97b6c945847e3,
MSI SHA-256 3d2e4764a4b7f953c9181df050390527ed56a9e8cdd6311251404a7e3263bf1b.
Setup Authenticode действителен, с меткой времени.
Локальный результат UPDATED/SERVICE_RUNNING/exit 0 в 07:22:22Z,
операция da21f425-9fd7-450c-99ae-d4a2577c198d, native accepted seq5.
Доставлено событие установки seq3. Файлы private4 неизменны по
сводной проверке байтов, NTFS ID и SDDL. Установленный и вложенный
Observer 1.0.13 одинаковы побайтно с исходным .245 и подписаны.
В интервале 07:02–07:22:26Z нет записи Application 255 Core
или записи 1001 Installer с версией .252.

| Файл | SHA-256 |
| --- | --- |
| guest204-target252-terminal.json | ebd0e36a7d12f8d13fb5cf3a0bc38c4629c1fe8041740f96ed78395e535f1926 |
| guest204-target252-observer.json | 90ecc2ac6f7fc9d8e5e1082780b8f0da71dc388e161d41b7fae45fd6852a7c44 |
| guest204-signed-target-media.json | d9fb3b9a29fbe40fb07993a070ccf07f62ce455ef1330387c24c22092e69ca77 |

Gateway зафиксировал applied в 07:25:23Z для исходной попытки
1b85c1b5-5858-4fb0-a4e3-0fb18ceddc28, native exit 0/accepted
и 181,417 секунды непрерывного WSS. Карточка та же, сессия
d7d37063-8c37-430b-9e7b-db72a206058d, heartbeat 07:25:22Z.
Квитанция online-lab/target252-terminal.json имеет SHA-256
1bf5b296ebb6d703b90232079579fc69a116e9fde21995a6f4c00fb54bc39e87.

## Контекст, восстановление той же версии и SCM

Штатные network_v1, health_v1 и session_v1 завершились с
completed/succeeded на сессии .252 d7d37063-8c37-430b-9e7b-db72a206058d
в 07:20:38–07:20:41Z. Один inventory_v1 по обычному интерфейсу
Console завершился с succeeded на той же сессии в 07:32:56Z.
Сохранены только статусы, время и корреляция, без содержимого результатов.
Последняя проверка Application до 07:44:39Z не выявила Core 255 или
события сбоя Installer 1001 для .252.

Для сценария repair на одноразовой VM204 в 07:39:34Z штатно
остановили Core и удалили только SCM-регистрацию EndpointAgent, оставив
исходный MSI, выбранный Core и private4. Действительный подписанный
Setup той же версии завершился в 07:42:03Z с REPAIRED/SERVICE_RUNNING/10.
MSI, source и сводная проверка private4 прежние. Служба снова Running/Auto.
На той же карточке подтверждены доставка seq4, свежая WSS
88655ab1-cd00-4790-bd23-acf88f403599 и готовность Observer 1.0.13.

Отдельная штатная SCM-остановка запрошена в 07:43:37.618Z, заняла 1070 мс.
Подтверждено завершение старого Core PID 5572. После Start-Service
в 07:43:38.884Z зарегистрированы новые launcher/Core PID 1300/1212 и
Running/Auto, селектор побайтно прежний. Private4 и seq4 сохранились.

| Файл | SHA-256 |
| --- | --- |
| online-lab/target252-scheduled-context.json | 9b8f238c3eb38477740925bc55b37c18f159c58dda731378ba80f422818e46d4 |
| online-lab/context-252-safe-results.json | 801893b024e676a5e2e262cceda46809d71718abb2cfe56a673bc80a33eb4e63 |
| online-lab/target252-repair-provider.json | 89e5292602ab40ffad027a389da09885d1938a3d1115efffffc111e72afb6fa8 |
| guest204-repair252-terminal.json | a49e3e090c6cf60908c1a8ee935e9495328c1c61135be525205fc0ac43979e67 |
| guest204-repair252-post.json | c8d32be45bce4b7c8a0d0ef9e8707e8a818c4d495e1c51f550e0adf98178a0a5 |
| guest204-scm252-terminal.json | 4cda06bc225d14ebbd3eede328dabbeac4f5ae88660c12d6f0bca7dad484d48b |
| guest204-scm252-post.json | 86459c5bcfdf3b119da540ea705740bdd8f3190c3b01c151f0250f49f1c6dbe9 |
| guest204-final-event-observer.json | 54430c85fbfc5a827d9f2ba6f460c8b30d32c1169b6389782f783c6f124e9013 |

После SCM на той же карточке открылась отдельная WSS
e61442c4-b3ef-43d6-b09e-d7613f441e47, heartbeat 07:45:28Z и Observer
ready. Предыдущая сессия закрыта. Времена гостя и Gateway различались
примерно на 13 секунд, поэтому длительность SCM взята из локального
Stopwatch и не вычислялась вычитанием часов разных хостов.

- online-lab/target252-scm-routine-provider.json — 3ac053eaaf7c9e4c21de2cb39051d0804c393d6093cfad91179b11af24da0ab6.
- online-lab/target252-routine-session-span.json — 59697b6c00d2635b38642ecdc666fb8d6b5081fcbda8bd154acde7620b58b73d.

После сохранения квитанций VM204, её диск и оба ISO удалены. SHA-256 файла guest204-cleanup.log — 609abf9d38af6642a568487891df0e5b1217badc5489d3a7c00286bad1e8efff.
Отдельный профиль интерактивного UserSensor или независимого Support не входил в этот сценарий. Контроль чистой установки относится к .205; .252 проверен как штатное обновление и восстановление той же версии.

- setup252-local-build-proof.json — 543f6128899b7a6a82665dd1847d83bb3e4ff281e96ec4ee90d130252aad4a95.
- observer-source-and-reuse-proof.json — a67e319fede49ad59b41383f2e9889b01d9b702051d85289ab643e10faaf478a.
