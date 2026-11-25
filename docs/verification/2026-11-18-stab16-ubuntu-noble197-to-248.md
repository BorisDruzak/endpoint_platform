# STAB-16. Ubuntu Noble 3.2.197 → 3.2.248

18 ноября 2026 года подписанный production InRelease Noble проверен
с закреплённым ключом 840AC80D602970C76C282E6DD02C861F8B636743.
Срок действия, хеш индекса Packages и хеш опубликованного исходного
DEB совпали. Версия 3.2.248-1ubuntu1 отсутствовала в этом индексе и
точный путь к DEB в production pool вернул HTTP 404 по проверенному TLS.

| Поле | Значение |
| --- | --- |
| Исходный production DEB | endpoint-agent-ubuntu_3.2.197-1ubuntu1_amd64.deb |
| Исходный SHA-256 | 1d30e147ef8e108a2b379ffffcfb765d66ddb24926974592b23d86e491a6d573 |
| Целевой DEB | endpoint-agent-ubuntu_3.2.248-1ubuntu1_amd64.deb |
| Целевой SHA-256 | 28ae0ee313b9d853d4dc8f62db44bdc161392ffdfea9035e75788cdf513741e5 |
| Целевой source | 7bd7086a4650c9c9abd2218b2b9bbd0633235302, включает e049a050 |
| Тестовый профиль | Ubuntu Noble amd64, kernel 6.8.0-147-generic, glibc 2.39 |

Штатные PyInstaller spec и build_ubuntu_agent_deb.py собрали DEB на
Noble из чистого checkout с сохранёнными сборочными wheels. Метаданные DEB
и установленный Core подтвердили source и версию 3.2.248, Python 3.12.3
и PyInstaller 6.19.0. Пакет amd64 требует libc6 >= 2.39. Оба DEB помещены
в отдельный подписанный file: APT. Production origin пакета сохранён
в поставляемом conffile, а в клоне использован отдельный loopback Gateway
по имени endpoint-staging.sosnadmin.local с собственным SAN. Проверены
строгий TLS, штатный LoadCredential CA и отсутствие внешних адаптеров.

VM178 один раз зарегистрирована штатным bootstrap кандидата с ACK 204.
Со штатной службой, временно остановленной в лаборатории, установлен
точный исходный production .197. После запуска службы Gateway получил
WSS и heartbeat 3.2.197. На работающей службе apt-get install обновил
DEB до 3.2.248. Сверены dpkg, новый PID, штатный unit без drop-in,
ожидаемый source и свежий heartbeat 3.2.248 на той же карточке.

После перезагрузки появились новый boot ID и третий WSS session ID,
а Gateway снова получил heartbeat 3.2.248 на карточке
538c56a3-6024-4b5d-a109-b69a83328253. Сохранились одна карточка и
один credential. Все четыре файла сохранности совпали по содержимому,
inode, uid, gid и режиму доступа. Содержимое приватных файлов не
экспортировалось.

Первый запуск стенда потребовал отключить ожидание сети без NIC,
доустановить QGA и добавить две зависимости PostgreSQL. После первой
перезагрузки QGA потребовал настройки автозапуска. После исправления
инфраструктуры проверка прошла при штатной перезагрузке, без изменений
unit агента. VM178, оба диска, четыре ISO и временные ключи удалены.
Production APT использовался для чтения.

| Квитанция в C:/endpoint-platform-wix-build/stab16-noble248-20261118 | SHA-256 |
| --- | --- |
| production-input.txt | f29a9cd7844dc13acd35b7f44ad20d51957ece10dc9a4acf2616d3ba6c1b872e |
| production-target-unoccupied.txt | d18519131d433f93f07e812a79247ccae9a36feb760b895857deeebb33ba7a33 |
| core-identity.json | 362c80a10b7d53007a054fc48261ad2ffab6e947c697987402a694b11366c12f |
| deb-control.txt | bfc3ea11a8abd513a5308bd1a8fbe70b3a67a3c021006505840aebf9f1f0d992 |
| gpgv.log | 6b9fdca29d46776ea4053ca74a6628186f0c62900f43edc0dd76fce1d56953db |
| ca-profile.json | 45664bb5b8ac1f1778bada7a64d7401ead6a9929ba10da45257d7b67fecdbafe |
| transition-final.json | 5a360d3c6be6f222fa5a97420ff0ccc8102f7e305d35a03a7dd3fe4cd43db0ee |
| reboot-final.json | 5bd96978053ea45fbc73e9521d1d11bcabf10c28203c2b510476138413a62c72 |
| cleanup.log | 4265a28afa07150638b50c049b6535dc3d138a6d02d95727ac04fcf31b7681fd |

## Граница управления обновлениями DEB

Извлечённый из проверенного DEB systemd unit совпал с
packaging/ubuntu/endpoint-agent-ubuntu.service:18. Он включает
gateway_wss, отключает migration HTTP fallback и задаёт
package-managed-updates. В pc_agent/runtime/application.py:115–118
настройки требуют именно WSS без fallback, а :574–575 и :590–591
исключают периодический HTTPS poll. Запись pending_alt_update.json
находится в отдельном HTTP-пути pc_agent/endpoint_gateway.py:242–259
и pc_agent/gateway_update_runtime.py:51–105. Штатный DEB unit этот
путь не запускает. Сам серверный фильтр linux_amd64 не различает
пакетного владельца, поэтому вывод относится к штатному unit и его
настройкам.

На точном 7bd7086a тест test_linux_deb_leaves_core_update_to_the_package_manager
прошёл (1 passed, 30 deselected). SHA-256 packaged-service.txt
f7f1f900a32911e1d77616b00cec230e7aac0fca60d1c3fb3614a6e5cc445b0b.
