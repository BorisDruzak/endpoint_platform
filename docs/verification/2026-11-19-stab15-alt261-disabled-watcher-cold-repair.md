# STAB-15. Холодное восстановление ALT 3.2.261 с отключённым watcher

Штатный ремонт сохраняет настройку включения служб. В RPM scriptlet ветвь ремонта не включает watcher, а Setup сверяет исходные свойства всех затронутых unit. Предыдущее испытание точной .261 начиналось с включённым watcher.

На одноразовой ALT Workstation K 11.4 x86_64 VM221 установили подписанную пару 3.2.261-alt6 из `788fe236bba1685526c270cc0febc11c9866697f`. SHA-256 комплекта `0299cdd07bc6e27b2b3503db8885c587737101c8aa6c6dce91de2614343642f1`, Core RPM `018ab4d1c3abc4619c4d59cfa74da1e9655971a1876a247ca7393cde8a05f1cd`, UserSensor RPM `f02933902e73d103af6d35d575b8502af1fa2937ffd643e33244ed6a5c3b3510`. До ремонта только `endpoint-agent-update.path` отключили штатным `systemctl disable --now`.

На отключённой сети начали обычный ремонт. После сохранения обоих post-scriptlet receipts и native exit 0 наблюдатель зафиксировал read-only дочерний RPM и остановил исходный координатор. На новой загрузке без сети штатный `reconcile` вернул 0 и завершил исходную операцию `6037c45e-5377-4e22-9f19-973aa05e2c9e`. Трасса содержит только `rpm -q` и `rpm -V`, повторных RPM-транзакций нет. Watcher был `disabled/inactive/dead` до ремонта, до reconcile на новой загрузке и после восстановления WSS.

Core вернулся в исходное активное состояние. Уже работающий Support сохранил PID 961 и обе монотонные метки старта на новой загрузке. Туннель не открывался. Селектор, ACK 1, идентичность, CA, конфигурация и ACL совпали. После возврата связи прежняя карточка получила новую WSS `0c1c9cf1-ce58-487b-8152-24093f516230`. Событий установки не добавилось. Таймер start-limit в этом прогоне не проверяли.

Удалены VM221, снимок, диск, выделенные Gateway и БД, дополнительный IP и временные каталоги. Квитанции в `C:/endpoint-platform-wix-build/stab15-alt-native-261/disabled-cold-repair`. SHA-256 `receipts.sha256` — `c09c9f1e84ea958ad3a65770a0d2c2ab24f46a4dce463c2d1a84d8c613c06a9d`.

```powershell
python -B C:/endpoint-platform-wix-build/stab15-alt-native-261/disabled-cold-repair/verify-disabled.py
```
