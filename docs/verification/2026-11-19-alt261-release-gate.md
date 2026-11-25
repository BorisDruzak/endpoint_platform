# ALT 3.2.261. Проверка исходной ревизии

Подписанная лабораторная пара 3.2.261-alt6 собрана из `788fe236bba1685526c270cc0febc11c9866697f`. SHA-256 Core RPM `018ab4d1c3abc4619c4d59cfa74da1e9655971a1876a247ca7393cde8a05f1cd`, UserSensor RPM `f02933902e73d103af6d35d575b8502af1fa2937ffd643e33244ed6a5c3b3510`, комплекта `0299cdd07bc6e27b2b3503db8885c587737101c8aa6c6dce91de2614343642f1`. Этим же исходником и хешами запись `alt_native_candidate_261` связывает артефакты и нативные результаты в [локальном реестре выпуска](../releases/current-agent-release.json). На момент проверки исходников кандидат имел статус `signed_lab_candidate`. Позднее нативный прогон выявил [потерю целевой версии после подтверждения обновления](2026-11-19-stab15-alt261-pilot-post-ack2-power.md).

Ранее на этой ревизии прошло 172 целевых Linux-теста и отдельно один тест содержимого точного подписанного RPM. Дополнительно выполнили целиком Linux job `provider-release-gate` из `.github/workflows/endpoint-operations-provider.yml`, blob `91bab509f8ae012688b73a4122e7471d45455359`. На изолированной Ubuntu использовали чистый checkout точного SHA из Git bundle, Python 3.12.3, одноразовый PostgreSQL 16 только на loopback и проверенный офлайн-набор зависимостей из предыдущего прогона. Выполнили `pytest tests pc_agent/tests --ignore=pc_agent/tests/windows` с параметрами workflow, проверку сгенерированных контрактов, компиляцию и `git diff --check`.

Итог — **5410 passed, 2 subtests passed, 727 skipped**, 0 ошибок и 0 падений, exit 0. В JUnit счётчик suite равен 6139 с учётом двух подтестов. В XML 6137 элементов testcase. Это локальное воспроизведение Linux job. Hosted GitHub Actions для этой ревизии не запускали. Нативные сценарии не повторяли. Подписи комплекта, вложения и обе квитанции прерванного ремонта повторно проверены автономным `verify-delivery.py`.

Временный runner, БД, слушающий сокет и каталоги удалены. Состояние, PID и время запуска исходных стендовых служб совпали до и после. Квитанции в `C:/endpoint-platform-wix-build/stab15-alt-native-261/full-linux-gate`.

| Квитанция | SHA-256 |
| --- | --- |
| `artifacts/endpoint-operations-provider.xml` | `9d30d38c5de6e052e96d2524259611532573744bfd43a7ce7785c635ee250b9f` |
| `artifacts/dependencies.txt` | `d12398cdbfc0150a9fe649642eb9df8c0676da599d2c95abf2aa82a339f1aa49` |
| `artifacts/source.json` | `88e25b2d15d4284b23af40190a5a8f1a64fbe8f0b1de0ac0ea8e9c178639d6e9` |
| `receipts.sha256` | `d7eba005ccc2390eb6ad1835d97fb1f5f23b6acba097b40e59f1ebf44d95a38f` |
