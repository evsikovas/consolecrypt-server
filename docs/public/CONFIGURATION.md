# Справочник настроек сервера ConsoleCrypt

> То же самое на сайте: [справочник параметров](https://consolecrypt.dev/guide#server-reference).
> Same on the website: [configuration reference](https://consolecrypt.dev/guide#server-reference).

Полный список параметров сервера синхронизации **0.2.3** (протокол **1.11**):
что делает каждый ключ, какие значения он принимает, значение по умолчанию,
путь в Helm и является ли значение секретом. Справочник составлен по коду загрузки
конфигурации (`server/src/config.rs`, `server/src/config/*.rs`,
`server/src/telemetry.rs`) и шаблонам Helm chart. Проверка
`server/scripts/test_configuration_docs.py` падает, если сервер принимает ключ,
которого здесь нет, или здесь описан ключ, которого сервер не знает.

Как задавать параметры в Docker Compose, `docker run`, Helm, JSON-файле и
systemd, с готовыми примерами — в [HOSTING.md](HOSTING.md#как-задать-любой-параметр).
Пошаговое подключение IdP и Active Directory — в [ENTERPRISE.md](ENTERPRISE.md).

English version: [below](#english).

## Как сервер читает настройки

**Источники и приоритет.** Сервер читает переменные окружения `CC_*` и,
необязательно, приватный JSON-файл:

1. переменная окружения процесса (в том числе **явно пустая**);
2. значение из JSON-файла, указанного флагом `--config <путь>`, а без флага —
   переменной `CC_CONFIG_FILE`;
3. встроенное значение по умолчанию.

Пустое значение равно «не задано»: если в окружении есть `CC_X=` (пусто), сервер
использует значение по умолчанию **и не смотрит в JSON-файл** для этого ключа.
Из окружения читаются только известные ключи этого справочника; переменная с
опечаткой в имени молча игнорируется. В JSON-файле, наоборот, неизвестный или
повторённый ключ останавливает запуск.

**Формат значений.**

| Тип | Как записывать |
|---|---|
| логический | `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` (строчными буквами) |
| целое число | десятичная запись без единиц и разделителей: `1073741824`, а не `1GiB` |
| длительность | целое число в единицах из имени ключа: `_SECS` — секунды, `_MINUTES` — минуты, `_HOURS` — часы, `_DAYS` — сутки |
| адрес | `хост:порт`, например `0.0.0.0:8080` или `[::]:8080` |
| список | через запятую и/или пробел (`CC_AUTH_ALLOWED_DOMAINS`, `CC_OIDC_MFA_ACR_VALUES`); `CC_OIDC_SCOPES` — через пробел |
| путь к файлу | абсолютный путь внутри контейнера или на хосте службы |

В JSON-файле все значения — строки, включая числа и логические значения:
`{"CC_MAX_VAULT_OBJECTS": "200000", "CC_HSTS": "true"}`.

**Проверка при запуске.** Неверное значение останавливает сервер с сообщением
`invalid configuration: <КЛЮЧ>: …`; значение в сообщение не попадает.
Проверяются диапазоны (они указаны в таблицах) и связи между ключами:

- любой флаг совместного доступа требует `CC_OBJECT_SHARING_ENABLED=true` и
  `CC_REQUIRE_REQUEST_PROOF=true`;
- `CC_REFRESH_TOKEN_TTL_SECS` не меньше `CC_ACCESS_TOKEN_TTL_SECS`;
- `CC_AUTH_MODE=enterprise` требует `CC_AUTH_PROVIDER` и ключей выбранного
  провайдера, OIDC — ещё и `CC_PUBLIC_URL` с `https://`.

Enterprise-режим дополнительно проверяет при старте сеть: discovery и JWKS
IdP или подключение, TLS и bind к каталогу (см. [ENTERPRISE.md](ENTERPRISE.md)).
При старте сервер пишет в журнал строку `starting` с действующей конфигурацией;
пароли и URL базы в ней скрыты. По ней удобно проверить, что ключ дошёл до
процесса.

**Когда применяются изменения.** Только при перезапуске процесса: файл и
окружение перечитываются не на лету. Исключение — переопределения лимитов
отдельного аккаунта (`admin limits set`), они действуют без перезапуска не позже
чем через 30 секунд.

**Секреты.** Секретные значения — `CC_DATABASE_URL` (если содержит пароль),
`CC_DATABASE_PASSWORD`, `CC_SMTP_PASSWORD` и файлы enterprise-входа. Сервер не
пишет их в журнал. Общего механизма `*_FILE` нет: переменных вида
`CC_DATABASE_PASSWORD_FILE` или `CC_SMTP_PASSWORD_FILE` сервер не знает. Из файла
читаются только пять ключей, которые сами являются путями:
`CC_OIDC_CLIENT_SECRET_FILE`, `CC_OIDC_TOKEN_KEY_FILE`,
`CC_LDAP_BIND_PASSWORD_FILE`, `CC_OIDC_CA_FILE`, `CC_LDAP_CA_FILE`. Пароли базы и
SMTP передавайте через окружение (Kubernetes `secretKeyRef`, приватный
`server.env`) или через приватный JSON-файл с правами `0600`.

**Какие команды читают конфигурацию.** `serve` (по умолчанию), `migrate` и
`admin …` загружают и проверяют всю конфигурацию, поэтому команде `admin` нужны
те же ключи, что и серверу (в контейнере они уже есть). `healthcheck` читает
только `CC_LISTEN_ADDR` и проверяет `http://127.0.0.1:<порт>/readyz`.

## Сеть, публичный адрес, TLS и proxy

Сервер сам не завершает TLS и не имеет ключей сертификатов: HTTPS обеспечивает
reverse proxy или Ingress перед ним. Proxy должен передавать WebSocket
`/v1/events/ws`, принимать тела запросов до 16 MiB и не менять путь, query и
тело: они входят в подпись устройства.

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_LISTEN_ADDR` | — (в chart всегда `0.0.0.0:8080`) | `0.0.0.0:8080` | `хост:порт` | нет | Адрес и порт HTTP/WebSocket API. На хосте без контейнера и proxy на той же машине задайте `127.0.0.1:8080`, чтобы API не был доступен напрямую. Порт берёт и `healthcheck`. |
| `CC_PUBLIC_URL` | `config.publicUrl` | не задан | URL `https://…` | нет | Публичный базовый адрес экземпляра (`https://sync.example.org`, без `/v1`). Из него строятся кнопки в письмах (`/account#action=verify`, `reset`, `deny-device`) и адрес возврата OIDC `CC_PUBLIC_URL/v1/auth/oidc/callback`. Без него письма содержат только код и не упоминают веб-страницу. Должен быть абсолютным `http(s)://` адресом без `?` и `#` (иначе сервер не запустится). Для OIDC обязателен и должен начинаться с `https://` (`http://` — только `127.0.0.1`/`localhost` для разработки). Страницу `/account` по этому адресу обслуживает ваш сайт или сам сервер (`CC_WEB_ACCOUNT=true`); если её нет, ссылки из писем вернут 404 — коды в письмах всё равно работают в приложении. |
| `CC_WEB_ACCOUNT` | `config.webAccount` | `false` | логическое | нет | Встроенная страница аккаунта на самом сервере: `GET /account` (+ `app.js`, `app.css`). Подтверждение email, новый пароль по коду из письма, «Это не я» для писем о новых устройствах — только через публичные эндпоинты с кодом, без входа, cookie и доступа к хранилищу; строгий same-origin CSP. Для self-hosted без сайта: включите и задайте `CC_PUBLIC_URL` равным адресу сервера, reverse proxy должен передавать `/account` и `/account/*`. Выключено — сервер остаётся только API. |
| `CC_TRUST_PROXY_HEADERS` | `config.trustProxyHeaders` (`auto` = `ingress.enabled`, `"true"`, `"false"`) | `false` | логическое | нет | Брать адрес клиента из **последнего** элемента `X-Forwarded-For` (то, что добавил ваш proxy). Включайте только при одном доверенном proxy, который перезаписывает или дополняет заголовок, и при закрытом прямом доступе к порту API — иначе клиент подделает адрес. Без него все лимиты по IP видят только адрес proxy. |
| `CC_HSTS` | `config.hsts` | `true` | логическое | нет | Добавлять `Strict-Transport-Security: max-age=63072000; includeSubDomains`. Выключайте, только если proxy сам ставит HSTS или поддомены должны оставаться доступными по HTTP. |
| `CC_SOURCE_CODE_URL` | `config.sourceCodeUrl` | адрес исходников сборки (образ задаёт его сам) | URL | нет | Ссылка на исходный код, которую `/v1/meta` отдаёт как `source_code_url` (AGPL-3.0 §13). Для официального образа не задавайте. Если вы запускаете **изменённый** сервер, укажите, где взять ваш исходный код. |

## База данных и пул соединений

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_DATABASE_URL` | `database.url`, `database.existingSecret` + `database.existingSecretKey` или встроенная `postgresql.*` | **обязателен** | `postgres://…` URL | да, если с паролем | URL PostgreSQL 16: `postgres://пользователь@хост:5432/база?sslmode=verify-full`. Для внешней базы используйте `sslmode=verify-full` и при собственном CA — `sslrootcert=<путь в контейнере>`. Пароль в URL нужно percent-encode; проще передать его отдельно в `CC_DATABASE_PASSWORD`. **Секрет**, если содержит пароль. В Helm `database.url` хранится в Secret chart, `existingSecret` — в вашем Secret. |
| `CC_DATABASE_PASSWORD` | только со встроенной базой (`postgresql.auth.password` / `existingSecret`); для внешней — `extraEnv` с `secretKeyRef` | не задан | строка | да | Пароль, который подставляется поверх URL; экранирование не нужно. **Секрет.** Если не задан ни здесь, ни в URL, драйвер использует стандартную переменную `PGPASSWORD`. |
| `DATABASE_URL` | — | не задан | `postgres://…` URL | да, если с паролем | Прежнее имя `CC_DATABASE_URL`, **только окружение**. Используется, если `CC_DATABASE_URL` не задан в окружении процесса; тогда оно важнее `CC_DATABASE_URL` из JSON-файла. **Секрет**, если содержит пароль. |
| `CC_DATABASE_MAX_CONNECTIONS` | `database.maxConnections` | `20` | целое ≥ 1 | нет | Размер пула на один процесс (pod), не меньше 1. Каждый процесс держит ещё одно соединение для `LISTEN/NOTIFY`. Следите, чтобы `реплики × (значение + 1)` было меньше `max_connections` PostgreSQL. Ожидание свободного соединения — 5 секунд. |
| `CC_DATABASE_CONNECT_TIMEOUT_SECS` | `database.connectTimeoutSecs` | `60` | секунды, целое | нет | Сколько секунд запуск повторяет попытки подключиться к недоступной базе (пауза растёт от 0,25 до 5 секунд), прежде чем завершиться с ошибкой. Действует для `serve`, `migrate` и `admin`. |
| `CC_RUN_MIGRATIONS` | `migrations.runAtStartup` | `true` | логическое | нет | Применять встроенные миграции при запуске (под advisory lock — безопасно для нескольких реплик). `false` — только если миграции выполняются отдельно (`consolecrypt-server migrate`, Helm `migrations.job.enabled`) или для заранее проверенного отката. Откат образа миграции не отменяет. |
| `CC_EVENT_BUS` | `config.eventBus` | `postgres` | `postgres`, `local` | нет | Как события реального времени доходят до WebSocket-клиентов: `postgres` (`LISTEN/NOTIFY`, работает с любым числом реплик) или `local` (внутри одного процесса, только одна реплика; chart запрещает `local` при `replicaCount > 1` и автомасштабировании). |

## Почта (SMTP)

Почта нужна для кодов подтверждения адреса и сброса пароля, писем защиты
устройств, предупреждений о неудачных входах и приглашений в команды.

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_MAIL_TRANSPORT` | `mail.transport` | `disabled` | `disabled` (`none`), `smtp`, `file` | нет | `disabled` (или `none`) — письма не отправляются, администратор использует `admin verify-email` и `admin reset-token`; `smtp` — отправка через SMTP; `file` — только для разработки, каждое письмо записывается файлом в `CC_MAIL_DIR`. |
| `CC_MAIL_DIR` | `mail.file.dir` (emptyDir в pod) | `./.dev-mail` | путь к каталогу | нет | Каталог для `file`; путь относительно рабочего каталога процесса. Файлы создаются с правами `0600`. |
| `CC_MAIL_FROM` | `mail.from` | `ConsoleCrypt <no-reply@localhost>` | адрес `Имя <a@example.org>` | нет | Отправитель. Адрес должен быть разрешён вашим SMTP-сервером и DNS-записями отправителя. |
| `CC_MAIL_LANGUAGE` | `mail.language` | `ru` | `ru`, `en` | нет | Язык писем и встроенной страницы аккаунта. Письма уходят в HTML с текстовой альтернативой (UTF-8); код всегда показан для вставки в приложение, срок его действия берётся из настроек TTL. |
| `CC_SMTP_HOST` | `mail.smtp.host` | — | имя хоста | нет | Имя SMTP-сервера; обязательно при `smtp`. |
| `CC_SMTP_PORT` | `mail.smtp.port` | `587` | 1–65535 | нет | Порт SMTP (1–65535). |
| `CC_SMTP_TLS` | `mail.smtp.tls` | `starttls` | `starttls`, `tls`, `none` | нет | `starttls` (обычно 587), `tls` — неявный TLS (обычно 465), `none` — без шифрования, только для локального relay или тестового перехватчика писем. |
| `CC_SMTP_USERNAME` | `mail.smtp.username` | не задан | строка | нет | Логин SMTP. Пусто — без аутентификации (relay с доступом по IP). |
| `CC_SMTP_PASSWORD` | `mail.smtp.password` (Secret chart) или `mail.smtp.existingSecret` + `existingSecretPasswordKey` | не задан | строка | да | Пароль SMTP. **Секрет**: в Helm используйте `existingSecret`. |

## Регистрация, подтверждение адреса, токены и пароли аккаунтов

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_REGISTRATION_OPEN` | `config.registrationOpen` | `true` | логическое | нет | Разрешить регистрацию новых аккаунтов. `false` — регистрация отвечает 403, `/v1/meta` сообщает `registration_open: false`; существующие аккаунты работают. В enterprise-режиме не действует: аккаунты создаёт первый вход через IdP/каталог (`CC_AUTH_AUTO_CREATE`). |
| `CC_REQUIRE_EMAIL_VERIFICATION` | `config.requireEmailVerification` | `false` | логическое | нет | Требовать подтверждённый адрес: без него вход, создание хранилища, команды и общего объекта отвечают `email_not_verified`. Нужна почта или `admin verify-email`. Пример Docker Compose включает его. |
| `CC_EMAIL_VERIFY_TTL_SECS` | `config.tokens.emailVerifyTtlSecs` | `172800` (48 ч) | секунды, целое | нет | Срок действия кода подтверждения адреса. |
| `CC_PASSWORD_RESET_TTL_SECS` | `config.tokens.passwordResetTtlSecs` | `3600` (1 ч) | секунды, целое | нет | Срок действия кода сброса пароля аккаунта (из письма или `admin reset-token`). |
| `CC_ACCESS_TOKEN_TTL_SECS` | `config.tokens.accessTtlSecs` | `900` (15 мин) | секунды, 60–86400 | нет | Срок жизни access token, 60–86400. Короче — быстрее действует отзыв, но чаще обновление. |
| `CC_REFRESH_TOKEN_TTL_SECS` | `config.tokens.refreshTtlSecs` | `2592000` (30 сут) | секунды, ≥ `CC_ACCESS_TOKEN_TTL_SECS` | нет | Срок жизни refresh token (сеанса устройства без обновления); не меньше access token. После него устройство входит заново. |
| `CC_ARGON2_MEMORY_KIB` | `config.argon2.memoryKib` | `19456` (19 MiB) | KiB, целое | нет | Память Argon2id для хэша **пароля аккаунта** (ключи хранилищ сервер не получает). Новые параметры применяются к новым хэшам; существующие проверяются со своими параметрами до смены пароля. |
| `CC_ARGON2_ITERATIONS` | `config.argon2.iterations` | `2` | целое ≥ 1 | нет | Число проходов Argon2id. |
| `CC_ARGON2_PARALLELISM` | `config.argon2.parallelism` | `1` | целое ≥ 1 | нет | Параллелизм Argon2id. |
| `CC_ARGON2_MAX_CONCURRENT` | `config.argon2.maxConcurrent` (`4`) | число CPU, не больше 4 | целое ≥ 1 | нет | Сколько хэшей считается одновременно (защита CPU и памяти от перегрузки входами), не меньше 1. Пиковая память ≈ `CC_ARGON2_MEMORY_KIB × CC_ARGON2_MAX_CONCURRENT` — держите её заметно ниже лимита памяти контейнера. |

## Устройства и защита от входа с нового устройства

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_REQUIRE_REQUEST_PROOF` | `config.requireRequestProof` | `true` | логическое | нет | Требовать подпись каждого запроса ключом устройства (протокол 1.5): украденный токен бесполезен без ключа. `false` — временное исключение для старых клиентов: неверные подписи по-прежнему отклоняются, отсутствующие только считаются (`cc_request_proofs_total{result="missing"}`). Совместный доступ требует `true`. |
| `CC_DEVICE_REQUEST_TTL_SECS` | `config.tokens.deviceRequestTtlSecs` | `86400` (24 ч) | секунды, целое | нет | Сколько живёт запрос доверия нового устройства, ожидающий одобрения на доверенном устройстве. |
| `CC_DEVICE_PROTECTION_ENABLED` | `config.deviceProtection.enabled` | `false` | логическое | нет | Защита от входа с нового устройства: карантин, ограничение выдачи материала разблокировки неподтверждённым устройствам, письма «новое устройство», событие `device_registered`, отзыв неиспользованных устройств при сбросе пароля. Ссылки «Это не я» ведут на `CC_PUBLIC_URL/account`. Подробно — [HOSTING.md](HOSTING.md#защита-от-входа-с-нового-устройства). |
| `CC_NEW_DEVICE_MAIL_ENABLED` | `config.deviceProtection.newDeviceMail` | `true` | логическое | нет | Письма о новом устройстве (действует при включённой защите и настроенной почте). |
| `CC_DEVICE_QUARANTINE_DAYS` | `config.deviceProtection.quarantineDays` | `14` | сутки, 0–365 | нет | Карантин нового устройства в сутках, 0–365: в это время оно не может отзывать доверенные устройства, а смена пароля и «выход везде» с него не завершают сеансы доверенных устройств. `0` — без карантина. |
| `CC_ENVELOPE_LIMIT_ACCOUNT_PER_HOUR` | `config.deviceProtection.envelopesPerAccountPerHour` | `5` | целое ≥ 0, `0` — без лимита | нет | Сколько раз в час неподтверждённые устройства аккаунта могут получить материал разблокировки хранилища (`0` — без ограничения). Счётчики общие для всех реплик. |
| `CC_ENVELOPE_LIMIT_ACCOUNT_PER_DAY` | `config.deviceProtection.envelopesPerAccountPerDay` | `20` | целое ≥ 0, `0` — без лимита | нет | То же за сутки. |
| `CC_ENVELOPE_LIMIT_DEVICE_PER_HOUR` | `config.deviceProtection.envelopesPerDevicePerHour` | `3` | целое ≥ 0, `0` — без лимита | нет | То же для одного неподтверждённого устройства за час. |
| `CC_NEW_DEVICE_MAIL_PER_HOUR` | `config.deviceProtection.newDeviceMailsPerHour` | `10` | целое ≥ 0 | нет | Писем о новых устройствах на аккаунт в час; остальные входы часа сводятся в одно письмо. |

## Синхронизация, WebSocket и квоты

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_SYNC_PAGE_BYTES` | `config.sync.pageBytes` | `8388608` (8 MiB) | байты, ≥ 65536 | нет | Бюджет байт одной страницы `changes`/`snapshot` и списков общего доступа, не меньше 65536. |
| `CC_QUOTAS_V2_ENABLED` | `config.quotas.v2Enabled` | `true` | логическое | нет | Квоты сервера 0.2.2: учёт надгробий и объектов, пределы устройств, удаление неизвестного объекта без надгробия. `false` возвращает поведение 0.2.1 (счётчики продолжают вестись). |
| `CC_MAX_VAULT_BYTES` | `config.quotas.maxVaultBytes` | `1073741824` (1 GiB) | байты, ≥ 1048576 | нет | Шифротекст плюс надгробия на одно хранилище, не меньше 1 MiB. Сверх — `413`, `details.reason = "vault_quota"`. |
| `CC_TOMBSTONE_COST_BYTES` | `config.quotas.tombstoneCostBytes` | `256` | байты, 0–1048576 | нет | Сколько байт квоты стоит каждое надгробие (удалённый объект), 0–1048576. |
| `CC_MAX_VAULT_OBJECTS` | `config.quotas.maxVaultObjects` | `100000` | целое ≥ 1 | нет | Живых объектов и надгробий в одном хранилище, не меньше 1. Сверх — `413`, `object_limit`. |
| `CC_MAX_VAULTS_PER_ACCOUNT` | `config.quotas.maxVaultsPerAccount` | `50` | целое ≥ 1 | нет | Хранилищ, которыми владеет аккаунт, не меньше 1. Сверх — `403`, `vault_limit`. |
| `CC_MAX_DEVICES_PER_ACCOUNT` | `config.quotas.maxDevicesPerAccount` | `20` | 1–64 | нет | Неотозванных устройств аккаунта, 1–64 (64 — предел получателей общего объекта). Вход с ещё одного — `403`, `device_limit`. |
| `CC_NEW_DEVICES_PER_ACCOUNT_PER_DAY` | `config.quotas.newDevicesPerAccountPerDay` | `10` | целое ≥ 0, `0` — без лимита | нет | Новых устройств аккаунта за любые 24 часа, `0` — без ограничения. Сверх — `403`, `device_daily_limit` с `details.until`. |
| `CC_WS_PING_INTERVAL_SECS` | `config.websocket.pingIntervalSecs` | `30` | секунды, ≥ 1 | нет | Интервал ping в WebSocket, не меньше 1. Уменьшите, если proxy закрывает «тихие» соединения быстрее. |
| `CC_WS_SESSION_RECHECK_SECS` | `config.websocket.sessionRecheckSecs` | `30` | секунды, 1–30 | нет | Как часто открытый WebSocket проверяет, что сеанс не отозван, 1–30: отзыв доходит до сокетов не позже чем за 30 секунд. |
| `CC_WS_MAX_CONNECTIONS_PER_USER` | `config.websocket.maxConnectionsPerUser` | `32` | целое ≥ 1 | нет | Одновременных WebSocket-подключений аккаунта на одну реплику, не меньше 1; сверх — `429`. |

Квоты отдельного аккаунта меняются без перезапуска: `admin limits set --email …
max_vault_bytes=… max_vault_objects=… max_devices_per_account=…
new_devices_per_account_per_day=…`. `CC_MAX_VAULTS_PER_ACCOUNT` так не
переопределяется.

## Совместный доступ и команды

Все флаги совместного доступа выключены по умолчанию и требуют
`CC_OBJECT_SHARING_ENABLED=true` и `CC_REQUIRE_REQUEST_PROOF=true` (иначе сервер не
запустится). Выключение флага скрывает объекты этого типа, не удаляя их
шифротекст. Возможности клиент узнаёт авторизованным запросом
`/v1/shares/capabilities`. Подробности — [SHARING.md](SHARING.md).

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_OBJECT_SHARING_ENABLED` | `config.objectSharingEnabled` | `false` | логическое | нет | Основной механизм совместного доступа к хостам. |
| `CC_SHARED_GROUPS_ENABLED` | `config.sharedGroupsEnabled` | `false` | логическое | нет | Общие группы (коллекции). |
| `CC_SHARED_SECRETS_ENABLED` | `config.sharedSecretsEnabled` | `false` | логическое | нет | Отдельные общие секреты. |
| `CC_SHARED_KUBE_CONTEXTS_ENABLED` | `config.sharedKubeContextsEnabled` | `false` | логическое | нет | Общие подключения Kubernetes (`supports_kube_contexts`). |
| `CC_SHARED_DB_CONNECTIONS_ENABLED` | `config.sharedDbConnectionsEnabled` | `false` | логическое | нет | Общие подключения к базам данных (`supports_db_connections`). |
| `CC_SHARED_NOTES_ENABLED` | `config.sharedNotesEnabled` | `false` | логическое | нет | Общие заметки к общим объектам (`supports_notes_v1`): до 500 заметок на объект, до 288 KiB шифротекста на заметку. |
| `CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED` | `config.sharingOwnerOnlineEnrollmentEnabled` | `false` | логическое | нет | Добавление новых собственных устройств получателя при участии владельца. |
| `CC_TEAMS_ENABLED` | `extraEnv` | `true` | логическое | нет | Команды (общие хранилища, `/v1/teams/*`, `capabilities.teams` в `/v1/meta`). Не зависит от флагов совместного доступа. При `false` маршруты команд отвечают 404, данные сохраняются. |
| `CC_MAX_TEAMS_PER_ACCOUNT` | `extraEnv` | `50` | целое ≥ 1 | нет | Команд, в которых может состоять аккаунт, не меньше 1. |
| `CC_MAX_TEAM_MEMBERS` | `extraEnv` | `200` | целое ≥ 2 | нет | Участников одной команды, не меньше 2. |

## Лимиты запросов

Лимиты защищают сервер от одного аккаунта, устройства или адреса. Большинство
лимитов хранится в PostgreSQL (token bucket по времени базы) и одинаково
действует на всех репликах; три лимита первой ступени живут в памяти каждой
реплики. При отказе — `429 rate_limited` с `Retry-After` и `details.limit`.

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_RATE_LIMIT_ENABLED` | `config.rateLimit.enabled` | `true` | логическое | нет | `false` выключает **все** лимиты запросов (квоты остаются). Только для отладки. |
| `CC_RATE_LIMIT_MODE` | `config.rateLimit.mode` | `observe` | `observe`, `enforce` | нет | `observe` — превышения лимитов PostgreSQL и лимита чтений только считаются (`cc_rate_limit_observed_total{limiter}`, событие аудита `limit_exceeded` не чаще раза в час на аккаунт и лимит); `enforce` — отклоняются. Лимиты входа и восстановления (отмечены ниже) и первые ступени `CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE` и `CC_RATE_LIMIT_PROOF_PER_DEVICE_PER_MINUTE` действуют в обоих режимах. Порядок: неделю наблюдайте метрику, при необходимости поднимите пороги, затем `enforce`. |
| `CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE` | `config.rateLimit.authPerIpPerMinute` | `30` | целое, в минуту | нет | Первая ступень в памяти реплики: публичные запросы входа, регистрации и восстановления с одного IP (IPv6 — по /64) в минуту. Пока не задан `CC_LIMIT_AUTH_IP_RATE`, это же значение задаёт общий лимит `auth_ip`. |
| `CC_RATE_LIMIT_PROOF_PER_DEVICE_PER_MINUTE` | `config.rateLimit.proofPerDevicePerMinute` | `20` | целое, в минуту | нет | В памяти реплики: попыток подтверждения ключа (attest/approve) на устройство в минуту. |
| `CC_RATE_LIMIT_READ_PER_DEVICE_PER_MINUTE` | `config.rateLimit.readPerDevicePerMinute` | `1200` | целое, в минуту; `0` — выкл. | нет | В памяти реплики: авторизованных чтений (GET) на устройство в минуту; `0` — без лимита. Подчиняется `CC_RATE_LIMIT_MODE`. |
| `CC_RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE` | `config.rateLimit.loginPerEmailPerMinute` | не задан (`10`) | целое, в минуту | нет | Прежнее имя (до 0.2.2): частота лимита `login_email` в минуту (и его ёмкость). Если задан `CC_LIMIT_LOGIN_EMAIL_RATE`, игнорируется. |
| `CC_RATE_LIMIT_RECOVERY_PER_EMAIL_PER_HOUR` | `config.rateLimit.recoveryPerEmailPerHour` | не задан (`5`) | целое, в час | нет | Прежнее имя: частота `recovery_email` в час. Если задан `CC_LIMIT_RECOVERY_EMAIL_RATE`, игнорируется. |

### Лимиты PostgreSQL: `CC_LIMIT_<ИМЯ>_*`

У каждого лимита четыре ключа (`<ИМЯ>` — имя лимита заглавными буквами):

- `CC_LIMIT_<ИМЯ>_RATE` — частота основного bucket: `N` в естественном периоде
  лимита (указан в таблице) или `N/s`, `N/sec`, `N/min` (`N/m`), `N/hour` (`N/h`),
  `N/day` (`N/d`); дробное `N` допустимо; `0` — без основного bucket. Если задана
  только частота, ёмкость становится равной одному периоду этой частоты.
- `CC_LIMIT_<ИМЯ>_BURST` — ёмкость bucket (сколько запросов подряд), целое не
  меньше 1. По умолчанию — один период частоты, если в таблице не указан всплеск.
- `CC_LIMIT_<ИМЯ>_PER_HOUR`, `CC_LIMIT_<ИМЯ>_PER_DAY` — дополнительные потолки
  за час и за сутки, целые; `0` — нет потолка.

Лимит без частоты и потолков не ограничивает ничего. В Helm все четыре ключа
задаются блоком `config.rateLimit.limits`, например
`{push_account: {rate: "600/min", burst: 600, perHour: 0, perDay: 0}}` (поля
`rate`, `burst`, `perHour`, `perDay`). Для отдельного аккаунта —
`admin limits set --email … push_account_rate=600/min` (суффиксы `_rate`,
`_burst`, `_per_hour`, `_per_day`); лимиты входа так не переопределяются.

| Имя | Что ограничено | По умолчанию | Ключи |
|---|---|---|---|
| `push_device` | отправка изменений с одного устройства | 120/мин, всплеск 60 | `CC_LIMIT_PUSH_DEVICE_RATE`, `CC_LIMIT_PUSH_DEVICE_BURST`, `CC_LIMIT_PUSH_DEVICE_PER_HOUR`, `CC_LIMIT_PUSH_DEVICE_PER_DAY` |
| `push_account` | отправка изменений всеми устройствами аккаунта | 300/мин | `CC_LIMIT_PUSH_ACCOUNT_RATE`, `CC_LIMIT_PUSH_ACCOUNT_BURST`, `CC_LIMIT_PUSH_ACCOUNT_PER_HOUR`, `CC_LIMIT_PUSH_ACCOUNT_PER_DAY` |
| `mutations_account` | число изменений внутри отправок аккаунта | 50 000/час | `CC_LIMIT_MUTATIONS_ACCOUNT_RATE`, `CC_LIMIT_MUTATIONS_ACCOUNT_BURST`, `CC_LIMIT_MUTATIONS_ACCOUNT_PER_HOUR`, `CC_LIMIT_MUTATIONS_ACCOUNT_PER_DAY` |
| `unknown_delete_account` | удаление объектов, которых на сервере не было | 1000/сутки | `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_RATE`, `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_BURST`, `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_PER_HOUR`, `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_PER_DAY` |
| `share_write_account` | создание общих объектов | 60/час, всплеск 20 | `CC_LIMIT_SHARE_WRITE_ACCOUNT_RATE`, `CC_LIMIT_SHARE_WRITE_ACCOUNT_BURST`, `CC_LIMIT_SHARE_WRITE_ACCOUNT_PER_HOUR`, `CC_LIMIT_SHARE_WRITE_ACCOUNT_PER_DAY` |
| `share_revision_account` | ревизии общих объектов, смена доступа, общие заметки | 600/час | `CC_LIMIT_SHARE_REVISION_ACCOUNT_RATE`, `CC_LIMIT_SHARE_REVISION_ACCOUNT_BURST`, `CC_LIMIT_SHARE_REVISION_ACCOUNT_PER_HOUR`, `CC_LIMIT_SHARE_REVISION_ACCOUNT_PER_DAY` |
| `recipient_lookup_account` | поиск получателя по адресу почты | 30/мин и 300/сутки | `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_RATE`, `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_BURST`, `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_PER_HOUR`, `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_PER_DAY` |
| `enrollment_account` | добавление собственных устройств получателя | 30/час | `CC_LIMIT_ENROLLMENT_ACCOUNT_RATE`, `CC_LIMIT_ENROLLMENT_ACCOUNT_BURST`, `CC_LIMIT_ENROLLMENT_ACCOUNT_PER_HOUR`, `CC_LIMIT_ENROLLMENT_ACCOUNT_PER_DAY` |
| `trust_request_device` | запросы доверия с одного устройства | 10/час | `CC_LIMIT_TRUST_REQUEST_DEVICE_RATE`, `CC_LIMIT_TRUST_REQUEST_DEVICE_BURST`, `CC_LIMIT_TRUST_REQUEST_DEVICE_PER_HOUR`, `CC_LIMIT_TRUST_REQUEST_DEVICE_PER_DAY` |
| `trust_request_account` | запросы доверия всех устройств аккаунта | 30/сутки | `CC_LIMIT_TRUST_REQUEST_ACCOUNT_RATE`, `CC_LIMIT_TRUST_REQUEST_ACCOUNT_BURST`, `CC_LIMIT_TRUST_REQUEST_ACCOUNT_PER_HOUR`, `CC_LIMIT_TRUST_REQUEST_ACCOUNT_PER_DAY` |
| `verification_account` | сверка ключей: объявление одобряющего устройства, подписанные отпечатки ключа хранилища | 20/час | `CC_LIMIT_VERIFICATION_ACCOUNT_RATE`, `CC_LIMIT_VERIFICATION_ACCOUNT_BURST`, `CC_LIMIT_VERIFICATION_ACCOUNT_PER_HOUR`, `CC_LIMIT_VERIFICATION_ACCOUNT_PER_DAY` |
| `account_security` | смена пароля, перевыпуск комплекта восстановления, замена конверта | 10/час | `CC_LIMIT_ACCOUNT_SECURITY_RATE`, `CC_LIMIT_ACCOUNT_SECURITY_BURST`, `CC_LIMIT_ACCOUNT_SECURITY_PER_HOUR`, `CC_LIMIT_ACCOUNT_SECURITY_PER_DAY` |
| `ws_connect_account` | новые WebSocket-подключения аккаунта | 60/мин | `CC_LIMIT_WS_CONNECT_ACCOUNT_RATE`, `CC_LIMIT_WS_CONNECT_ACCOUNT_BURST`, `CC_LIMIT_WS_CONNECT_ACCOUNT_PER_HOUR`, `CC_LIMIT_WS_CONNECT_ACCOUNT_PER_DAY` |
| `auth_ip` (всегда действует) | публичные запросы входа, регистрации и восстановления с одного адреса, общий для реплик | 30/мин | `CC_LIMIT_AUTH_IP_RATE`, `CC_LIMIT_AUTH_IP_BURST`, `CC_LIMIT_AUTH_IP_PER_HOUR`, `CC_LIMIT_AUTH_IP_PER_DAY` |
| `login_email` (всегда действует) | **неудачные** входы на один адрес почты из одной сети (/24 IPv4, /64 IPv6) | 10/мин и 50/час | `CC_LIMIT_LOGIN_EMAIL_RATE`, `CC_LIMIT_LOGIN_EMAIL_BURST`, `CC_LIMIT_LOGIN_EMAIL_PER_HOUR`, `CC_LIMIT_LOGIN_EMAIL_PER_DAY` |
| `login_email_total` (всегда действует) | неудачные входы на адрес из всех сетей | 200/час | `CC_LIMIT_LOGIN_EMAIL_TOTAL_RATE`, `CC_LIMIT_LOGIN_EMAIL_TOTAL_BURST`, `CC_LIMIT_LOGIN_EMAIL_TOTAL_PER_HOUR`, `CC_LIMIT_LOGIN_EMAIL_TOTAL_PER_DAY` |
| `recovery_email` (всегда действует) | запросы сброса пароля на адрес из одной сети | 5/час | `CC_LIMIT_RECOVERY_EMAIL_RATE`, `CC_LIMIT_RECOVERY_EMAIL_BURST`, `CC_LIMIT_RECOVERY_EMAIL_PER_HOUR`, `CC_LIMIT_RECOVERY_EMAIL_PER_DAY` |
| `recovery_email_total` (всегда действует) | письма сброса на адрес из всех сетей (ответ всегда `202`) | 20/сутки | `CC_LIMIT_RECOVERY_EMAIL_TOTAL_RATE`, `CC_LIMIT_RECOVERY_EMAIL_TOTAL_BURST`, `CC_LIMIT_RECOVERY_EMAIL_TOTAL_PER_HOUR`, `CC_LIMIT_RECOVERY_EMAIL_TOTAL_PER_DAY` |

Чужие попытки не блокируют владельца: успешный вход лимиты почты не тратит, а
вход с известного устройства аккаунта ограничивается только адресом. Действующие
значения: `consolecrypt-server admin limits show` (с `--email` — для аккаунта).

## Enterprise-вход: `CC_AUTH_*`, `CC_OIDC_*`, `CC_LDAP_*`

В режиме `standard` ключи провайдеров не читаются и не проверяются, поэтому
переход туда и обратно — смена одного `CC_AUTH_MODE`. Порядок настройки,
рецепты для IdP и каталога, команды и разбор ошибок — в [ENTERPRISE.md](ENTERPRISE.md).
В Helm блок `auth:`; секреты берутся из существующего Secret, который chart
монтирует только для чтения в `/run/secrets/consolecrypt-auth`, и пути `*_FILE`
chart подставляет сам.

### Общие ключи

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_AUTH_MODE` | `auth.mode` | `standard` | `standard`, `enterprise` | нет | `standard` — email и пароль аккаунта; `enterprise` — вход только через IdP (OIDC) или каталог (LDAP), регистрация и пароли аккаунтов выключены. |
| `CC_AUTH_PROVIDER` | `auth.provider` | — | `oidc`, `ldap` | нет | `oidc` или `ldap`; обязателен в enterprise. |
| `CC_AUTH_DISPLAY_NAME` | `auth.displayName` | не задан | до 64 печатных символов | нет | Подпись кнопки входа в приложении («Войти через …»), до 64 печатных символов. |
| `CC_AUTH_ALLOWED_DOMAINS` | `auth.allowedDomains` (список) | пусто — любые | список доменов | нет | Допустимые домены почты (`acme.com, acme.ru`; `@` в начале отбрасывается, регистр не важен, поддомены не включаются). Нужен для автоматической привязки существующих аккаунтов с паролем; обязателен для пресета `google`. |
| `CC_AUTH_AUTO_CREATE` | `auth.autoCreate` | `true` | логическое | нет | Создавать аккаунт при первом входе новой учётной записи. `false` — входят только уже существующие или привязанные аккаунты, остальным `403` (`not_provisioned`). |
| `CC_AUTH_RECHECK_MINUTES` | `auth.recheckMinutes` | `15` | минуты, 1–1440 | нет | Как часто (1–1440 мин) перепроверять пользователя в IdP/каталоге. Отключённый сотрудник теряет синхронизацию не позже чем через это время + 1 минуту. |
| `CC_AUTH_RECHECK_GRACE_HOURS` | `auth.recheckGraceHours` | `24` | часы, 0–720 | нет | Сколько часов (0–720) сеансы живут, пока IdP/каталог недоступен; затем обновление отвечает `503 idp_unavailable`. |

### OIDC

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_OIDC_PRESET` | `auth.oidc.preset` | `generic` | `generic`, `entra`, `adfs`, `keycloak`, `google`, `okta` | нет | `generic`, `entra`, `adfs`, `keycloak`, `google`, `okta`: значения по умолчанию и проверки при старте (Entra — issuer с tenant id, без `/common`, `/organizations`, `/consumers`; AD FS — оканчивается на `/adfs`; Keycloak — содержит `/realms/`; Google — фиксированный issuer, обязательный список доменов, проверка `hd`). |
| `CC_OIDC_ISSUER` | `auth.oidc.issuer` | обязателен (у `google` — `https://accounts.google.com`) | URL `https://…` | нет | Точный issuer: посимвольно равен `issuer` в discovery и `iss` в ID token, включая завершающий `/`. Только `https://` (или `http://` на loopback для разработки), без query и fragment. |
| `CC_OIDC_CLIENT_ID` | `auth.oidc.clientId` | обязателен | строка | нет | Идентификатор клиента (приложения) сервера в IdP. |
| `CC_OIDC_CLIENT_SECRET_FILE` | `auth.oidc.existingSecret` + `clientSecretKey` (`client-secret`) | обязателен | путь к файлу | файл — да | Путь к файлу с client secret (UTF-8, завершающий перевод строки отбрасывается, до 64 KiB). **Секрет**: файл должен читать пользователь процесса (в контейнере UID 65532). |
| `CC_OIDC_TOKEN_KEY_FILE` | `auth.oidc.existingSecret` + `tokenKeyKey` (`token-key`) | обязателен | путь к файлу | файл — да | Путь к файлу с 32-байтовым ключом, которым в базе шифруются refresh token IdP (ChaCha20-Poly1305): 64 hex-символа (`openssl rand -hex 32`), base64 32 байт или 32 случайных байта. **Секрет.** При смене ключа сохранённые refresh token становятся нечитаемыми — пользователи один раз войдут заново. |
| `CC_OIDC_SCOPES` | `auth.oidc.scopes` | `openid email profile offline_access`; `adfs`: `openid email profile allatclaims`; `google`: `openid email profile` | список через пробел, с `openid` | нет | Scopes через пробел; `openid` обязателен. `offline_access` нужен для refresh token и перепроверки; Google его отвергает (пресет сам добавляет `access_type=offline` и `prompt=consent`). |
| `CC_OIDC_EMAIL_CLAIM` | `auth.oidc.emailClaim` | `email`; `entra`: `preferred_username`; `adfs`: `upn` | имя claim | нет | Claim ID token, используемый как адрес почты аккаунта (значение должно содержать `@`). |
| `CC_OIDC_REQUIRED_CLAIM` | `auth.oidc.requiredClaim` | не задан | `claim=значение` | нет | `имя=значение`: пускать только тех, у кого claim равен значению или (для массива, например `groups`, `roles`) содержит его. Иначе `403 group_required`. |
| `CC_OIDC_REQUIRE_MFA` | `auth.oidc.requireMfa` | `false` | логическое | нет | Требовать многофакторный вход: `mfa` или `http://schemas.microsoft.com/claims/multipleauthn` в `amr`, либо `acr` из `CC_OIDC_MFA_ACR_VALUES`. Иначе `403 mfa_required`. Для `google` без `acr`-значений не принимается. |
| `CC_OIDC_MFA_ACR_VALUES` | `auth.oidc.mfaAcrValues` | пусто | список | нет | Значения `acr`, которые считаются многофакторными (через запятую или пробел). |
| `CC_OIDC_TOKEN_AUTH_METHOD` | `auth.oidc.tokenAuthMethod` | `client_secret_basic` | `client_secret_basic` (`basic`), `client_secret_post` (`post`) | нет | Аутентификация сервера на token endpoint: `client_secret_basic` (`basic`) или `client_secret_post` (`post`). |
| `CC_OIDC_CA_FILE` | `auth.oidc.caKey` (ключ в том же Secret) | системные корни | путь к PEM-файлу | нет | PEM-сертификат дополнительного корневого CA для IdP за внутренним CA (например, AD FS). |

### LDAP / Active Directory

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_LDAP_URL` | `auth.ldap.url` | обязателен | `ldaps://…`, `ldap://…` | нет | `ldaps://dc1.acme.local:636` или `ldap://dc1.acme.local:389` вместе с `CC_LDAP_STARTTLS=true`. Простой `ldap://` без STARTTLS сервер отклоняет: пароль домена не должен идти открытым текстом. Имя хоста должно совпадать с сертификатом контроллера. |
| `CC_LDAP_STARTTLS` | `auth.ldap.starttls` | `false` | логическое | нет | STARTTLS для `ldap://`; с `ldaps://` недопустим. |
| `CC_LDAP_CA_FILE` | `auth.ldap.caKey` (ключ в том же Secret) | системные корни | путь к PEM-файлу | нет | PEM с корневым сертификатом CA домена (один или несколько сертификатов). |
| `CC_LDAP_BIND_DN` | `auth.ldap.bindDn` | обязателен | DN | нет | DN сервисной учётки для поиска и перепроверок, например `CN=svc-consolecrypt,OU=Service,DC=acme,DC=local`. Достаточно прав на чтение каталога. |
| `CC_LDAP_BIND_PASSWORD_FILE` | `auth.ldap.existingSecret` + `bindPasswordKey` (`bind-password`) | обязателен | путь к файлу | файл — да | Путь к файлу с паролем сервисной учётки. **Секрет.** |
| `CC_LDAP_BASE_DN` | `auth.ldap.baseDn` | обязателен | DN | нет | Где искать пользователей (`DC=acme,DC=local`). Также служит идентификатором источника для привязок: при его смене привязки нужно пересоздать. |
| `CC_LDAP_USER_FILTER` | `auth.ldap.userFilter` | `(&(objectClass=user)(\|(mail={login})(userPrincipalName={login})(sAMAccountName={login})))` | фильтр LDAP с `{login}` | нет | Фильтр поиска с `{login}`; должен начинаться с `(`. Ввод пользователя экранируется по RFC 4515, префикс `ДОМЕН\` отбрасывается. Если найдено несколько записей, вход отклоняется. |
| `CC_LDAP_EMAIL_ATTR` | `auth.ldap.emailAttr` | `mail` | имя атрибута | нет | Атрибут с адресом почты. |
| `CC_LDAP_ID_ATTR` | `auth.ldap.idAttr` | `objectGUID` | имя атрибута | нет | Стабильный идентификатор пользователя; для `objectGUID` хранится как строка GUID. Смена почты или имени не ломает привязку. |
| `CC_LDAP_REQUIRED_GROUP` | `auth.ldap.requiredGroup` | не задан | DN | нет | DN группы, членом которой (с учётом вложенных групп, правило AD `LDAP_MATCHING_RULE_IN_CHAIN`) должен быть пользователь; проверяется при входе и перепроверке. При старте сервер проверяет, что группа существует. |
| `CC_LDAP_TIMEOUT_SECS` | `auth.ldap.timeoutSecs` | `10` | секунды, 1–60 | нет | Таймаут соединения и операций, 1–60 секунд. |
| `CC_LDAP_MAX_FAILURES` | `auth.ldap.maxFailures` | `3` | 1–100 | нет | Неудачных входов на логин и на пользователя каталога за окно, 1–100; дальше сервер отвечает `429`, **не обращаясь к AD**. Держите **ниже** порога блокировки учётных записей домена. |
| `CC_LDAP_FAILURE_WINDOW_MINUTES` | `auth.ldap.failureWindowMinutes` | `15` | минуты, 1–1440 | нет | Окно счётчика неудачных входов, 1–1440 минут; не короче окна сброса счётчика блокировки в политике домена. |
| `CC_LDAP_MAX_FAILURES_PER_IP` | `auth.ldap.maxFailuresPerIp` | `30` | целое ≥ 0, `0` — без лимита | нет | Неудачных входов с одного IP за окно; `0` — без ограничения. |

## Наблюдаемость: метрики, журнал, трассировка

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_METRICS_LISTEN` | `metrics.enabled` (`true` → `0.0.0.0:9090`, `false` → `off`) | `0.0.0.0:9090` | `хост:порт`, `off`, `disabled` | нет | Отдельный listener Prometheus (`GET /metrics`). `off` или `disabled` — выключить. Метрики без аутентификации: не публикуйте порт наружу и не включайте его в Ingress. Пример Docker Compose их выключает. |
| `CC_LOG_FORMAT` | `config.log.format` | `json` | `json`, `pretty` (`text`) | нет | Формат журнала в stderr: `json` или `pretty` (`text`). Команды `admin` всегда пишут в `pretty`. |
| `CC_LOG` | `config.log.filter` | `info,sqlx=warn` | фильтр EnvFilter | нет | **Только окружение** (в JSON-файл не принимается). Фильтр журнала в синтаксисе `tracing` EnvFilter: `info`, `debug,sqlx=warn`. Без него читается `RUST_LOG`. |
| `RUST_LOG` | `extraEnv` | — | фильтр EnvFilter | нет | **Только окружение.** Запасной фильтр журнала, если `CC_LOG` не задан. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `extraEnv` | не задан | URL | нет | **Только окружение.** Включает экспорт трассировок OpenTelemetry (OTLP HTTP/protobuf), например `http://otel-collector:4318`. Действуют стандартные переменные `OTEL_*`. Спаны содержат только несекретные поля (request_id, маршрут, статус, UUID пользователя и устройства). |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | `extraEnv` | не задан | URL | нет | **Только окружение.** То же, отдельный адрес только для трассировок. |

## Обслуживание и хранение данных

Проход обслуживания удаляет устаревшие служебные записи. Он выполняется на одной
реплике за раз (advisory lock). Сроки хранения — в сутках, `0` — хранить
всегда, не больше 36500. Резервные копии сервер не делает: используйте
`pg_dump` по [HOSTING.md](HOSTING.md).

| Переменная | Helm | По умолчанию | Значения | Секрет | Что делает |
|---|---|---|---|---|---|
| `CC_MAINTENANCE_INTERVAL_SECS` | `config.maintenance.intervalSecs` | `3600` | секунды, `0` — выкл. | нет | Период прохода обслуживания; `0` — выключить. |
| `CC_RETENTION_SESSION_DAYS` | `config.maintenance.retention.sessionDays` | `7` | сутки, 0–36500, `0` — всегда | нет | Сколько хранить отозванные и истёкшие сеансы. |
| `CC_RETENTION_SYNC_MUTATION_DAYS` | `config.maintenance.retention.syncMutationDays` | `30` | сутки, 0–36500, `0` — всегда | нет | Записи идемпотентности принятых изменений синхронизации. |
| `CC_RETENTION_AUDIT_DAYS` | `config.maintenance.retention.auditDays` | `365` | сутки, 0–36500, `0` — всегда | нет | Журнал аудита (`audit_events`). |
| `CC_RETENTION_DELETED_VAULT_DAYS` | `config.maintenance.retention.deletedVaultDays` | `30` | сутки, 0–36500, `0` — всегда | нет | Через сколько дней удаляется шифротекст удалённого хранилища. |
| `CC_RETENTION_DEVICE_REQUEST_DAYS` | `config.maintenance.retention.deviceRequestDays` | `90` | сутки, 0–36500, `0` — всегда | нет | Решённые и истёкшие запросы доверия устройств. |

## Служебные переменные

| Переменная | Где | Что делает |
|---|---|---|
| `CC_CONFIG_FILE` | только окружение | Путь к приватному JSON-файлу настроек, если не передан `--config`. Файл: обычный, до 64 KiB, один JSON-объект с известными ключами и строковыми значениями, на Unix — права `0600` или `0400`. Не ищется в текущем каталоге, не исполняется, `$` и команды не подставляются. |

Переменные примера Docker Compose — их читает Compose, а не сервер:

| Переменная | Что делает |
|---|---|
| `CC_SERVER_VERSION` | Версия образа `ghcr.io/evsikovas/consolecrypt-server:<версия>`. |
| `CC_SERVER_IMAGE` | Полная ссылка на образ вместо версии, например с `@sha256:` digest. |
| `CC_DOMAIN` | Домен, на который Caddy получает сертификат. |
| `CC_HTTP_PORT` | Порт API на `127.0.0.1` хоста (по умолчанию `8080`). |
| `CC_POSTGRES_ADMIN_PASSWORD` | Пароль администратора PostgreSQL в контейнере базы (создаётся `init-config.py`). |
| `CC_POSTGRES_PASSWORD`, `CC_METRICS_PORT` | Только для `server/docker-compose.yml` разработки: пароль встроенной базы и порт метрик на хосте. |

## Команды администратора

Команды запускаются тем же бинарным файлом с той же конфигурацией
(`--config` — глобальный флаг): `docker compose … exec -T server
/usr/local/bin/consolecrypt-server admin …` или `kubectl exec deployment/… --
/usr/local/bin/consolecrypt-server admin …`. Они не дают доступа к содержимому
хранилищ.

| Команда | Что делает |
|---|---|
| `serve` | Запустить сервер (по умолчанию). |
| `migrate` | Применить миграции и выйти. |
| `healthcheck` | Проверить `/readyz` локального listener; код 0 — готов. |
| `admin list-users` | Аккаунты: статус, способ входа (`password`, `oidc`, `ldap`), подтверждение адреса, число устройств и хранилищ. |
| `admin verify-email --email …` | Отметить адрес подтверждённым (сервер без почты). |
| `admin reset-token --email …` | Напечатать одноразовый код сброса пароля аккаунта (срок — `CC_PASSWORD_RESET_TTL_SECS`). |
| `admin set-password --email … --password-stdin` | Задать пароль из первой строки stdin; все сеансы завершаются. |
| `admin disable-user --email …` / `admin enable-user --email …` | Отключить аккаунт с отзывом сеансов / включить снова. |
| `admin session revoke --email …` | Завершить все сеансы аккаунта. |
| `admin rotate-epoch --all` / `--vault <id>` | После восстановления базы из копии: сменить эпохи хранилищ, чтобы клиенты заметили откат. |
| `admin limits show [--email …]` | Действующие лимиты и квоты (сервера или аккаунта). |
| `admin limits set --email … ключ=значение…` | Переопределить лимиты и квоты аккаунта; действует не позже чем через 30 секунд. |
| `admin limits reset --email … [ключ…]` | Убрать переопределения (все без ключей). |
| `admin auth status` | Режим входа, провайдер, последняя проверка IdP/каталога, привязанные аккаунты. |
| `admin auth test [--login … [--password-stdin]]` | Повторить проверки запуска; с `--login` — найти пользователя LDAP (с `--password-stdin` — настоящий bind) или перепроверить аккаунт OIDC в IdP. |
| `admin identity link --email … --subject … [--issuer …]` | Привязать аккаунт к OIDC `sub` или `objectGUID`; пароль аккаунта удаляется, сеансы завершаются. |
| `admin identity unlink --email … [--subject …]` | Снять привязки аккаунта (или одну). |

---

## English

The complete parameter reference of the sync server **0.2.3** (protocol
**1.11**): what every key does, which values it accepts, its default, its Helm
path and whether the value is a secret. It is derived from the configuration loader
(`server/src/config.rs`, `server/src/config/*.rs`, `server/src/telemetry.rs`)
and the Helm chart templates. `server/scripts/test_configuration_docs.py` fails
when the server accepts a key that is missing here, or this page lists a key the
server does not know.

How to set parameters with Docker Compose, `docker run`, Helm, a JSON file or
systemd, with worked examples: [HOSTING.md](HOSTING.md#english). Step-by-step
IdP and Active Directory setup: [ENTERPRISE.md](ENTERPRISE.md#english).

## How the server reads its settings

**Sources and precedence.** The server reads `CC_*` environment variables and,
optionally, a private JSON file:

1. the process environment (including an **explicitly empty** variable);
2. the JSON file given by `--config <path>`, or, without the flag, by
   `CC_CONFIG_FILE`;
3. the built-in default.

An empty value means "not set": with `CC_X=` (empty) in the environment the
server uses the default **and does not look at the JSON file** for that key. Only
the known keys of this reference are read from the environment; a variable with
a typo in its name is silently ignored. In the JSON file, by contrast, an unknown
or duplicated key stops the start.

**Value formats.**

| Type | How to write it |
|---|---|
| boolean | `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` (lower case) |
| integer | plain decimal without units or separators: `1073741824`, not `1GiB` |
| duration | an integer in the unit named by the key: `_SECS` seconds, `_MINUTES` minutes, `_HOURS` hours, `_DAYS` days |
| address | `host:port`, e.g. `0.0.0.0:8080` or `[::]:8080` |
| list | comma and/or space separated (`CC_AUTH_ALLOWED_DOMAINS`, `CC_OIDC_MFA_ACR_VALUES`); `CC_OIDC_SCOPES` is space separated |
| file path | an absolute path inside the container or on the service host |

In the JSON file every value is a string, numbers and booleans included:
`{"CC_MAX_VAULT_OBJECTS": "200000", "CC_HSTS": "true"}`.

**Validation at start-up.** An invalid value stops the server with
`invalid configuration: <KEY>: …`; the value itself is never printed. Ranges
(listed in the tables) and cross-key rules are checked:

- every sharing flag requires `CC_OBJECT_SHARING_ENABLED=true` and
  `CC_REQUIRE_REQUEST_PROOF=true`;
- `CC_REFRESH_TOKEN_TTL_SECS` must be at least `CC_ACCESS_TOKEN_TTL_SECS`;
- `CC_AUTH_MODE=enterprise` requires `CC_AUTH_PROVIDER` and the provider's keys;
  OIDC also requires an `https://` `CC_PUBLIC_URL`.

Enterprise mode also checks the network at start-up: the IdP's discovery and
JWKS, or the directory connection, TLS and bind (see
[ENTERPRISE.md](ENTERPRISE.md#english)). At start-up the server logs a `starting`
line with the effective configuration, passwords and the database URL redacted —
a quick way to confirm a key reached the process.

**When changes apply.** Only when the process restarts; neither the file nor
the environment is re-read at run time. The exception is per-account limit
overrides (`admin limits set`), which apply within 30 seconds without a restart.

**Secrets.** Secret values are `CC_DATABASE_URL` (when it contains a password),
`CC_DATABASE_PASSWORD`, `CC_SMTP_PASSWORD` and the enterprise sign-in files. The
server never logs them. There is no generic `*_FILE` mechanism: the server does
not know `CC_DATABASE_PASSWORD_FILE` or `CC_SMTP_PASSWORD_FILE`. Only five keys,
which are paths themselves, point at files: `CC_OIDC_CLIENT_SECRET_FILE`,
`CC_OIDC_TOKEN_KEY_FILE`, `CC_LDAP_BIND_PASSWORD_FILE`, `CC_OIDC_CA_FILE`,
`CC_LDAP_CA_FILE`. Pass the database and SMTP passwords through the environment
(a Kubernetes `secretKeyRef`, the private `server.env`) or a private JSON file
with mode `0600`.

**Which commands read the configuration.** `serve` (the default), `migrate` and
`admin …` load and validate the whole configuration, so `admin` needs the same
keys as the server (inside the container they are already there). `healthcheck`
reads only `CC_LISTEN_ADDR` and probes `http://127.0.0.1:<port>/readyz`.

## Network, public URL, TLS and proxy

The server does not terminate TLS and has no certificate settings: a reverse
proxy or Ingress in front provides HTTPS. The proxy must forward the
`/v1/events/ws` WebSocket, accept request bodies up to 16 MiB and leave the path,
query and body untouched: they are covered by the device signature.

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_LISTEN_ADDR` | — (the chart always uses `0.0.0.0:8080`) | `0.0.0.0:8080` | `host:port` | no | Address and port of the HTTP/WebSocket API. On a host without containers, with the proxy on the same machine, use `127.0.0.1:8080` so the API is not reachable directly. `healthcheck` uses its port. |
| `CC_PUBLIC_URL` | `config.publicUrl` | not set | `https://…` URL | no | Public base URL of the instance (`https://sync.example.org`, without `/v1`). Mail buttons (`/account#action=verify`, `reset`, `deny-device`) and the OIDC redirect URI `CC_PUBLIC_URL/v1/auth/oidc/callback` are built from it. Without it mails carry only a code and never mention a web page. Must be an absolute `http(s)://` URL without `?` or `#` (otherwise the server does not start). Required for OIDC and must start with `https://` (`http://` only on `127.0.0.1`/`localhost` for development). The `/account` page at this origin is served by your website or by the server itself (`CC_WEB_ACCOUNT=true`); without one, mail links answer 404 — the codes in the mails still work in the app. |
| `CC_WEB_ACCOUNT` | `config.webAccount` | `false` | boolean | no | Built-in account page on the server itself: `GET /account` (+ `app.js`, `app.css`). Confirm email, set a new password with the mailed code, "This wasn't me" for new-device mails — only through the public code-based endpoints, without sign-in, cookies or vault access; strict same-origin CSP. For a self-hosted server without a website: turn it on and set `CC_PUBLIC_URL` to the server's URL; the reverse proxy must pass `/account` and `/account/*`. Off: the server stays API-only. |
| `CC_TRUST_PROXY_HEADERS` | `config.trustProxyHeaders` (`auto` = `ingress.enabled`, `"true"`, `"false"`) | `false` | boolean | no | Take the client address from the **last** `X-Forwarded-For` entry (the one your proxy added). Enable only with exactly one trusted proxy that sets or appends the header and with direct access to the API port closed — otherwise clients can spoof their address. Without it every per-IP limit sees only the proxy's address. |
| `CC_HSTS` | `config.hsts` | `true` | boolean | no | Send `Strict-Transport-Security: max-age=63072000; includeSubDomains`. Turn it off only if the proxy sets HSTS itself or subdomains must stay reachable over HTTP. |
| `CC_SOURCE_CODE_URL` | `config.sourceCodeUrl` | the build's source URL (the image sets it) | URL | no | Source link that `/v1/meta` returns as `source_code_url` (AGPL-3.0 §13). Leave it unset for the official image. If you run a **modified** server, point it at your modified source. |

## Database and connection pool

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_DATABASE_URL` | `database.url`, `database.existingSecret` + `database.existingSecretKey`, or the bundled `postgresql.*` | **required** | `postgres://…` URL | yes, with a password | PostgreSQL 16 URL: `postgres://user@host:5432/db?sslmode=verify-full`. For an external database use `sslmode=verify-full` and, with a private CA, `sslrootcert=<path in the container>`. A password inside the URL must be percent-encoded; passing it separately in `CC_DATABASE_PASSWORD` is simpler. **Secret** when it contains a password. In Helm `database.url` is stored in the chart's Secret, `existingSecret` in yours. |
| `CC_DATABASE_PASSWORD` | only with the bundled database (`postgresql.auth.password` / `existingSecret`); for an external one use `extraEnv` with a `secretKeyRef` | not set | string | yes | Password applied on top of the URL; no escaping needed. **Secret.** When neither this nor the URL has a password, the driver uses the standard `PGPASSWORD` variable. |
| `DATABASE_URL` | — | not set | `postgres://…` URL | yes, with a password | Legacy name of `CC_DATABASE_URL`, **environment only**. Used when `CC_DATABASE_URL` is not in the process environment; it then wins over `CC_DATABASE_URL` from the JSON file. **Secret** when it contains a password. |
| `CC_DATABASE_MAX_CONNECTIONS` | `database.maxConnections` | `20` | integer ≥ 1 | no | Pool size per process (pod), at least 1. Each process holds one more connection for `LISTEN/NOTIFY`. Keep `replicas × (value + 1)` below PostgreSQL's `max_connections`. Waiting for a free connection times out after 5 seconds. |
| `CC_DATABASE_CONNECT_TIMEOUT_SECS` | `database.connectTimeoutSecs` | `60` | seconds, integer | no | How many seconds start-up keeps retrying an unreachable database (back-off from 0.25 to 5 seconds) before exiting with an error. Applies to `serve`, `migrate` and `admin`. |
| `CC_RUN_MIGRATIONS` | `migrations.runAtStartup` | `true` | boolean | no | Apply the built-in migrations at start-up (under an advisory lock — safe with several replicas). Use `false` only when migrations run separately (`consolecrypt-server migrate`, Helm `migrations.job.enabled`) or for a rollback you have verified. Rolling the image back does not undo migrations. |
| `CC_EVENT_BUS` | `config.eventBus` | `postgres` | `postgres`, `local` | no | How real-time events reach WebSocket clients: `postgres` (`LISTEN/NOTIFY`, any number of replicas) or `local` (in-process, one replica only; the chart refuses `local` with `replicaCount > 1` or autoscaling). |

## Mail (SMTP)

Mail carries address verification and password reset codes, device protection
mails, failed sign-in warnings and team invitations.

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_MAIL_TRANSPORT` | `mail.transport` | `disabled` | `disabled` (`none`), `smtp`, `file` | no | `disabled` (or `none`): nothing is sent, the operator uses `admin verify-email` and `admin reset-token`; `smtp`: send through SMTP; `file`: development only, each message is written as a file into `CC_MAIL_DIR`. |
| `CC_MAIL_DIR` | `mail.file.dir` (an emptyDir in the pod) | `./.dev-mail` | directory path | no | Directory for `file`; relative to the process working directory. Files are created with mode `0600`. |
| `CC_MAIL_FROM` | `mail.from` | `ConsoleCrypt <no-reply@localhost>` | address `Name <a@example.org>` | no | Sender. Your SMTP server and the sender's DNS records must allow it. |
| `CC_MAIL_LANGUAGE` | `mail.language` | `ru` | `ru`, `en` | no | Language of mail and of the built-in account page. Mail is HTML with a plain-text alternative (UTF-8); the code is always shown for pasting into the app, its validity comes from the TTL settings. |
| `CC_SMTP_HOST` | `mail.smtp.host` | — | host name | no | SMTP host name; required with `smtp`. |
| `CC_SMTP_PORT` | `mail.smtp.port` | `587` | 1–65535 | no | SMTP port (1–65535). |
| `CC_SMTP_TLS` | `mail.smtp.tls` | `starttls` | `starttls`, `tls`, `none` | no | `starttls` (usually 587), `tls` — implicit TLS (usually 465), `none` — unencrypted, only for a local relay or a test mail catcher. |
| `CC_SMTP_USERNAME` | `mail.smtp.username` | not set | string | no | SMTP login. Empty: no authentication (an IP-authorised relay). |
| `CC_SMTP_PASSWORD` | `mail.smtp.password` (chart Secret) or `mail.smtp.existingSecret` + `existingSecretPasswordKey` | not set | string | yes | SMTP password. **Secret**: use `existingSecret` in Helm. |

## Registration, address verification, tokens and account passwords

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_REGISTRATION_OPEN` | `config.registrationOpen` | `true` | boolean | no | Allow new account registration. `false`: registration answers 403 and `/v1/meta` reports `registration_open: false`; existing accounts keep working. Ignored in enterprise mode, where the first IdP/directory sign-in creates accounts (`CC_AUTH_AUTO_CREATE`). |
| `CC_REQUIRE_EMAIL_VERIFICATION` | `config.requireEmailVerification` | `false` | boolean | no | Require a verified address: without it, sign-in and creating a vault, team or shared item answer `email_not_verified`. Needs mail or `admin verify-email`. The Docker Compose example turns it on. |
| `CC_EMAIL_VERIFY_TTL_SECS` | `config.tokens.emailVerifyTtlSecs` | `172800` (48 h) | seconds, integer | no | Lifetime of an address verification code. |
| `CC_PASSWORD_RESET_TTL_SECS` | `config.tokens.passwordResetTtlSecs` | `3600` (1 h) | seconds, integer | no | Lifetime of an account password reset code (from a mail or `admin reset-token`). |
| `CC_ACCESS_TOKEN_TTL_SECS` | `config.tokens.accessTtlSecs` | `900` (15 min) | seconds, 60–86400 | no | Access token lifetime, 60–86400. Shorter means revocation bites sooner but refreshes are more frequent. |
| `CC_REFRESH_TOKEN_TTL_SECS` | `config.tokens.refreshTtlSecs` | `2592000` (30 days) | seconds, ≥ `CC_ACCESS_TOKEN_TTL_SECS` | no | Refresh token lifetime (a device session without a refresh); at least the access token lifetime. After it the device signs in again. |
| `CC_ARGON2_MEMORY_KIB` | `config.argon2.memoryKib` | `19456` (19 MiB) | KiB, integer | no | Argon2id memory for **account password** hashes (the server never gets vault keys). New parameters apply to new hashes; existing hashes are verified with their own parameters until the password changes. |
| `CC_ARGON2_ITERATIONS` | `config.argon2.iterations` | `2` | integer ≥ 1 | no | Argon2id passes. |
| `CC_ARGON2_PARALLELISM` | `config.argon2.parallelism` | `1` | integer ≥ 1 | no | Argon2id parallelism. |
| `CC_ARGON2_MAX_CONCURRENT` | `config.argon2.maxConcurrent` (`4`) | number of CPUs, at most 4 | integer ≥ 1 | no | Hashes computed at the same time (a CPU and memory guard against sign-in floods), at least 1. Peak memory ≈ `CC_ARGON2_MEMORY_KIB × CC_ARGON2_MAX_CONCURRENT` — keep it well below the container's memory limit. |

## Devices and new-device protection

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_REQUIRE_REQUEST_PROOF` | `config.requireRequestProof` | `true` | boolean | no | Require every request to be signed with the device key (protocol 1.5): a stolen token is useless without the key. `false` is a temporary exception for old clients: invalid proofs are still refused, missing ones are only counted (`cc_request_proofs_total{result="missing"}`). Sharing requires `true`. |
| `CC_DEVICE_REQUEST_TTL_SECS` | `config.tokens.deviceRequestTtlSecs` | `86400` (24 h) | seconds, integer | no | How long a new device's trust request waits for approval on a trusted device. |
| `CC_DEVICE_PROTECTION_ENABLED` | `config.deviceProtection.enabled` | `false` | boolean | no | Protection against sign-ins from new devices: quarantine, limits on unlock material for untrusted devices, "new device" mails, the `device_registered` event, revoking unused devices on password reset. "This wasn't me" links point to `CC_PUBLIC_URL/account`. Details: [HOSTING.md](HOSTING.md#защита-от-входа-с-нового-устройства). |
| `CC_NEW_DEVICE_MAIL_ENABLED` | `config.deviceProtection.newDeviceMail` | `true` | boolean | no | "New device" mails (with protection on and mail configured). |
| `CC_DEVICE_QUARANTINE_DAYS` | `config.deviceProtection.quarantineDays` | `14` | days, 0–365 | no | Quarantine of a new device in days, 0–365: meanwhile it cannot revoke trusted devices, and a password change or "sign out everywhere" from it does not end trusted devices' sessions. `0`: no quarantine. |
| `CC_ENVELOPE_LIMIT_ACCOUNT_PER_HOUR` | `config.deviceProtection.envelopesPerAccountPerHour` | `5` | integer ≥ 0, `0` = no limit | no | How often per hour the account's untrusted devices may receive vault unlock material (`0` = no limit). Counters are shared by all replicas. |
| `CC_ENVELOPE_LIMIT_ACCOUNT_PER_DAY` | `config.deviceProtection.envelopesPerAccountPerDay` | `20` | integer ≥ 0, `0` = no limit | no | The same per day. |
| `CC_ENVELOPE_LIMIT_DEVICE_PER_HOUR` | `config.deviceProtection.envelopesPerDevicePerHour` | `3` | integer ≥ 0, `0` = no limit | no | The same for one untrusted device per hour. |
| `CC_NEW_DEVICE_MAIL_PER_HOUR` | `config.deviceProtection.newDeviceMailsPerHour` | `10` | integer ≥ 0 | no | "New device" mails per account per hour; later sign-ins of that hour are folded into one mail. |

## Sync, WebSocket and quotas

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_SYNC_PAGE_BYTES` | `config.sync.pageBytes` | `8388608` (8 MiB) | bytes, ≥ 65536 | no | Byte budget of one `changes`/`snapshot` page and of sharing lists, at least 65536. |
| `CC_QUOTAS_V2_ENABLED` | `config.quotas.v2Enabled` | `true` | boolean | no | Server 0.2.2 quotas: tombstone and object accounting, device limits, deleting an unknown object without a tombstone. `false` restores the 0.2.1 behaviour (counters are still maintained). |
| `CC_MAX_VAULT_BYTES` | `config.quotas.maxVaultBytes` | `1073741824` (1 GiB) | bytes, ≥ 1048576 | no | Ciphertext plus tombstones per vault, at least 1 MiB. Beyond: `413`, `details.reason = "vault_quota"`. |
| `CC_TOMBSTONE_COST_BYTES` | `config.quotas.tombstoneCostBytes` | `256` | bytes, 0–1048576 | no | Quota bytes each tombstone (deleted object) costs, 0–1048576. |
| `CC_MAX_VAULT_OBJECTS` | `config.quotas.maxVaultObjects` | `100000` | integer ≥ 1 | no | Live objects plus tombstones per vault, at least 1. Beyond: `413`, `object_limit`. |
| `CC_MAX_VAULTS_PER_ACCOUNT` | `config.quotas.maxVaultsPerAccount` | `50` | integer ≥ 1 | no | Vaults an account may own, at least 1. Beyond: `403`, `vault_limit`. |
| `CC_MAX_DEVICES_PER_ACCOUNT` | `config.quotas.maxDevicesPerAccount` | `20` | 1–64 | no | Non-revoked devices per account, 1–64 (64 is the recipient limit of a shared item). One more: `403`, `device_limit`. |
| `CC_NEW_DEVICES_PER_ACCOUNT_PER_DAY` | `config.quotas.newDevicesPerAccountPerDay` | `10` | integer ≥ 0, `0` = no limit | no | New devices per account in any 24 hours, `0` = no limit. Beyond: `403`, `device_daily_limit` with `details.until`. |
| `CC_WS_PING_INTERVAL_SECS` | `config.websocket.pingIntervalSecs` | `30` | seconds, ≥ 1 | no | WebSocket ping interval, at least 1. Lower it if your proxy closes idle connections sooner. |
| `CC_WS_SESSION_RECHECK_SECS` | `config.websocket.sessionRecheckSecs` | `30` | seconds, 1–30 | no | How often an open WebSocket checks that its session is not revoked, 1–30: revocation reaches sockets within 30 seconds. |
| `CC_WS_MAX_CONNECTIONS_PER_USER` | `config.websocket.maxConnectionsPerUser` | `32` | integer ≥ 1 | no | Concurrent WebSocket connections per account per replica, at least 1; more answer `429`. |

Quotas of a single account change without a restart: `admin limits set --email …
max_vault_bytes=… max_vault_objects=… max_devices_per_account=…
new_devices_per_account_per_day=…`. `CC_MAX_VAULTS_PER_ACCOUNT` cannot be
overridden this way.

## Sharing and teams

Every sharing flag is off by default and requires `CC_OBJECT_SHARING_ENABLED=true`
and `CC_REQUIRE_REQUEST_PROOF=true` (otherwise the server does not start). Turning
a flag off hides objects of that kind without deleting their ciphertext. Clients
learn the capabilities from the authenticated `/v1/shares/capabilities`. Details:
[SHARING.md](SHARING.md#english).

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_OBJECT_SHARING_ENABLED` | `config.objectSharingEnabled` | `false` | boolean | no | The main sharing mechanism for hosts. |
| `CC_SHARED_GROUPS_ENABLED` | `config.sharedGroupsEnabled` | `false` | boolean | no | Shared groups (collections). |
| `CC_SHARED_SECRETS_ENABLED` | `config.sharedSecretsEnabled` | `false` | boolean | no | Individual shared secrets. |
| `CC_SHARED_KUBE_CONTEXTS_ENABLED` | `config.sharedKubeContextsEnabled` | `false` | boolean | no | Shared Kubernetes connections (`supports_kube_contexts`). |
| `CC_SHARED_DB_CONNECTIONS_ENABLED` | `config.sharedDbConnectionsEnabled` | `false` | boolean | no | Shared database connections (`supports_db_connections`). |
| `CC_SHARED_NOTES_ENABLED` | `config.sharedNotesEnabled` | `false` | boolean | no | Shared notes on shared objects (`supports_notes_v1`): up to 500 notes per object, up to 288 KiB of ciphertext per note. |
| `CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED` | `config.sharingOwnerOnlineEnrollmentEnabled` | `false` | boolean | no | Adding a recipient's new personal devices with the owner online. |
| `CC_TEAMS_ENABLED` | `extraEnv` | `true` | boolean | no | Teams (shared vaults, `/v1/teams/*`, `capabilities.teams` in `/v1/meta`). Independent of the sharing flags. With `false` the team routes answer 404; data is kept. |
| `CC_MAX_TEAMS_PER_ACCOUNT` | `extraEnv` | `50` | integer ≥ 1 | no | Teams an account may belong to, at least 1. |
| `CC_MAX_TEAM_MEMBERS` | `extraEnv` | `200` | integer ≥ 2 | no | Members of one team, at least 2. |

## Request limits

Limits protect the server from any single account, device or address. Most
limits live in PostgreSQL (token buckets on database time) and act the same on
every replica; three first-stage limits live in each replica's memory. A refusal
is `429 rate_limited` with `Retry-After` and `details.limit`.

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_RATE_LIMIT_ENABLED` | `config.rateLimit.enabled` | `true` | boolean | no | `false` turns off **every** request limit (quotas stay). Debugging only. |
| `CC_RATE_LIMIT_MODE` | `config.rateLimit.mode` | `observe` | `observe`, `enforce` | no | `observe`: excess on the PostgreSQL limits and the read limit is only counted (`cc_rate_limit_observed_total{limiter}`, audit event `limit_exceeded` at most hourly per account and limit); `enforce`: it is refused. Sign-in and recovery limits (marked below) and the first stages `CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE` and `CC_RATE_LIMIT_PROOF_PER_DEVICE_PER_MINUTE` act in both modes. Procedure: watch the metric for a week, raise thresholds if needed, then `enforce`. |
| `CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE` | `config.rateLimit.authPerIpPerMinute` | `30` | integer, per minute | no | First stage in replica memory: public sign-in, registration and recovery requests per IP (IPv6 per /64) per minute. While `CC_LIMIT_AUTH_IP_RATE` is unset, the same value sets the shared `auth_ip` limit. |
| `CC_RATE_LIMIT_PROOF_PER_DEVICE_PER_MINUTE` | `config.rateLimit.proofPerDevicePerMinute` | `20` | integer, per minute | no | In replica memory: key proof attempts (attest/approve) per device per minute. |
| `CC_RATE_LIMIT_READ_PER_DEVICE_PER_MINUTE` | `config.rateLimit.readPerDevicePerMinute` | `1200` | integer, per minute; `0` = off | no | In replica memory: authenticated reads (GET) per device per minute; `0` = off. Follows `CC_RATE_LIMIT_MODE`. |
| `CC_RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE` | `config.rateLimit.loginPerEmailPerMinute` | not set (`10`) | integer, per minute | no | Pre-0.2.2 name: the per-minute rate (and capacity) of `login_email`. Ignored when `CC_LIMIT_LOGIN_EMAIL_RATE` is set. |
| `CC_RATE_LIMIT_RECOVERY_PER_EMAIL_PER_HOUR` | `config.rateLimit.recoveryPerEmailPerHour` | not set (`5`) | integer, per hour | no | Pre-0.2.2 name: the hourly rate of `recovery_email`. Ignored when `CC_LIMIT_RECOVERY_EMAIL_RATE` is set. |

### PostgreSQL limits: `CC_LIMIT_<NAME>_*`

Each limit has four keys (`<NAME>` is the limit name in upper case):

- `CC_LIMIT_<NAME>_RATE` — rate of the main bucket: `N` per the limit's natural
  period (see the table) or `N/s`, `N/sec`, `N/min` (`N/m`), `N/hour` (`N/h`),
  `N/day` (`N/d`); a fractional `N` is allowed; `0` = no main bucket. Setting only
  the rate makes the capacity one period of that rate.
- `CC_LIMIT_<NAME>_BURST` — bucket capacity (requests in a row), an integer of at
  least 1. Default: one period of the rate unless the table lists a burst.
- `CC_LIMIT_<NAME>_PER_HOUR`, `CC_LIMIT_<NAME>_PER_DAY` — extra hourly and daily
  ceilings, integers; `0` = no ceiling.

A limit with no rate and no ceilings limits nothing. In Helm all four keys come
from `config.rateLimit.limits`, e.g.
`{push_account: {rate: "600/min", burst: 600, perHour: 0, perDay: 0}}` (fields
`rate`, `burst`, `perHour`, `perDay`). For one account:
`admin limits set --email … push_account_rate=600/min` (suffixes `_rate`,
`_burst`, `_per_hour`, `_per_day`); sign-in limits cannot be overridden this way.

| Name | What it limits | Default | Keys |
|---|---|---|---|
| `push_device` | pushes from one device | 120/min, burst 60 | `CC_LIMIT_PUSH_DEVICE_RATE`, `CC_LIMIT_PUSH_DEVICE_BURST`, `CC_LIMIT_PUSH_DEVICE_PER_HOUR`, `CC_LIMIT_PUSH_DEVICE_PER_DAY` |
| `push_account` | pushes from all devices of an account | 300/min | `CC_LIMIT_PUSH_ACCOUNT_RATE`, `CC_LIMIT_PUSH_ACCOUNT_BURST`, `CC_LIMIT_PUSH_ACCOUNT_PER_HOUR`, `CC_LIMIT_PUSH_ACCOUNT_PER_DAY` |
| `mutations_account` | changes inside an account's pushes | 50,000/hour | `CC_LIMIT_MUTATIONS_ACCOUNT_RATE`, `CC_LIMIT_MUTATIONS_ACCOUNT_BURST`, `CC_LIMIT_MUTATIONS_ACCOUNT_PER_HOUR`, `CC_LIMIT_MUTATIONS_ACCOUNT_PER_DAY` |
| `unknown_delete_account` | deletes of objects the server never had | 1000/day | `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_RATE`, `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_BURST`, `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_PER_HOUR`, `CC_LIMIT_UNKNOWN_DELETE_ACCOUNT_PER_DAY` |
| `share_write_account` | creating shared objects | 60/hour, burst 20 | `CC_LIMIT_SHARE_WRITE_ACCOUNT_RATE`, `CC_LIMIT_SHARE_WRITE_ACCOUNT_BURST`, `CC_LIMIT_SHARE_WRITE_ACCOUNT_PER_HOUR`, `CC_LIMIT_SHARE_WRITE_ACCOUNT_PER_DAY` |
| `share_revision_account` | shared object revisions, access changes, shared notes | 600/hour | `CC_LIMIT_SHARE_REVISION_ACCOUNT_RATE`, `CC_LIMIT_SHARE_REVISION_ACCOUNT_BURST`, `CC_LIMIT_SHARE_REVISION_ACCOUNT_PER_HOUR`, `CC_LIMIT_SHARE_REVISION_ACCOUNT_PER_DAY` |
| `recipient_lookup_account` | recipient lookups by e-mail address | 30/min and 300/day | `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_RATE`, `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_BURST`, `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_PER_HOUR`, `CC_LIMIT_RECIPIENT_LOOKUP_ACCOUNT_PER_DAY` |
| `enrollment_account` | adding a recipient's own devices | 30/hour | `CC_LIMIT_ENROLLMENT_ACCOUNT_RATE`, `CC_LIMIT_ENROLLMENT_ACCOUNT_BURST`, `CC_LIMIT_ENROLLMENT_ACCOUNT_PER_HOUR`, `CC_LIMIT_ENROLLMENT_ACCOUNT_PER_DAY` |
| `trust_request_device` | trust requests from one device | 10/hour | `CC_LIMIT_TRUST_REQUEST_DEVICE_RATE`, `CC_LIMIT_TRUST_REQUEST_DEVICE_BURST`, `CC_LIMIT_TRUST_REQUEST_DEVICE_PER_HOUR`, `CC_LIMIT_TRUST_REQUEST_DEVICE_PER_DAY` |
| `trust_request_account` | trust requests from all devices of an account | 30/day | `CC_LIMIT_TRUST_REQUEST_ACCOUNT_RATE`, `CC_LIMIT_TRUST_REQUEST_ACCOUNT_BURST`, `CC_LIMIT_TRUST_REQUEST_ACCOUNT_PER_HOUR`, `CC_LIMIT_TRUST_REQUEST_ACCOUNT_PER_DAY` |
| `verification_account` | key verification: approving-device announcements, signed vault key fingerprints | 20/hour | `CC_LIMIT_VERIFICATION_ACCOUNT_RATE`, `CC_LIMIT_VERIFICATION_ACCOUNT_BURST`, `CC_LIMIT_VERIFICATION_ACCOUNT_PER_HOUR`, `CC_LIMIT_VERIFICATION_ACCOUNT_PER_DAY` |
| `account_security` | password change, recovery kit reissue, envelope replacement | 10/hour | `CC_LIMIT_ACCOUNT_SECURITY_RATE`, `CC_LIMIT_ACCOUNT_SECURITY_BURST`, `CC_LIMIT_ACCOUNT_SECURITY_PER_HOUR`, `CC_LIMIT_ACCOUNT_SECURITY_PER_DAY` |
| `ws_connect_account` | new WebSocket connections of an account | 60/min | `CC_LIMIT_WS_CONNECT_ACCOUNT_RATE`, `CC_LIMIT_WS_CONNECT_ACCOUNT_BURST`, `CC_LIMIT_WS_CONNECT_ACCOUNT_PER_HOUR`, `CC_LIMIT_WS_CONNECT_ACCOUNT_PER_DAY` |
| `auth_ip` (always enforced) | public sign-in, registration and recovery requests from one address, shared by replicas | 30/min | `CC_LIMIT_AUTH_IP_RATE`, `CC_LIMIT_AUTH_IP_BURST`, `CC_LIMIT_AUTH_IP_PER_HOUR`, `CC_LIMIT_AUTH_IP_PER_DAY` |
| `login_email` (always enforced) | **failed** sign-ins to one e-mail address from one network (/24 IPv4, /64 IPv6) | 10/min and 50/hour | `CC_LIMIT_LOGIN_EMAIL_RATE`, `CC_LIMIT_LOGIN_EMAIL_BURST`, `CC_LIMIT_LOGIN_EMAIL_PER_HOUR`, `CC_LIMIT_LOGIN_EMAIL_PER_DAY` |
| `login_email_total` (always enforced) | failed sign-ins to an address from all networks | 200/hour | `CC_LIMIT_LOGIN_EMAIL_TOTAL_RATE`, `CC_LIMIT_LOGIN_EMAIL_TOTAL_BURST`, `CC_LIMIT_LOGIN_EMAIL_TOTAL_PER_HOUR`, `CC_LIMIT_LOGIN_EMAIL_TOTAL_PER_DAY` |
| `recovery_email` (always enforced) | password reset requests to an address from one network | 5/hour | `CC_LIMIT_RECOVERY_EMAIL_RATE`, `CC_LIMIT_RECOVERY_EMAIL_BURST`, `CC_LIMIT_RECOVERY_EMAIL_PER_HOUR`, `CC_LIMIT_RECOVERY_EMAIL_PER_DAY` |
| `recovery_email_total` (always enforced) | reset mails to an address from all networks (the answer is always `202`) | 20/day | `CC_LIMIT_RECOVERY_EMAIL_TOTAL_RATE`, `CC_LIMIT_RECOVERY_EMAIL_TOTAL_BURST`, `CC_LIMIT_RECOVERY_EMAIL_TOTAL_PER_HOUR`, `CC_LIMIT_RECOVERY_EMAIL_TOTAL_PER_DAY` |

Other people's attempts do not lock the owner out: a successful sign-in spends no
e-mail limit, and a sign-in from one of the account's known devices is limited
only by address. Effective values: `consolecrypt-server admin limits show` (with
`--email` for an account).

## Enterprise sign-in: `CC_AUTH_*`, `CC_OIDC_*`, `CC_LDAP_*`

In `standard` mode the provider keys are neither read nor validated, so switching
back and forth is a change of `CC_AUTH_MODE` alone. Setup order, IdP and
directory recipes, commands and troubleshooting: [ENTERPRISE.md](ENTERPRISE.md#english).
In Helm this is the `auth:` block; secrets come from an existing Secret that the
chart mounts read-only at `/run/secrets/consolecrypt-auth`, and the chart fills in
the `*_FILE` paths itself.

### Common keys

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_AUTH_MODE` | `auth.mode` | `standard` | `standard`, `enterprise` | no | `standard`: e-mail and account password; `enterprise`: sign-in only through the IdP (OIDC) or the directory (LDAP); registration and account passwords are off. |
| `CC_AUTH_PROVIDER` | `auth.provider` | — | `oidc`, `ldap` | no | `oidc` or `ldap`; required in enterprise mode. |
| `CC_AUTH_DISPLAY_NAME` | `auth.displayName` | not set | up to 64 printable characters | no | Label of the app's sign-in button ("Sign in with …"), up to 64 printable characters. |
| `CC_AUTH_ALLOWED_DOMAINS` | `auth.allowedDomains` (a list) | empty — any | list of domains | no | Allowed e-mail domains (`acme.com, acme.ru`; a leading `@` is dropped, case-insensitive, subdomains are not included). Required for automatically linking existing password accounts; mandatory for the `google` preset. |
| `CC_AUTH_AUTO_CREATE` | `auth.autoCreate` | `true` | boolean | no | Create an account at a new identity's first sign-in. `false`: only existing or linked accounts sign in; everyone else gets `403` (`not_provisioned`). |
| `CC_AUTH_RECHECK_MINUTES` | `auth.recheckMinutes` | `15` | minutes, 1–1440 | no | How often (1–1440 min) to re-check the user at the IdP/directory. A disabled employee loses sync within this time + 1 minute. |
| `CC_AUTH_RECHECK_GRACE_HOURS` | `auth.recheckGraceHours` | `24` | hours, 0–720 | no | How many hours (0–720) sessions survive while the IdP/directory is unreachable; then refresh answers `503 idp_unavailable`. |

### OIDC

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_OIDC_PRESET` | `auth.oidc.preset` | `generic` | `generic`, `entra`, `adfs`, `keycloak`, `google`, `okta` | no | `generic`, `entra`, `adfs`, `keycloak`, `google`, `okta`: defaults and start-up checks (Entra: tenant-id issuer, no `/common`, `/organizations`, `/consumers`; AD FS: ends with `/adfs`; Keycloak: contains `/realms/`; Google: fixed issuer, mandatory domain list, `hd` check). |
| `CC_OIDC_ISSUER` | `auth.oidc.issuer` | required (`google`: `https://accounts.google.com`) | `https://…` URL | no | Exact issuer: character for character equal to `issuer` in discovery and `iss` in the ID token, trailing `/` included. `https://` only (`http://` on loopback for development), no query or fragment. |
| `CC_OIDC_CLIENT_ID` | `auth.oidc.clientId` | required | string | no | The server's client (application) id at the IdP. |
| `CC_OIDC_CLIENT_SECRET_FILE` | `auth.oidc.existingSecret` + `clientSecretKey` (`client-secret`) | required | file path | the file: yes | Path of the file with the client secret (UTF-8, trailing newline dropped, up to 64 KiB). **Secret**: the process user must be able to read it (UID 65532 in the container). |
| `CC_OIDC_TOKEN_KEY_FILE` | `auth.oidc.existingSecret` + `tokenKeyKey` (`token-key`) | required | file path | the file: yes | Path of the file with the 32-byte key that seals IdP refresh tokens in the database (ChaCha20-Poly1305): 64 hex characters (`openssl rand -hex 32`), base64 of 32 bytes, or 32 random bytes. **Secret.** Changing it makes stored refresh tokens unreadable — users sign in once more. |
| `CC_OIDC_SCOPES` | `auth.oidc.scopes` | `openid email profile offline_access`; `adfs`: `openid email profile allatclaims`; `google`: `openid email profile` | space-separated list incl. `openid` | no | Space-separated scopes; `openid` is required. `offline_access` provides the refresh token for re-checks; Google rejects it (the preset adds `access_type=offline` and `prompt=consent` itself). |
| `CC_OIDC_EMAIL_CLAIM` | `auth.oidc.emailClaim` | `email`; `entra`: `preferred_username`; `adfs`: `upn` | claim name | no | ID token claim used as the account e-mail (the value must contain `@`). |
| `CC_OIDC_REQUIRED_CLAIM` | `auth.oidc.requiredClaim` | not set | `claim=value` | no | `name=value`: admit only identities whose claim equals the value or, for arrays such as `groups` and `roles`, contains it. Otherwise `403 group_required`. |
| `CC_OIDC_REQUIRE_MFA` | `auth.oidc.requireMfa` | `false` | boolean | no | Require multi-factor sign-in: `mfa` or `http://schemas.microsoft.com/claims/multipleauthn` in `amr`, or an `acr` from `CC_OIDC_MFA_ACR_VALUES`. Otherwise `403 mfa_required`. Refused for `google` without `acr` values. |
| `CC_OIDC_MFA_ACR_VALUES` | `auth.oidc.mfaAcrValues` | empty | list | no | `acr` values that count as multi-factor (comma or space separated). |
| `CC_OIDC_TOKEN_AUTH_METHOD` | `auth.oidc.tokenAuthMethod` | `client_secret_basic` | `client_secret_basic` (`basic`), `client_secret_post` (`post`) | no | How the server authenticates at the token endpoint: `client_secret_basic` (`basic`) or `client_secret_post` (`post`). |
| `CC_OIDC_CA_FILE` | `auth.oidc.caKey` (a key in the same Secret) | system roots | path to a PEM file | no | PEM certificate of an extra root CA for an IdP behind an internal CA (e.g. AD FS). |

### LDAP / Active Directory

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_LDAP_URL` | `auth.ldap.url` | required | `ldaps://…`, `ldap://…` | no | `ldaps://dc1.acme.local:636`, or `ldap://dc1.acme.local:389` together with `CC_LDAP_STARTTLS=true`. Plain `ldap://` without STARTTLS is refused: domain passwords must not travel in clear text. The host name must match the domain controller's certificate. |
| `CC_LDAP_STARTTLS` | `auth.ldap.starttls` | `false` | boolean | no | STARTTLS for `ldap://`; not allowed with `ldaps://`. |
| `CC_LDAP_CA_FILE` | `auth.ldap.caKey` (a key in the same Secret) | system roots | path to a PEM file | no | PEM with the domain's root CA certificate (one or more certificates). |
| `CC_LDAP_BIND_DN` | `auth.ldap.bindDn` | required | DN | no | DN of the service account for searches and re-checks, e.g. `CN=svc-consolecrypt,OU=Service,DC=acme,DC=local`. Read access to the directory is enough. |
| `CC_LDAP_BIND_PASSWORD_FILE` | `auth.ldap.existingSecret` + `bindPasswordKey` (`bind-password`) | required | file path | the file: yes | Path of the file with the service account password. **Secret.** |
| `CC_LDAP_BASE_DN` | `auth.ldap.baseDn` | required | DN | no | Where to search for users (`DC=acme,DC=local`). It also identifies the source of identity links: after changing it the links must be recreated. |
| `CC_LDAP_USER_FILTER` | `auth.ldap.userFilter` | `(&(objectClass=user)(\|(mail={login})(userPrincipalName={login})(sAMAccountName={login})))` | LDAP filter with `{login}` | no | Search filter with `{login}`; must start with `(`. User input is escaped per RFC 4515 and a `DOMAIN\` prefix is dropped. If several entries match, sign-in is refused. |
| `CC_LDAP_EMAIL_ATTR` | `auth.ldap.emailAttr` | `mail` | attribute name | no | Attribute holding the e-mail address. |
| `CC_LDAP_ID_ATTR` | `auth.ldap.idAttr` | `objectGUID` | attribute name | no | Stable user identifier; `objectGUID` is stored as a GUID string. A changed e-mail or name does not break the link. |
| `CC_LDAP_REQUIRED_GROUP` | `auth.ldap.requiredGroup` | not set | DN | no | DN of the group the user must belong to (nested groups count, AD rule `LDAP_MATCHING_RULE_IN_CHAIN`); checked at sign-in and re-check. At start-up the server checks that the group exists. |
| `CC_LDAP_TIMEOUT_SECS` | `auth.ldap.timeoutSecs` | `10` | seconds, 1–60 | no | Connection and operation timeout, 1–60 seconds. |
| `CC_LDAP_MAX_FAILURES` | `auth.ldap.maxFailures` | `3` | 1–100 | no | Failed sign-ins per login and per directory user within the window, 1–100; after that the server answers `429` **without contacting AD**. Keep it **below** the domain's account lockout threshold. |
| `CC_LDAP_FAILURE_WINDOW_MINUTES` | `auth.ldap.failureWindowMinutes` | `15` | minutes, 1–1440 | no | Failed sign-in window, 1–1440 minutes; not shorter than the domain policy's lockout counter reset time. |
| `CC_LDAP_MAX_FAILURES_PER_IP` | `auth.ldap.maxFailuresPerIp` | `30` | integer ≥ 0, `0` = no limit | no | Failed sign-ins per IP within the window; `0` = no limit. |

## Observability: metrics, logs, tracing

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_METRICS_LISTEN` | `metrics.enabled` (`true` → `0.0.0.0:9090`, `false` → `off`) | `0.0.0.0:9090` | `host:port`, `off`, `disabled` | no | Separate Prometheus listener (`GET /metrics`). `off` or `disabled` turns it off. Metrics are unauthenticated: never publish the port or route it through the Ingress. The Docker Compose example turns them off. |
| `CC_LOG_FORMAT` | `config.log.format` | `json` | `json`, `pretty` (`text`) | no | Log format on stderr: `json` or `pretty` (`text`). `admin` commands always log `pretty`. |
| `CC_LOG` | `config.log.filter` | `info,sqlx=warn` | EnvFilter directive | no | **Environment only** (not accepted in the JSON file). Log filter in `tracing` EnvFilter syntax: `info`, `debug,sqlx=warn`. Without it `RUST_LOG` is read. |
| `RUST_LOG` | `extraEnv` | — | EnvFilter directive | no | **Environment only.** Fallback log filter when `CC_LOG` is unset. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `extraEnv` | not set | URL | no | **Environment only.** Enables OpenTelemetry trace export (OTLP HTTP/protobuf), e.g. `http://otel-collector:4318`. Standard `OTEL_*` variables apply. Spans carry only non-secret fields (request id, route, status, user and device UUIDs). |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | `extraEnv` | not set | URL | no | **Environment only.** The same with a traces-only endpoint. |

## Maintenance and data retention

The maintenance pass deletes expired bookkeeping rows. It runs on one replica at a
time (advisory lock). Retention is in days, `0` keeps forever, at most 36500.
The server makes no backups: use `pg_dump` as described in [HOSTING.md](HOSTING.md).

| Variable | Helm | Default | Values | Secret | What it does |
|---|---|---|---|---|---|
| `CC_MAINTENANCE_INTERVAL_SECS` | `config.maintenance.intervalSecs` | `3600` | seconds, `0` = off | no | Period of the maintenance pass; `0` turns it off. |
| `CC_RETENTION_SESSION_DAYS` | `config.maintenance.retention.sessionDays` | `7` | days, 0–36500, `0` = forever | no | How long revoked and expired sessions are kept. |
| `CC_RETENTION_SYNC_MUTATION_DAYS` | `config.maintenance.retention.syncMutationDays` | `30` | days, 0–36500, `0` = forever | no | Idempotency records of accepted sync changes. |
| `CC_RETENTION_AUDIT_DAYS` | `config.maintenance.retention.auditDays` | `365` | days, 0–36500, `0` = forever | no | The audit trail (`audit_events`). |
| `CC_RETENTION_DELETED_VAULT_DAYS` | `config.maintenance.retention.deletedVaultDays` | `30` | days, 0–36500, `0` = forever | no | After how many days a deleted vault's ciphertext is purged. |
| `CC_RETENTION_DEVICE_REQUEST_DAYS` | `config.maintenance.retention.deviceRequestDays` | `90` | days, 0–36500, `0` = forever | no | Decided and expired device trust requests. |

## Service variables

| Variable | Where | What it does |
|---|---|---|
| `CC_CONFIG_FILE` | environment only | Path of the private JSON settings file when `--config` is not given. The file: regular, up to 64 KiB, one JSON object of known keys with string values, mode `0600` or `0400` on Unix. It is never looked up in the working directory, never executed, and `$` or commands are not expanded. |

Variables of the Docker Compose example — read by Compose, not by the server:

| Variable | What it does |
|---|---|
| `CC_SERVER_VERSION` | Image version `ghcr.io/evsikovas/consolecrypt-server:<version>`. |
| `CC_SERVER_IMAGE` | The full image reference instead of a version, e.g. with an `@sha256:` digest. |
| `CC_DOMAIN` | Domain Caddy obtains the certificate for. |
| `CC_HTTP_PORT` | API port on the host's `127.0.0.1` (default `8080`). |
| `CC_POSTGRES_ADMIN_PASSWORD` | PostgreSQL administrator password inside the database container (created by `init-config.py`). |
| `CC_POSTGRES_PASSWORD`, `CC_METRICS_PORT` | Only for the development `server/docker-compose.yml`: the bundled database password and the host metrics port. |

## Admin commands

Commands run with the same binary and the same configuration (`--config` is a
global flag): `docker compose … exec -T server /usr/local/bin/consolecrypt-server
admin …` or `kubectl exec deployment/… -- /usr/local/bin/consolecrypt-server admin
…`. They never give access to vault contents.

| Command | What it does |
|---|---|
| `serve` | Run the server (the default). |
| `migrate` | Apply migrations and exit. |
| `healthcheck` | Probe `/readyz` of the local listener; exit code 0 means ready. |
| `admin list-users` | Accounts: status, sign-in method (`password`, `oidc`, `ldap`), address verification, device and vault counts. |
| `admin verify-email --email …` | Mark the address verified (a server without mail). |
| `admin reset-token --email …` | Print a single-use account password reset code (valid for `CC_PASSWORD_RESET_TTL_SECS`). |
| `admin set-password --email … --password-stdin` | Set the password from the first stdin line; all sessions end. |
| `admin disable-user --email …` / `admin enable-user --email …` | Disable the account and revoke its sessions / enable it again. |
| `admin session revoke --email …` | End every session of the account. |
| `admin rotate-epoch --all` / `--vault <id>` | After restoring the database from a backup: rotate vault epochs so clients notice the rollback. |
| `admin limits show [--email …]` | Effective limits and quotas (of the server or an account). |
| `admin limits set --email … key=value…` | Override an account's limits and quotas; applies within 30 seconds. |
| `admin limits reset --email … [key…]` | Remove overrides (all of them without keys). |
| `admin auth status` | Sign-in mode, provider, last IdP/directory check, linked accounts. |
| `admin auth test [--login … [--password-stdin]]` | Repeat the start-up checks; with `--login` look up an LDAP user (a real bind with `--password-stdin`) or re-check an OIDC account at the IdP. |
| `admin identity link --email … --subject … [--issuer …]` | Link the account to an OIDC `sub` or an `objectGUID`; the account password is removed and sessions end. |
| `admin identity unlink --email … [--subject …]` | Remove the account's links (or one of them). |
