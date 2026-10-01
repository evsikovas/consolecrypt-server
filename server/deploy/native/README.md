# Настройки сервера и SMTP

SMTP — настройка сервера. Клиент и статический сайт не получают SMTP-пароль.
В образе и исходниках находятся только примеры. Рабочие пароли создаёт оператор.

## Docker Compose

Готовый комплект — [`../docker`](../docker). Генератор создаёт приватный
`server.env` вне репозитория (каталог `0700`, файл `0600`) и не перезаписывает
существующие пароли базы. SMTP-пароль вводится скрыто:

```sh
python3 server/deploy/docker/init-config.py \
  --directory "$HOME/.config/consolecrypt-server" --domain sync.example.org
docker compose --env-file "$HOME/.config/consolecrypt-server/server.env" \
  -f server/deploy/docker/compose.yaml --profile https up -d
```

`CC_MAIL_TRANSPORT=smtp`, `CC_MAIL_FROM`, `CC_SMTP_HOST`, `CC_SMTP_PORT`,
`CC_SMTP_TLS`, `CC_SMTP_USERNAME`, `CC_SMTP_PASSWORD` берутся из `server.env`.
Для 587 обычно используют `starttls`, для 465 — `tls`. После изменения
пересоздайте сервер командой `up -d --force-recreate server` с теми же
`--env-file` и `-f`. Новый образ для смены SMTP не нужен.

Не выполняйте `source server.env`: синтаксис Compose не является shell-скриптом.
Не публикуйте вывод `docker compose config` или `docker inspect`: он может
содержать пароли. Доступ к Docker позволяет читать окружение контейнера;
файл `0600` не защищает от администратора Docker.

## Бинарник без Docker

Сервер поддерживает приватный JSON-файл: `--config /etc/consolecrypt/server.json`
или переменную `CC_CONFIG_FILE`. Флаг имеет приоритет над `CC_CONFIG_FILE`;
переменные `CC_*` процесса имеют приоритет над значениями файла, включая пустое
значение. Значения JSON — строки, включая числа и `true`/`false`. Названия
совпадают с переменными из `server/.env.example`. Неизвестные и повторные ключи,
неверный формат и недоступный файл останавливают запуск без вывода содержимого.
Файл не исполняется, `$` и shell-команды в значениях не подставляются.

Пример [`server.example.json`](server.example.json) содержит пустые пароли и
демонстрационный SMTP. На Linux подготовьте системного пользователя
`consolecrypt`, установите бинарник в `/usr/local/bin/consolecrypt-server`, затем:

```sh
sudo install -d -m 0750 -o root -g consolecrypt /etc/consolecrypt
sudo install -m 0600 -o consolecrypt -g consolecrypt \
  server/deploy/native/server.example.json /etc/consolecrypt/server.json
sudo -u consolecrypt editor /etc/consolecrypt/server.json
sudo install -m 0644 server/deploy/native/consolecrypt-server.service \
  /etc/systemd/system/consolecrypt-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now consolecrypt-server
```

Перед запуском задайте реальные SMTP/БД и создайте отдельную роль PostgreSQL —
владельца БД без superuser/createrole/createdb. Пример слушает только loopback;
публичный HTTPS и WebSocket обслуживает ваш reverse proxy. Если приложение
доступно только через один доверенный proxy, включите
`CC_TRUST_PROXY_HEADERS=true`. `CC_PUBLIC_URL` необязателен: без него письма
содержат код, который пользователь вводит в клиенте.

Для проверки после настройки: `consolecrypt-server --config /etc/consolecrypt/server.json healthcheck`.
Под тем же пользователем можно запускать `migrate` и `admin` с тем же `--config`.
Перезапустите службу после редактирования файла; автоматического перечитывания нет.
На Unix сервер отвергает файл с доступом для группы/остальных: используйте
`0600` или `0400`. На Windows ограничьте ACL файла и каталога служебной учётной
записью и администраторами; Unix-проверка режима там не применяется.

`CC_LOG`/`RUST_LOG` и стандартные `OTEL_*` — переменные подсистемы наблюдаемости,
они остаются в окружении процесса и не входят в JSON. По умолчанию файл не
ищется в текущем каталоге. JSON-конфигурация требует сервера с поддержкой
`--config`; Docker-комплект с закреплённым образом 0.1.11 продолжает использовать
`server.env` и не требует этого флага.

## Kubernetes / Helm

Параметры SMTP задаются в `mail.smtp` Helm values, пароль — в Kubernetes Secret
через `mail.smtp.existingSecret` и `existingSecretPasswordKey`. Deployment
получает `CC_SMTP_PASSWORD` через `secretKeyRef`. Не переносите рабочий пароль
в публичные values или в Dockerfile. Локальные JSON/ENV и backups храните вне
репозитория с ограниченными правами; шифруйте резервные копии средствами вашей
инфраструктуры.
