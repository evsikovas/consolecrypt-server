# Выпуск сервера по тегу

Workflow: [server.yml](../../.github/workflows/server.yml). Ветка `main` хранит
актуальную кодовую базу. Workflow запускается **только push тега `vX.Y.Z`**,
совпадающего с `server/Cargo.toml`: сначала проверки, затем сборка AMD64/ARM64,
публикация и настроенная выкладка. Push ветки, PR и workflow_dispatch не запускают
этот workflow. Неудачные jobs можно повторить в исходном tagged run.

## Проверки и источники

Сначала выполняются форматирование, Clippy, тесты протокола и сервера с
PostgreSQL 16, backup/restore и тесты release/deploy guards.
`CC_TEST_REQUIRE_DB=1` запрещает пропуск проверок БД.

`server/scripts/release.py` проверяет upstream-репозиторий, событие tag push,
точную версию, полный commit ID, чистый checkout,
совпадение checkout с разыменованным Git-тегом и принадлежность коммита истории
`origin/main`. Невлитая ветка, `main`, старый префикс `server-v`, несовпадающий
номер и перемещённый тег не проходят. Сборщики получают проверенный commit ID,
а не повторно разрешают изменяемую ветку.

На GitHub-hosted `ubuntu-24.04` и `ubuntu-24.04-arm` собираются нативные образы.
Каждый проходит изолированную Compose-проверку API, HTTPS, миграций,
backup/restore и сохранности данных. Личные Mac/Windows runners и домашний
k3s runner клиента не используются для публикации сервера или доступа к VPS.

Публикуются архитектурные образы и multi-platform manifest:

```text
ghcr.io/evsikovas/consolecrypt-server:<version>-<full-commit>-amd64
ghcr.io/evsikovas/consolecrypt-server:<version>-<full-commit>-arm64
ghcr.io/evsikovas/consolecrypt-server:sha-<full-commit>
ghcr.io/evsikovas/consolecrypt-server:<version>
```

Существующие ссылки не перезаписываются; `latest` не перемещается. Сетевой сбой
или отказ авторизации при проверке registry останавливает публикацию.
Артефакт `server-image/server-image.json` содержит digest, версию, тег и точную
ссылку на исходники. После обеих архитектур создаётся GitHub Release `vX.Y.Z`:
сначала draft с `server-image.json`, `build-receipt.json` и `SHA256SUMS`, затем
проверяются файлы и публикуется релиз. Receipt содержит URL Actions run и номер
попытки. Уже существующие релизы и опубликованные assets workflow не изменяет. Для запуска используется только `image` вида
`ghcr.io/evsikovas/consolecrypt-server@sha256:…`.

Если часть архитектур уже опубликована, полный повтор не пересобирает их поверх
старых ссылок. Сохраните проверенные артефакты и завершите оставшиеся jobs либо
выпустите новый patch-тег. Не удаляйте и не перемещайте уже опубликованный тег.

## Доступы

Начальные проверки имеют только `contents: read`; `packages: write` есть
только у заданий после проверки релизного тега. Actions закреплены полными SHA. GHCR
использует автоматический `GITHUB_TOKEN`, без постоянного PAT для публикации.
Пакет сервера должен оставаться публичным. SMTP, БД и production-конфигурация
не входят в image/artifacts. Прежняя GitLab pipeline отключена через
`workflow: rules: when: never`; старый publish_image.py оставлен только для
локальной проверки `--verify-only`.

## Порядок выпуска

1. Проверить и включить изменения в `main`, поднять `server/Cargo.toml` и запись
   самого сервера в `server/Cargo.lock` (следующий выпуск — `0.1.13`).
2. После локальной проверки `main` создать и отправить тег на выбранном коммите:

   ```sh
   git tag -a v0.1.13 -m 'ConsoleCrypt Server 0.1.13'
   git push origin v0.1.13
   ```

3. Дождаться обеих архитектур и manifest, сохранить `server-image.json`.
4. Сделать и проверить резервную копию production БД; проверить совместимость
   миграций с предыдущим сервером. Только затем обновлять существующий сервис.
5. После выпуска отдельно обновить pinned digest и appVersion в Helm/Compose
   примерах. До проверки нового образа они сохраняют последний проверенный 0.1.12.

## Обновление существующего Docker Compose

[release-compose.py](../deploy/release-compose.py) выполняется на рабочем сервере
с его существующими Compose-файлами и приватным env-файлом. Он не переносит
данные, не создаёт новый PostgreSQL и не меняет proxy, DNS, SMTP или другие
Compose-сервисы. Нужны Python 3, Docker и Compose v2 с `up --wait`.

Сохраните приватный JSON-конфиг вне Git; пути и имена ниже — пример, их нужно
сверить с действующей установкой:

```json
{
  "project_directory": "/opt/consolecrypt",
  "project": "consolecrypt",
  "compose_files": ["/opt/consolecrypt/compose.yaml"],
  "env_file": "/opt/consolecrypt/server.env",
  "service": "server",
  "state_directory": "/opt/consolecrypt/releases/server",
  "base_url": "https://sync.consolecrypt.dev"
}
```

После доставки script и manifest из того же проверенного тега:

```sh
python3 release-compose.py --config /etc/consolecrypt/server-release.json \
  --manifest server-image.json --tag v0.1.13 --revision FULL_COMMIT_FROM_WORKFLOW
```

Скрипт сверяет tag/version/source/digest, загружает образ по digest, запоминает
точный ID прежнего контейнерного образа, меняет только `server`, выполняет
`up --no-deps --no-build --pull never --wait` и проверяет ID работающего образа,
`/readyz` и версию/source URL в публичном `/v1/meta`. Source URL выставляется
в runtime вместе с образом. Пароли не печатаются и не копируются в release-state.

`state_directory/compose.release.json` — постоянный дополнительный Compose-файл;
используйте его после основного файла при следующих ручных `compose up`.
Иначе старый image из основного Compose-файла может вернуться. Не выполняйте
`docker image prune -a` до завершения проверки и срока хранения rollback.

## Откат

При сбое предыдущий image ID остаётся в `previous.json`; незавершённый выпуск
помечен `pending.json`. Повтор того же выпуска сохраняет прежний rollback,
другой выпуск блокируется до завершения или отката. Автоматического отката БД нет.

После проверки совместимости предыдущего сервера с текущей схемой:

```sh
python3 release-compose.py --config /etc/consolecrypt/server-release.json --rollback
```

Откат запускает точный сохранённый локальный image ID без скачивания или сборки,
восстанавливает прежний source URL и проверяет доступность. Если миграция
несовместима назад, сначала остановите запись и восстановите проверенную БД
по [HOSTING.md](../../docs/public/HOSTING.md); не запускайте старый бинарный файл
против несовместимой схемы. База, env-файлы и секреты не откатываются этим скриптом.

## Подключение production job

После проверки реальной установки задайте **repository variables**:
`PROD_SSH_HOST`, `PROD_SSH_USER`, `PROD_DEPLOY_CONFIG_PATH` (абсолютный путь к
приватному JSON выше), при необходимости `PROD_SSH_PORT` (по умолчанию 22).
Добавьте **repository secrets** `PROD_SSH_PRIVATE_KEY` и
`PROD_SSH_KNOWN_HOSTS` с заранее проверенным host key. Значения не хранятся в Git.
Используйте repo scope: предварительная проверка конфигурации не читает secrets
из environment. Сам deployment отмечается environment `production`; при
необходимости установите для него правила допуска только тегов.

`deployment_config` после публикации релиза проверяет наличие этих настроек.
Без них он записывает в summary `Production deploy skipped` с именами недостающих
полей, а `deploy` имеет статус skipped. Это не считается выполненной выкладкой.
При наличии конфигурации `deploy_ssh.py` снова проверяет tag/source, принимает
только закреплённый SSH host key и передаёт script + manifest на существующий VPS.
На VPS Docker уже должен иметь pull-доступ к нужному registry. Приватный ключ
не передаётся на VPS, не попадает в command line/payload и удаляется с runner
после шага. Производственная выкладка сериализована, running deploy не отменяется.
Само наличие домашнего k3s runner не даёт ему роли production target.
