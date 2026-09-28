# Публичный сервер и сайт ConsoleCrypt

Адрес: **https://consolecrypt.evsikov.net**. Сайт, личный кабинет `/account`
и API `/v1/...` обслуживаются одним Rust-сервером. Клиентам нужен базовый URL,
без добавления `/v1`. Версия сервера/сайта: **0.1.3**, протокол **1.5**.
Версии установщиков приложения независимы: macOS 0.1.2+6, Android 0.1.2+7.
Исходники развёрнутого сервера опубликованы в ветке `codex/public-server-website`
([merge request !1](https://git.evsikov.net/publics/consolecrypt/-/merge_requests/1)).
В момент публикации защита `main` не разрешала текущей учётной записи слияние;
её настройки не менялись. `/v1/meta` указывает на фактически опубликованную ветку.

## Что входит

- Русскоязычный адаптивный сайт: возможности, защита, скриншоты, загрузки из GitLab.
- Личный кабинет: регистрация, вход, подтверждение email, сброс и смена пароля,
  список устройств и отзыв их доступа, выход из сеанса.
- Браузер использует Ed25519-подписи запросов протокола 1.5. Приватные ключи
  создаются Web Crypto как неэкспортируемые и сохраняются в IndexedDB.
  Access/refresh tokens остаются только в памяти вкладки.
- Хранилище не расшифровывается в браузере. Парольная фраза, SSH-ключи,
  содержимое терминала и объектов хранилища кабинету не нужны.
- Подтверждение email и восстановление пароля приходят от
  `ConsoleCrypt <consolecrypt@evsikov.net>` через `smtp.masterhost.ru:465`, TLS.
- Письма содержат код для приложения и ссылку в кабинет. Код находится
  во фрагменте URL (`#`), который не передаётся HTTP-серверу и access logs.
- Начиная с сервера 0.1.2 все письма объявляют `MIME-Version: 1.0` и
  `Content-Type: text/plain; charset=utf-8`, чтобы почтовые клиенты правильно
  показывали кириллицу. Исправление применяется к новым письмам.

Учётные записи привязаны к конкретному серверу. Аккаунт с localhost или другого
self-hosted сервера не появляется на публичном сервере автоматически. Никакая
локальная база пользователей при развёртывании не переносилась.

## Архитектура установленного экземпляра

- k3s, узел `akita`, архитектура amd64; namespace/release `consolecrypt`.
- Deployment `consolecrypt`, один непривилегированный distroless-контейнер.
- PostgreSQL 16: StatefulSet `consolecrypt-postgresql`, отдельный PVC 16 GiB,
  `local-path`. База не публикуется наружу.
- Traefik завершает TLS. cert-manager использует существующий ClusterIssuer
  `letsencrypt-cloudflare`; external-dns создаёт A-запись.
- HTTP перенаправляется на HTTPS. Пути API не переписываются: они подписаны.
- Метрики остаются на внутреннем Service, порт 9090.
- NetworkPolicy разрешает вход к приложению от Traefik, к базе — от приложения
  и задания резервного копирования; исходящие запросы приложения — DNS, база, SMTP.
- Секреты `consolecrypt-database` и `consolecrypt-smtp` не входят в Helm values,
  Docker context и Git. Файлы kubeconfig/паролей необходимо хранить отдельно.

Исходники сайта: `server/web/`. Они включены в бинарный файл через `server/src/web.rs`.
Внешние JavaScript, аналитика и CDN-шрифты не используются. API и страницы имеют
раздельные Content-Security-Policy; неизвестные API-пути возвращают JSON 404.

Проверка 2026-09-28: публичный HTTPS и сертификат действуют; DMG/APK доступны
непустыми файлами из GitLab; регистрационное письмо доставлено в предоставленный
ящик и код подтверждения принят. Временный тестовый аккаунт удалён по точному UUID,
хранилищ он не создавал. Первый pg_dump успешно восстановлен в отдельную временную
базу (4 миграции); тестовая база затем удалена.

Обновление 0.1.2: на полученном через IMAP регистрационном письме проверены
`MIME-Version: 1.0`, `text/plain; charset=utf-8`, корректное декодирование русской
темы и текста стандартным MIME-парсером. Код принят API с ответом 204;
временный проверочный аккаунт удалён по UUID. Пройдены 24 unit-теста сервера,
5 тестов веб-протокола, `cargo fmt --check` и `helm lint`.

HTTP-редирект проверен на ingress и возвращает 301. **Публичный TCP/80 сейчас
закрыт выше уровня кластера**: открывайте сайт с `https://`. Если нужен переход
с внешнего `http://`, владелец сети должен пробросить TCP/80 на ingress
`10.10.10.11:80`. Настройки маршрутизатора в рамках этой установки не менялись.

## Проверки перед обновлением

```sh
# Node.js 22+; у веб-части нет сторонних npm-зависимостей.
node --test server/web/tests/protocol.test.js
cargo fmt --check --manifest-path server/Cargo.toml

# Только отдельная тестовая PostgreSQL. Пароль задавайте через секрет окружения.
export CC_TEST_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:5432/TEST_DB'
export CC_TEST_REQUIRE_DB=1
cargo test --manifest-path server/Cargo.toml --locked \
  --lib --test web --test auth --test request_proofs --test security

helm lint server/helm/consolecrypt-server -f server/deploy/evsikov.values.yaml
```

`server/web/tests/account.integration.test.js` дополнительно проверяет полный
цикл браузерной авторизации на локальном сервере с file mail transport.
Запускайте его с `CC_WEB_TEST_URL=http://127.0.0.1:PORT` и
`CC_WEB_TEST_MAIL_DIR=/path/to/isolated/test/mail`; публичный сервер тест отвергает.

## Обновление

1. Увеличьте версию сервера в `server/Cargo.toml`, `server/Cargo.lock`, веб-части
   в `server/web/package.json` и `server/web/assets/api.js`, chart/appVersion.
   При каждой пересборке используйте новый номер/tag, не перезаписывайте старый.
2. Запустите проверки. Опубликуйте исходники изменённого сервера в GitLab (AGPL).
3. Соберите образ для amd64 из корня репозитория:

```sh
docker build --platform linux/amd64 -f server/Dockerfile \
  -t consolecrypt-server:NEW_VERSION .
```

4. Для этого односерверного k3s образ предварительно загружается на узел:

```sh
python3 server/deploy/import-k3s-image.py \
  --kubeconfig /private/path/kubeconfig.yaml --node akita \
  --image consolecrypt-server:NEW_VERSION \
  --archive-name consolecrypt-server-NEW_VERSION.tar
```

Скрипт требует прав администратора кластера. Он временно монтирует только
`/var/lib/rancher/k3s/agent/images` в служебный pod, передаёт tar атомарно и
удаляет pod. Сокет containerd и корень узла не монтируются. Архив остаётся на
узле: k3s сможет импортировать его после перезапуска. При добавлении узлов
импортируйте образ на каждый из них или перейдите на registry и `IfNotPresent`.
Неработающий существующий GitLab Runner не является частью этой схемы.

5. Первичная подготовка секретов (также обновляет SMTP-пароль, но **никогда**
   не заменяет уже существующий пароль базы):

```sh
python3 server/deploy/bootstrap-secrets.py \
  --kubeconfig /private/path/kubeconfig.yaml \
  --smtp-password-file /private/path/smtp-password.txt
```

6. Примените новую версию, дождитесь readiness:

```sh
helm upgrade --install consolecrypt server/helm/consolecrypt-server \
  --namespace consolecrypt --kubeconfig /private/path/kubeconfig.yaml \
  -f server/deploy/evsikov.values.yaml --set image.tag=NEW_VERSION \
  --history-max 5 --wait --timeout 5m
kubectl --kubeconfig /private/path/kubeconfig.yaml apply \
  -f server/deploy/evsikov.network.yaml -f server/deploy/evsikov.backup.yaml
kubectl --kubeconfig /private/path/kubeconfig.yaml -n consolecrypt \
  rollout status deployment/consolecrypt --timeout=120s
curl --fail https://consolecrypt.evsikov.net/readyz
curl --fail https://consolecrypt.evsikov.net/v1/meta
```

Миграции применяются при старте. Не изменяйте уже выполненные migration-файлы.
При обновлении содержимого существующего SMTP Secret перезапустите Deployment
(`kubectl rollout restart deployment/consolecrypt -n consolecrypt` с явным kubeconfig).

## Резервное копирование и восстановление

CronJob `consolecrypt-backup` запускает `pg_dump -Fc` каждый день в 03:30
Europe/Moscow. Копии находятся на отдельном PVC `consolecrypt-backups` (16 GiB).
Архив сначала проверяется `pg_restore --list`, затем атомарно переименовывается.
Хранятся копии примерно за последние восемь суток; старые удаляются после
успешного создания новой. Доступ к файлам ограничен `umask 077`.

**Оба PVC находятся на том же физическом узле. Это не внешняя аварийная копия.**
Для защиты от потери диска/узла настройте вынос архивов в отдельное хранилище.
Одноузловая установка также не обеспечивает отказоустойчивость. Контролируйте
свободное место, ошибки CronJob и объём регистраций публичного сервера.

Разовый запуск:

```sh
kubectl --kubeconfig /private/path/kubeconfig.yaml -n consolecrypt \
  create job --from=cronjob/consolecrypt-backup consolecrypt-backup-manual-YYYYMMDD
```

Восстановление сначала проверяют в **новой отдельной базе**, затем планируют
переключение приложения. После отката основной базы необходимо выполнить
`consolecrypt-server admin rotate-epoch --all`: это позволяет клиентам обнаружить
откат и восстановить недостающие данные. Не запускайте восстановление поверх
работающей базы и не удаляйте PVC/Secrets при обычном обновлении.

Для отката бинарного файла используйте предыдущую Helm revision
(`helm history` → `helm rollback` с явным kubeconfig). Учитывайте совместимость
миграций; rollback Helm сам по себе не откатывает базу.

## Сборки для скачивания

Ссылки на сайте указывают на [релиз v0.1.2](https://git.evsikov.net/publics/consolecrypt/-/releases/v0.1.2).
Готового Windows EXE пока нет; ссылка ведёт на инструкцию сборки. Когда он
появится, загрузите его в GitLab Release и обновите карточку Windows в
`server/web/index.html`, увеличьте версию сайта/сервера и пересоберите образ.

Публикуйте только очищенный Git-репозиторий. Локальные пароли, kubeconfig,
заметки агентов, базы, установщики и tar-образы не должны попадать в Git.
