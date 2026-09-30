# Сервер синхронизации и отдельный сайт

Публичный адрес: **https://consolecrypt.evsikov.net**. В приложении укажите
этот базовый URL, без `/v1`. Учётные записи разных серверов независимы.

Сервер **0.1.9**, протокол **1.5** обслуживает только `/v1`, `/healthz`, `/readyz`.
Сайт, `/account` и `/privacy` собираются и развёртываются независимо из
[consolecrypt-site](https://git.evsikov.net/publics/consolecrypt-site).
Сервер не содержит HTML, JavaScript или аналитику сайта. Ingress направляет
API и страницы в разные Service, сохраняя один HTTPS origin для кабинета.
Пути подписанных запросов API нельзя переписывать.

Кабинет использует Ed25519-подписи запросов. Неэкспортируемый ключ устройства
создаётся Web Crypto и сохраняется в IndexedDB; токены сеанса остаются в памяти
вкладки. Кабинет не расшифровывает хранилища и не получает SSH-ключи.
Подтверждение email и восстановление пароля отправляются по электронной почте.
Код в ссылке находится во фрагменте URL и не передаётся HTTP-серверу.

Самостоятельный Umami считает просмотры главной страницы и клики по загрузкам
Windows, macOS и Android. На `/account` и `/privacy` аналитика не подключена.
URL очищаются от query/hash перед отправкой. Настройка аналитики, сборка и
публикация сайта описаны в README отдельного репозитория.

## Свой сервер

Пароли, kubeconfig, SMTP-логины, настройки конкретных узлов и приватные
values храните вне Git. В репозитории есть только пример
`server/deploy/example.values.yaml`; скопируйте его в приватный каталог
и замените домен, issuer, registry и ссылки на существующие Secrets.
У Helm есть полная справка в `server/helm/consolecrypt-server/values.yaml`.

```sh
cargo fmt --check --manifest-path server/Cargo.toml
helm lint server/helm/consolecrypt-server -f /private/path/values.yaml
helm upgrade --install consolecrypt server/helm/consolecrypt-server \
  --namespace consolecrypt --create-namespace \
  --kubeconfig /private/path/kubeconfig.yaml \
  -f /private/path/values.yaml --history-max 5 --wait --atomic --timeout 5m
```

Используйте digest образа из артефакта `dist/server-image.json` задания
`publish-server-image`. Публикуются linux/amd64 и linux/arm64. Для закрытого
registry требуется read-only `imagePullSecret`; временный CI_JOB_TOKEN
не подходит для постоянного скачивания образов Kubernetes.

Для небольшого k3s без доступа к registry можно предварительно импортировать
образ на **каждый** узел и задать `image.pullPolicy: Never`:

```sh
python3 server/deploy/import-k3s-image.py \
  --kubeconfig /private/path/kubeconfig.yaml --node YOUR_NODE \
  --image consolecrypt-server:NEW_VERSION \
  --archive-name consolecrypt-server-NEW_VERSION.tar
```

Импорт требует администратора кластера. Временный pod монтирует только каталог
импорта образов k3s и удаляется после передачи. Сокет containerd и корень узла
не монтируются. Для нескольких узлов удобнее registry с immutable digest.

Создавайте секреты через менеджер секретов или
`server/deploy/bootstrap-secrets.py --kubeconfig FILE --smtp-password-file FILE`.
Скрипт сохраняет существующий пароль базы, но обновляет SMTP-пароль.
Секреты нельзя передавать через `helm --set`: они попадут в историю релиза.

## Проверка обновления

Проверьте readiness, `/v1/meta` (версию сервера, протокол и ссылку на исходники),
регистрацию, вход, синхронизацию двух устройств и отправку письма.
HTTP integration tests запускаются с отдельной PostgreSQL и переменными
`CC_TEST_DATABASE_URL`, `CC_TEST_REQUIRE_DB=1` — не с production базой.
Полный тест кабинета находится в отдельном сайте и использует локальный API
с file mail transport.

Миграции применяются при старте. Не изменяйте уже выполненные миграции.
Обновление приложения не должно удалять PVC, базу или существующие Secrets.
Helm rollback откатывает бинарный файл, но не содержимое базы.

Настройте регулярный `pg_dump`, проверку восстановления в отдельной базе и
хранение копий вне узла кластера. После отката базы выполните
`consolecrypt-server admin rotate-epoch --all`, чтобы клиенты обнаружили откат.
Копия на соседнем PVC того же узла не защищает от потери диска.

## Выпуск клиентов

Версия клиента независима от сервера и сайта. `build-macos` и `build-windows`
создают пакеты с уникальным номером GitLab job ID и контрольными суммами.
Установщики публикуются в GitLab Releases, а не в истории Git.
[Как выпускать новую версию](RELEASING.md).
