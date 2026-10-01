# Установка собственного сервера ConsoleCrypt

Сервер хранит учётные записи, сведения об устройствах и зашифрованные данные
хранилищ. Расшифровка происходит в клиенте; SSH-соединения клиент устанавливает
непосредственно с вашими хостами.

Ниже — установка в Kubernetes/k3s через Helm с PostgreSQL и SMTP. Домен
`sync.example.org`, адрес базы и почтовые настройки в примерах нужно заменить
своими. Все команды выполняются из корня исходников, если не указано иначе.

## 1. Подготовьте окружение и версию

Потребуются Kubernetes 1.25 или новее, `kubectl`, Helm 3 или 4, Python 3,
домен с DNS-записью на ingress-контроллер и действующий HTTPS-сертификат.
Пример рассчитан на Traefik и уже настроенный cert-manager с
`ClusterIssuer/letsencrypt`. Chart не устанавливает эти компоненты.

Проверенный комплект на 1 октября 2026 года:

| Компонент | Версия |
|---|---|
| Сервер | `0.1.10` |
| Протокол | `1.5` |
| Helm chart | `0.1.12` |
| PostgreSQL | `16` |
| Архитектуры образа | `linux/amd64`, `linux/arm64` |

Образ: `registry.evsikov.net/publics/consolecrypt/server:0.1.10`.
Для воспроизводимой установки используйте его digest:

```text
registry.evsikov.net/publics/consolecrypt/server@sha256:27d60ab711047dd27066eccfd0f7149b24490f40b85011adda1b85bae105bcc8
```

Получите соответствующий chart из исходников:

```sh
git clone https://git.evsikov.net/publics/consolecrypt.git
cd consolecrypt
git checkout --detach 2adfba091109dc92befcbca2b6d111f4649a98c0
```

При следующем обновлении меняйте digest и исходники chart согласованно.
Справочник параметров: [values.yaml](../../server/helm/consolecrypt-server/values.yaml).

Образ можно предварительно проверить Docker-командами:

```sh
docker pull registry.evsikov.net/publics/consolecrypt/server@sha256:27d60ab711047dd27066eccfd0f7149b24490f40b85011adda1b85bae105bcc8
docker run --rm --network none registry.evsikov.net/publics/consolecrypt/server@sha256:27d60ab711047dd27066eccfd0f7149b24490f40b85011adda1b85bae105bcc8 --version
```

В репозитории также есть `server/docker-compose.yml`: это вариант для локальной
разработки с пересборкой исходников, PostgreSQL и записью писем в файлы.
Его настройки по умолчанию не являются готовой установкой с HTTPS и SMTP.
Для постоянного использования ниже приведён полный путь через Helm.

## 2. Выберите кластер и приватный каталог

Откройте отдельный терминал Bash. Укажите свой kubeconfig и контекст:

```sh
set -euo pipefail
export CC_KUBECONFIG="$HOME/.kube/selfhost.yaml"
kubectl --kubeconfig "$CC_KUBECONFIG" config get-contexts
export CC_KUBE_CONTEXT="my-cluster"
export CC_INSTALL_DIR="$HOME/.config/consolecrypt-server"
export CC_API_ORIGIN="https://sync.example.org"
umask 077
mkdir -p "$CC_INSTALL_DIR"
chmod 700 "$CC_INSTALL_DIR"

cc_kubectl() {
  kubectl --kubeconfig "$CC_KUBECONFIG" --context "$CC_KUBE_CONTEXT" \
    --namespace consolecrypt "$@"
}
cc_helm() {
  helm --kubeconfig "$CC_KUBECONFIG" --kube-context "$CC_KUBE_CONTEXT" \
    --namespace consolecrypt "$@"
}

cc_kubectl get nodes
cc_kubectl create namespace consolecrypt --dry-run=client -o yaml | cc_kubectl apply -f -
```

Проверьте, что показаны узлы нужного кластера. Пароли и kubeconfig не должны
попадать в Git, аргументы команд, CI-логи или Helm values. Kubernetes Secrets
тоже требуют ограничения доступа и защиты резервных копий кластера.

## 3. PostgreSQL и Secrets

Основной вариант — отдельная PostgreSQL 16, управляемая вами, провайдером или
оператором PostgreSQL. Создайте базу `consolecrypt` и отдельного пользователя,
который владеет этой базой и может создавать таблицы и выполнять миграции.
Суперпользователь приложению не нужен. Разрешите подключение из серверных pod.

Для внешней базы используйте TLS с проверкой сертификата. URL имеет вид:

```text
postgresql://consolecrypt:URL_ENCODED_PASSWORD@db.example.org:5432/consolecrypt?sslmode=verify-full
```

Специальные символы пароля в URL нужно percent-encode. Если база использует
собственный CA, смонтируйте его сертификат в серверные pod и укажите
`sslrootcert` с путём внутри контейнера; не отключайте проверку сертификата.

Подготовьте пароль SMTP и полный URL базы. Следующий код запрашивает значения
без отображения на экране и сохраняет их без перевода строки. Он откажется
перезаписывать существующие файлы:

```sh
python3 - <<'PY'
import getpass
import os
from pathlib import Path

directory = Path(os.environ['CC_INSTALL_DIR'])
for name, prompt in [('database-url', 'Полный URL PostgreSQL: '),
                     ('smtp-password', 'Пароль SMTP: ')]:
    value = getpass.getpass(prompt)
    if not value or '\n' in value or '\r' in value:
        raise SystemExit('Требуется одно непустое значение')
    with (directory / name).open('x', encoding='utf-8') as handle:
        handle.write(value)
    (directory / name).chmod(0o600)
PY

cc_kubectl create secret generic consolecrypt-database \
  --from-file=database-url="$CC_INSTALL_DIR/database-url"
cc_kubectl create secret generic consolecrypt-smtp \
  --from-file=smtp-password="$CC_INSTALL_DIR/smtp-password"
```

Это команды первоначального создания. Если Secrets уже существуют, используйте
их имена и ключи в values, а обновление выполняйте через свой менеджер секретов.
Не создавайте новый пароль для уже существующей базы без согласованной смены
пароля в самой PostgreSQL.

### Встроенная PostgreSQL для небольшого сервера

Вместо внешней базы chart может создать один PostgreSQL pod с постоянным томом.
Это установка без репликации и автоматических резервных копий. Нужен рабочий
StorageClass; потеря единственного диска означает потерю базы без внешней копии.

Для **новой** установки подготовьте только файл `smtp-password` и выполните:

```sh
kubectl --kubeconfig "$CC_KUBECONFIG" config use-context "$CC_KUBE_CONTEXT"
python3 server/deploy/bootstrap-secrets.py \
  --kubeconfig "$CC_KUBECONFIG" \
  --smtp-password-file "$CC_INSTALL_DIR/smtp-password"
```

Этот helper использует текущий контекст указанного kubeconfig. Он создаёт
`consolecrypt-database` с ключом `password`, сохраняя существующий DB Secret,
и создаёт или обновляет `consolecrypt-smtp`. Полный URL внешней базы он
**не создаёт**. Не смешивайте два варианта: у Secrets разные ключи.

В values из следующего раздела замените блоки `database` и `postgresql` на:

```yaml
database:
  existingSecret: ""
postgresql:
  enabled: true
  auth:
    database: consolecrypt
    username: consolecrypt
    existingSecret: consolecrypt-database
    existingSecretPasswordKey: password
  persistence:
    enabled: true
    size: 8Gi
    storageClass: "" # StorageClass по умолчанию в вашем кластере
```

## 4. Настройте Helm, SMTP и HTTPS

Сохраните следующий пример как `$CC_INSTALL_DIR/values.yaml`, заменив домены,
SMTP-логин и при необходимости ingress class и issuer:

```yaml
fullnameOverride: consolecrypt
replicaCount: 1
image:
  repository: registry.evsikov.net/publics/consolecrypt/server
  tag: "0.1.10"
  digest: sha256:27d60ab711047dd27066eccfd0f7149b24490f40b85011adda1b85bae105bcc8
  pullPolicy: IfNotPresent

database:
  existingSecret: consolecrypt-database
  existingSecretKey: database-url
postgresql:
  enabled: false

config:
  publicUrl: ""
  sourceCodeUrl: https://git.evsikov.net/publics/consolecrypt/-/tree/2adfba091109dc92befcbca2b6d111f4649a98c0
  registrationOpen: true
  requireEmailVerification: true
  requireRequestProof: true
  eventBus: postgres
  trustProxyHeaders: "true"
  objectSharingEnabled: false
  sharedGroupsEnabled: false
  sharedSecretsEnabled: false
  sharingOwnerOnlineEnrollmentEnabled: false

mail:
  transport: smtp
  from: "ConsoleCrypt <no-reply@example.org>"
  smtp:
    host: smtp.example.org
    port: 587
    tls: starttls
    username: mailer@example.org
    existingSecret: consolecrypt-smtp
    existingSecretPasswordKey: smtp-password

migrations:
  runAtStartup: true
  job:
    enabled: false

ingress:
  enabled: true
  className: traefik
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
  hosts:
    - host: sync.example.org
      paths:
        - {path: /v1, pathType: Prefix}
        - {path: /healthz, pathType: Exact}
        - {path: /readyz, pathType: Exact}
  tls:
    - secretName: consolecrypt-tls
      hosts: [sync.example.org]
```

`publicUrl` здесь намеренно пуст: почтовое подтверждение использует код,
дальнейшие действия описаны ниже. Это поле не задаёт адрес прослушивания
или адрес, который нужно вводить в клиенте.

SMTP должен разрешать выбранный адрес отправителя. Для порта 465 задайте
`tls: tls`; для 587 — `tls: starttls`. Проверьте DNS-настройки отправителя
и доступ pod к SMTP-серверу. Режим `file` оставьте для локальных тестов.

Ingress должен передавать WebSocket `/v1/events/ws`, разрешать тело запроса
не меньше 16 MiB и сохранять путь, query и тело запросов без изменений:
они входят в подпись устройства. `trustProxyHeaders: "true"` подходит, когда
перед API стоит один доверенный proxy, корректно формирующий `X-Forwarded-For`,
а прямой доступ к порту API закрыт. Метрики на 9090 доступны только внутри
сети; этот порт не включён в Ingress.

Если TLS Secret выдаётся другим способом, уберите аннотацию cert-manager
и укажите существующий Secret. Если registry закрыт, создайте в этом namespace
`imagePullSecret` с правом только чтения и добавьте `imagePullSecrets` в values.
Краткоживущий токен задания CI для постоянного запуска pod не подходит.

## 5. Установите сервер

Сначала проверьте значения и результирующие ресурсы:

```sh
chmod 600 "$CC_INSTALL_DIR/values.yaml"
helm lint server/helm/consolecrypt-server -f "$CC_INSTALL_DIR/values.yaml"
helm template consolecrypt server/helm/consolecrypt-server \
  --namespace consolecrypt -f "$CC_INSTALL_DIR/values.yaml" \
  > "$CC_INSTALL_DIR/rendered.yaml"
```

Проверьте digest, домен, имена Secrets и наличие постоянного тома, если выбрана
встроенная база. В приведённых вариантах пароли берутся из существующих Secrets
и не записываются в Helm values или сгенерированный манифест.

```sh
cc_helm upgrade --install consolecrypt server/helm/consolecrypt-server \
  -f "$CC_INSTALL_DIR/values.yaml" --history-max 10 --wait --timeout 10m
cc_kubectl rollout status deployment/consolecrypt --timeout=180s
cc_kubectl get pods,service,ingress
```

Сервер подключится к базе, применит встроенные миграции и начнёт принимать
HTTP-запросы на внутреннем порту 8080. TLS завершается на Ingress.
Автоматический откат при ошибке включается разными параметрами:
[Helm 3](https://github.com/helm/helm-www/blob/main/versioned_docs/version-3/helm/helm_upgrade.md) —
`--atomic`, [Helm 4](https://helm.sh/docs/helm/helm_upgrade/) —
`--rollback-on-failure`. Используйте его при обновлении
только после проверки совместимости предыдущей версии с новой схемой базы;
миграции такой откат не отменяет.

## 6. Проверьте доступность и подключите клиент

```sh
curl --fail --silent --show-error "$CC_API_ORIGIN/healthz"
curl --fail --silent --show-error "$CC_API_ORIGIN/readyz"
curl --fail --silent --show-error "$CC_API_ORIGIN/v1/meta" | python3 -m json.tool
```

Ожидаются HTTP 200, ответы `ok`, `ready` и JSON с `server_version: "0.1.10"`,
`protocol_version: "1.5"` и выбранной `source_code_url`. Readiness проверяет
соединение с базой; успешный ответ ещё не подтверждает доставку почты или
синхронизацию. Не используйте `curl -k`: клиенту нужен доверенный сертификат.

В ConsoleCrypt создайте профиль с сервером `https://sync.example.org`,
**без `/v1`**, и зарегистрируйтесь. Если требуется подтверждение email,
дождитесь письма и подтвердите его код, затем повторите вход или настройку
профиля. Учётная запись действует на выбранном сервере.

Текущий desktop-клиент может запросить письмо сброса пароля, но отдельные
формы ввода почтового кода в нём ещё не предоставлены. До их появления
подтверждение email и завершение сброса выполняются через API. Следующий
скрипт запрашивает код и новый пароль без отображения и не сохраняет их.
В файл записывается только сам код скрипта:

```sh
cat > "$CC_INSTALL_DIR/account-code.py" <<'PY'
import getpass
import json
import os
import urllib.error
import urllib.parse
import urllib.request

origin = os.environ['CC_API_ORIGIN'].rstrip('/')
url = urllib.parse.urlsplit(origin)
if url.scheme != 'https' or not url.netloc or url.path or url.query or url.fragment or url.username:
    raise SystemExit('CC_API_ORIGIN должен быть базовым HTTPS-адресом вашего сервера')
action = input('Действие: verify (email) или reset (пароль): ').strip()
if action not in ('verify', 'reset'):
    raise SystemExit('Неизвестное действие')
body = {'token': getpass.getpass('Код из соответствующего письма: ')}
path = '/v1/auth/email/verify'
if action == 'reset':
    password = getpass.getpass('Новый пароль учётной записи (не менее 12 символов): ')
    if len(password) < 12 or password != getpass.getpass('Повторите новый пароль: '):
        raise SystemExit('Пароль слишком короткий или значения не совпадают')
    body['new_password'] = password
    path = '/v1/auth/password/reset'
request = urllib.request.Request(origin + path, data=json.dumps(body).encode(),
    headers={'Content-Type': 'application/json', 'x-cc-protocol-version': '1.5'}, method='POST')
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        print('Готово' if response.status == 204 else 'HTTP ' + str(response.status))
except urllib.error.HTTPError as error:
    raise SystemExit('Операция отклонена: HTTP ' + str(error.code)) from None
PY
chmod 600 "$CC_INSTALL_DIR/account-code.py"
python3 "$CC_INSTALL_DIR/account-code.py"
```

Код подтверждения и код сброса пароля — разные одноразовые коды. Сброс
пароля учётной записи завершает её сеансы и не расшифровывает хранилище.
Для частной установки без SMTP можно выбрать `mail.transport: disabled`;
администратор подтверждает адрес командой `admin verify-email` только после
самостоятельной проверки владельца адреса:

```sh
cc_kubectl exec deployment/consolecrypt -- \
  /usr/local/bin/consolecrypt-server admin verify-email --email user@example.org
```

После входа проверьте полный цикл: создайте тестовый хост без настоящих
секретов, подключите второе устройство, сверьте код доверия на обоих
устройствах, одобрите его и убедитесь, что изменения синхронизируются.
Проверьте также получение SMTP-письма. После создания нужных учётных записей
можно закрыть регистрацию через `config.registrationOpen: false` и повторить
`cc_helm upgrade` с полным приватным values-файлом.

Все четыре возможности совместного доступа в примере выключены.
Их включение — отдельное решение администратора после проверки совместимых
клиентов. Для обычной синхронизации своих устройств они не нужны.

### Необязательно: включить совместный доступ

Если вы решили разрешить совместный доступ на своём сервере, сначала
проверьте совместимые клиенты, подтверждение email и доверие устройствам.
В существующем блоке `config` своего приватного values-файла измените:

```yaml
config:
  requireRequestProof: true
  objectSharingEnabled: true
  sharedGroupsEnabled: true
  sharedSecretsEnabled: true
  sharingOwnerOnlineEnrollmentEnabled: true
```

`objectSharingEnabled` включает основной механизм; остальные флаги отдельно
разрешают общие группы, отдельные секреты и добавление новых собственных
устройств получателя при участии владельца. Расширения требуют основной
функции и обязательных подписей запросов. Включайте только нужные возможности;
не заменяйте этим фрагментом весь values-файл.

Ограничения прав, проверка кодов и отзыв описаны в [SHARING.md](SHARING.md).
Примените полный обновлённый файл:

```sh
cc_helm upgrade consolecrypt server/helm/consolecrypt-server \
  -f "$CC_INSTALL_DIR/values.yaml" --history-max 10 --wait --timeout 10m
```

Повторно проверьте readiness и обмен тестовым элементом между двумя
подтверждёнными учётными записями. Возможности доступны авторизованному клиенту
через `/v1/shares/capabilities`; одного `/v1/meta` для такой проверки недостаточно.

## 7. Резервные копии и восстановление

Все постоянные данные сервера находятся в PostgreSQL. Делайте регулярный
[pg_dump](https://www.postgresql.org/docs/16/app-pgdump.html) и храните
зашифрованные копии вне узла с базой. Отдельно сохраните
приватные настройки и секреты. Копия содержит чувствительные метаданные
учётных записей, даже несмотря на шифрование содержимого хранилищ.

Для внешней базы используйте инструменты PostgreSQL 16, файл подключений
`$CC_INSTALL_DIR/pg_service.conf` с секцией `[consolecrypt]` и файл паролей
`$CC_INSTALL_DIR/pgpass` с правами 0600. В service-файле задайте `host`, `port`,
`dbname`, `user`, `sslmode=verify-full` и при необходимости `sslrootcert`.
Пароль хранится в pgpass, а не в аргументах команды.
Форматы описаны в документации [service-файла](https://www.postgresql.org/docs/16/libpq-pgservice.html)
и [файла паролей](https://www.postgresql.org/docs/16/libpq-pgpass.html).

```sh
export PGSERVICEFILE="$CC_INSTALL_DIR/pg_service.conf"
export PGPASSFILE="$CC_INSTALL_DIR/pgpass"
chmod 600 "$PGSERVICEFILE" "$PGPASSFILE"
CC_BACKUP_FILE="$CC_INSTALL_DIR/consolecrypt-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump --dbname='service=consolecrypt' --format=custom --no-owner --no-acl \
  --file="$CC_BACKUP_FILE"
pg_restore --list "$CC_BACKUP_FILE" > "$CC_BACKUP_FILE.list"
```

Для встроенной базы вместо `pg_dump` на рабочем компьютере выполните:

```sh
CC_BACKUP_FILE="$CC_INSTALL_DIR/consolecrypt-$(date -u +%Y%m%dT%H%M%SZ).dump"
cc_kubectl exec statefulset/consolecrypt-postgresql -- \
  pg_dump -U consolecrypt -d consolecrypt --format=custom --no-owner --no-acl \
  > "$CC_BACKUP_FILE"
pg_restore --list "$CC_BACKUP_FILE" > "$CC_BACKUP_FILE.list"
```

Проверка списка архива не заменяет восстановления. Регулярно создавайте
**отдельную пустую проверочную базу** с отдельным пользователем и service-записью
`consolecrypt-restore-check`, затем выполняйте:

```sh
pg_restore --dbname='service=consolecrypt-restore-check' \
  --exit-on-error --no-owner --no-acl "$CC_BACKUP_FILE"
```

Сверьте таблицы, миграции, число записей и запуск той же версии сервера
в изолированном окружении. Не подключайте проверочную копию к рабочим клиентам.
Для восстановления после аварии сначала закройте клиентский доступ, восстановите
полную базу и сохранённые настройки, подключите сервер к восстановленной базе.
Перед возвратом клиентского доступа выполните:

```sh
cc_kubectl exec deployment/consolecrypt -- \
  /usr/local/bin/consolecrypt-server admin rotate-epoch --all
```

Это меняет эпохи личных хранилищ, чтобы клиенты обнаружили откат. Если до аварии
использовался совместный доступ, учитывайте его отдельные контрольные точки:
`rotate-epoch` не сбрасывает доверие общих элементов и не заменяет их процедуру
восстановления. Полная копия базы должна сохранять UUID экземпляра сервера.

## 8. Обновление

1. Сохраните предыдущие digest, chart и values; сделайте копию PostgreSQL
   и проверьте возможность восстановления.
2. Изучите миграции новой версии и совместимость отката. Закрепите новый
   digest и исходники chart; обновите `sourceCodeUrl` на исходники этой сборки.
3. Выполните `helm lint` и `helm template` с полным приватным values-файлом.
   Не меняйте DB Secret, имя базы, имя релиза или существующие PVC.
4. Выполните ту же команду `cc_helm upgrade --install`, затем проверьте
   `/readyz`, `/v1/meta`, SMTP и синхронизацию двух устройств.

Миграции встроены в бинарный файл и выполняются при старте. Выполненные SQL-файлы
не редактируют. Helm rollback меняет ресурсы приложения, но **не откатывает базу**.
Старый бинарный файл SQLx может отказаться запускаться при наличии более новых
миграций. Для заранее проверенного совместимого образа отката задают
`migrations.runAtStartup: false` и `migrations.job.enabled: false`; само по себе
отключение миграций не доказывает совместимость со схемой.

Не выполняйте `helm uninstall`, не удаляйте PVC или Secrets ради обновления
и не меняйте PostgreSQL 16 на другой major простой заменой тега. Смена major
PostgreSQL требует отдельного плана переноса данных.

Параметры запуска без Helm: [server/.env.example](../../server/.env.example).
