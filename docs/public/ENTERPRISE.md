# Enterprise-режим: вход через IdP (OIDC) или Active Directory (LDAP)

Начиная с сервера **0.2.0** (протокол **1.9**) у сервера синхронизации два режима
входа в аккаунт:

- **standard** (по умолчанию, как раньше) — регистрация и вход по email и паролю
  аккаунта, подтверждение почты, сброс пароля;
- **enterprise** — вход только через корпоративный источник учётных записей:
  IdP по OpenID Connect (Entra ID, AD FS, Keycloak, Google Workspace, Okta, любой
  OIDC) или Active Directory / LDAP (логин и пароль домена).

Меняется **только способ входа в аккаунт** на сервере синхронизации. Хранилища,
шифрование, устройства, защита от входа с нового устройства и совместный доступ
работают как раньше. Синхронизации каталога, групп, ролей, SCIM и админки нет.
Режим — часть открытого сервера, без отдельной сборки или лицензии.

## Что не меняется: шифрование

Пароль аккаунта (а теперь вместо него — IdP или AD) только доказывает личность
серверу. Данные открывает пароль хранилища (Argon2id на клиенте), Recovery Key
или одобрение доверенного устройства:

- ни IdP, ни AD, ни сервер не получают ничего, чем можно расшифровать хранилище;
- после входа через IdP/AD устройство — обычное новое устройство: действуют правила
  защиты от входа с нового устройства (карантин, ограничение выдачи password
  envelope, письмо, если включено `CC_DEVICE_PROTECTION_ENABLED` и настроена почта);
- онбординг хранилища (пароль хранилища + Recovery Kit) и подключение второго
  устройства не меняются.

## Как это работает

**OIDC.** Сервер — конфиденциальный клиент IdP, приложение — публичный клиент
сервера, PKCE (S256) на обоих участках:

1. Приложение открывает системный браузер на
   `GET /v1/auth/oidc/start?redirect_uri&code_challenge&state&device_id&login_hint`.
2. Сервер запоминает вход на 10 минут и перенаправляет на IdP со своими `state`,
   `nonce` и PKCE.
3. IdP возвращает браузер на `https://<сервер>/v1/auth/oidc/callback`. Сервер
   обменивает код, проверяет ID token (подпись RS256/PS256/ES256 через JWKS, точные
   `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, допуск часов 60 секунд), домен,
   группу и MFA, находит или создаёт аккаунт.
4. Браузер возвращается в приложение с одноразовым `login_code` (60 секунд,
   привязан к PKCE приложения и устройству), приложение получает обычные токены.

Допустимые адреса возврата в приложение: `http://127.0.0.1:{порт}/auth/callback`,
`http://[::1]:{порт}/auth/callback` (десктоп) и `consolecrypt://auth/callback`
(Android, iOS). Остальные отклоняются.

**LDAP / AD.** Приложение отправляет логин (email, UPN или `DOMAIN\user`) и пароль
домена на `POST /v1/auth/ldap/login` по TLS. Сервер ищет пользователя сервисной
учёткой, затем выполняет bind его DN с введённым паролем. Пароль не сохраняется
и не пишется в журнал. Ответы «нет пользователя» и «неверный пароль» одинаковы.

**Привязка аккаунта.** Аккаунт связан с внешним идентификатором — OIDC `(iss, sub)`
или `objectGUID` в AD. Email — только атрибут: смена адреса в AD не ломает аккаунт,
а чужой аккаунт с тем же email не захватывается (`identity_conflict`).

**Перепроверка (отключённые сотрудники).** Не чаще чем раз в
`CC_AUTH_RECHECK_MINUTES` сервер спрашивает IdP (обновлением refresh token IdP) или
AD (поиском по `objectGUID`), можно ли пользователю работать. Проверка идёт при
обновлении токена приложением и фоновым проходом раз в минуту для аккаунтов с
активными сессиями. Если пользователь отключён, удалён, вышел из группы или потерял
обязательный claim, все его сессии отзываются, приложение получает
`account_disabled` и блокирует синхронизированный профиль. Отключённый сотрудник
теряет доступ к синхронизации не позже чем через `CC_AUTH_RECHECK_MINUTES` + 1
минута. Если IdP или AD недоступен, сессии продолжают работать до
`CC_AUTH_RECHECK_GRACE_HOURS` после последней успешной проверки; дальше обновление
токена отвечает `503 idp_unavailable` (без отзыва), пока источник не вернётся.

## Конфигурация

Как остальные настройки: переменные `CC_*`, приватный JSON-файл (`--config`) или
Helm (блок `auth:`). Секреты — **только в файлах** (Kubernetes Secret, Docker
secret, файл с правами 0600); в журнал они не попадают.

### Общие ключи

| Ключ | По умолчанию | Назначение |
|---|---|---|
| `CC_AUTH_MODE` | `standard` | `standard` или `enterprise` |
| `CC_AUTH_PROVIDER` | — | `oidc` или `ldap` (только в enterprise) |
| `CC_AUTH_DISPLAY_NAME` | — | подпись кнопки «Войти через …» в приложении |
| `CC_AUTH_ALLOWED_DOMAINS` | — (любые) | допустимые домены email через запятую |
| `CC_AUTH_AUTO_CREATE` | `true` | создавать аккаунт при первом входе |
| `CC_AUTH_RECHECK_MINUTES` | `15` | как часто перепроверять пользователя (1–1440) |
| `CC_AUTH_RECHECK_GRACE_HOURS` | `24` | сколько живут сессии при недоступном IdP/AD (0–720) |
| `CC_PUBLIC_URL` | — | для OIDC обязателен (`https://…`): адрес возврата IdP |

### OIDC

| Ключ | Назначение |
|---|---|
| `CC_OIDC_PRESET` | `generic`, `entra`, `adfs`, `keycloak`, `google`, `okta` |
| `CC_OIDC_ISSUER` | точный issuer (без лишнего `/` в конце, если IdP его не пишет) |
| `CC_OIDC_CLIENT_ID` | идентификатор приложения в IdP |
| `CC_OIDC_CLIENT_SECRET_FILE` | файл с client secret |
| `CC_OIDC_TOKEN_KEY_FILE` | файл с 32-байтовым ключом шифрования refresh token IdP (`openssl rand -hex 32`) |
| `CC_OIDC_SCOPES` | по умолчанию `openid email profile offline_access` (adfs: `openid email profile allatclaims`, google: `openid email profile`) |
| `CC_OIDC_EMAIL_CLAIM` | по умолчанию `email` (entra: `preferred_username`, adfs: `upn`) |
| `CC_OIDC_REQUIRED_CLAIM` | `claim=значение`: пускать только эту группу/роль, например `groups=<object-id>` |
| `CC_OIDC_REQUIRE_MFA` | `true`: требовать `mfa` в `amr` (или одно из `CC_OIDC_MFA_ACR_VALUES` в `acr`) |
| `CC_OIDC_MFA_ACR_VALUES` | значения `acr`, которые считаются многофакторными |
| `CC_OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic` (по умолчанию) или `client_secret_post` |
| `CC_OIDC_CA_FILE` | дополнительный корневой сертификат IdP (внутренний CA) |

Пресет подставляет значения по умолчанию и проверяет типичные ошибки при старте:
для Entra запрещены `/common`, `/organizations` и `/consumers` (нужен tenant id),
для AD FS issuer должен заканчиваться на `/adfs`, для Keycloak — содержать
`/realms/`, для Google обязателен `CC_AUTH_ALLOWED_DOMAINS`, а `hd` из ID token
должен входить в этот список (иначе вошёл бы любой аккаунт Google).

Redirect URI, который регистрируется в IdP: `https://<сервер>/v1/auth/oidc/callback`
(то есть `CC_PUBLIC_URL` + `/v1/auth/oidc/callback`).

Для перепроверки нужен refresh token IdP, поэтому запрашивайте offline access
(`offline_access` в scopes; у Google пресет сам добавляет `access_type=offline`).
Если IdP не выдал refresh token, пользователь будет повторно входить через IdP раз
в `CC_AUTH_RECHECK_GRACE_HOURS`. Refresh token IdP хранится в БД только
зашифрованным (ChaCha20-Poly1305) ключом из `CC_OIDC_TOKEN_KEY_FILE`.

### LDAP / Active Directory

| Ключ | По умолчанию | Назначение |
|---|---|---|
| `CC_LDAP_URL` | — | `ldaps://dc1.acme.local:636`; `ldap://` — только с `CC_LDAP_STARTTLS=true` |
| `CC_LDAP_STARTTLS` | `false` | STARTTLS для `ldap://` |
| `CC_LDAP_CA_FILE` | системные корни | корневой сертификат домена (PEM) |
| `CC_LDAP_BIND_DN` | — | сервисная учётка, например `CN=svc-consolecrypt,OU=Service,DC=acme,DC=local` |
| `CC_LDAP_BIND_PASSWORD_FILE` | — | файл с паролем сервисной учётки |
| `CC_LDAP_BASE_DN` | — | где искать пользователей, например `DC=acme,DC=local` |
| `CC_LDAP_USER_FILTER` | `(&(objectClass=user)(\|(mail={login})(userPrincipalName={login})(sAMAccountName={login})))` | поиск; ввод экранируется по RFC 4515 |
| `CC_LDAP_EMAIL_ATTR` | `mail` | атрибут email |
| `CC_LDAP_ID_ATTR` | `objectGUID` | стабильный идентификатор |
| `CC_LDAP_REQUIRED_GROUP` | — | DN группы; вложенные группы учитываются (`LDAP_MATCHING_RULE_IN_CHAIN`) |
| `CC_LDAP_TIMEOUT_SECS` | `10` | таймаут соединения и операций |
| `CC_LDAP_MAX_FAILURES` | `3` | попыток на логин и на пользователя AD за окно (см. ниже) |
| `CC_LDAP_FAILURE_WINDOW_MINUTES` | `15` | окно счётчика неудачных входов |
| `CC_LDAP_MAX_FAILURES_PER_IP` | `30` | неудачных входов с одного IP за окно (0 — без ограничения) |

Простой `ldap://` без STARTTLS сервер отклоняет при старте: пароль домена не должен
идти по сети открытым текстом. Отключённые учётки AD (`userAccountControl` с флагом
`ACCOUNTDISABLE`) не входят. Пустой пароль отклоняется до обращения к AD (иначе
это был бы анонимный bind).

**Защита учёток AD от блокировки через сервер.** Неудачные bind учитываются в
политике блокировки домена, поэтому злоумышленник мог бы блокировать сотрудников
через `/v1/auth/ldap/login`. Сервер считает попытки в PostgreSQL (общие для всех
реплик) — на введённый логин и на найденного пользователя AD (разные написания
одного логина — email, UPN, `DOMAIN\user` — считаются вместе): после
`CC_LDAP_MAX_FAILURES` попыток за `CC_LDAP_FAILURE_WINDOW_MINUTES` дальнейшие
попытки отклоняются **без обращения к AD** (`429 rate_limited` с `Retry-After`),
пока окно не пройдёт. Неизвестный логин ведёт себя так же, существование
пользователя не раскрывается. Успешный вход сбрасывает счётчик.

> **Важно:** `CC_LDAP_MAX_FAILURES` должен быть **меньше порога блокировки учётной
> записи** в политике домена (Account lockout threshold), а
> `CC_LDAP_FAILURE_WINDOW_MINUTES` — не меньше окна сброса счётчика блокировки
> (Reset account lockout counter after). Иначе вход через сервер всё ещё может
> заблокировать учётку.

### Проверка при старте и команды администратора

При старте сервер проверяет конфигурацию и падает с понятной ошибкой: для OIDC —
discovery, совпадение `issuer`, JWKS с ключами RS256/PS256/ES256; для LDAP —
соединение, TLS, bind сервисной учётки, наличие base DN и группы.

```sh
consolecrypt-server admin auth status                       # режим, провайдер, последняя проверка, привязанные аккаунты
consolecrypt-server admin auth test                         # повторить проверки при старте
consolecrypt-server admin auth test --login alice@acme.com  # LDAP: найти пользователя, группа, отключён ли
consolecrypt-server admin auth test --login alice@acme.com --password-stdin   # LDAP: пробный bind
consolecrypt-server admin auth test --login alice@acme.com  # OIDC: перепроверить аккаунт в IdP сейчас
consolecrypt-server admin identity link --email alice@acme.com --subject <sub или objectGUID>
consolecrypt-server admin identity unlink --email alice@acme.com
consolecrypt-server admin session revoke --email alice@acme.com
consolecrypt-server admin list-users                        # колонка sign_in: password, oidc, ldap
```

OIDC `admin auth test --login` делает настоящую перепроверку: если IdP отказал,
сессии аккаунта отзываются. LDAP `--password-stdin` выполняет настоящий bind и
учитывается в политике блокировки домена.

## Переход со standard на enterprise

1. Обновите сервер до 0.2.0 (миграция `0011_enterprise_auth` только добавляет
   таблицы и делает `users.password_hash` необязательным).
2. Зарегистрируйте приложение в IdP или создайте сервисную учётку в AD (рецепты
   ниже), положите секреты в файлы/Secret.
3. Проверьте список аккаунтов: `admin list-users`.
4. Включите `CC_AUTH_MODE=enterprise` и перезапустите сервер. Обновите приложения
   до версии с поддержкой enterprise-входа (клиент 0.9.0).

После включения:

- регистрация, вход по паролю аккаунта, сброс и смена пароля, подтверждение почты
  отвечают `403 enterprise_auth_required`; старые приложения показывают ошибку
  входа с текстом «обновите приложение»;
- сессии, открытые паролем до переключения, не обновляются
  (`enterprise_auth_required`): пользователь один раз входит через IdP/AD;
- существующий аккаунт с паролем привязывается при первом входе, если email
  совпадает, домен есть в `CC_AUTH_ALLOWED_DOMAINS`, у аккаунта ещё нет внешнего
  идентификатора и IdP не сообщил `email_verified=false`. Пароль аккаунта при этом
  удаляется, его прежние сессии завершаются. Без `CC_AUTH_ALLOWED_DOMAINS` такие
  аккаунты автоматически не привязываются (`identity_conflict`) — используйте
  `admin identity link`;
- устройства и хранилища аккаунта сохраняются; устройство, которое уже было
  зарегистрировано, входит с подписью ключа устройства, как раньше.

**Аварийного входа по паролю в enterprise-режиме нет.** Если IdP или AD недоступен
или настроен неверно: `admin auth status`, `admin auth test`; чтобы временно пустить
людей по паролю, верните `CC_AUTH_MODE=standard` и задайте пароль командой
`admin set-password --email … --password-stdin`. Пароль аккаунта по-прежнему не
открывает хранилище. При повторном включении enterprise вход снова только через
IdP/AD, а пароль удаляется при следующем входе пользователя.

## Журнал

В журнал сервера (и в `audit_events`) пишутся входы (`login`, `metadata.method` =
`oidc`/`ldap`), создание аккаунтов, привязки (`identity_linked`/`identity_unlinked`),
отказы с причиной (`login_failed`, `metadata.reason`: `domain_not_allowed`,
`group_required`, `mfa_required`, `identity_conflict`, `nonce`, `aud`, …), отзывы
сессий перепроверкой (`enterprise_access_revoked`) и администратором. Пароли,
client secret, токены и коды входа в журнал не попадают. Метрики:
`cc_enterprise_logins_total{method,result}`, `cc_enterprise_rechecks_total{result}`,
`cc_ldap_lockout_guard_total{scope}`, `cc_oidc_jwks_refetch_total`.

## Рецепты

Во всех рецептах redirect URI в IdP: `https://sync.acme.com/v1/auth/oidc/callback`
(подставьте свой `CC_PUBLIC_URL`). Секреты:

```sh
install -d -m 700 /etc/consolecrypt/secrets
printf '%s' '<client secret>' > /etc/consolecrypt/secrets/oidc-client-secret
openssl rand -hex 32 > /etc/consolecrypt/secrets/oidc-token-key
chmod 600 /etc/consolecrypt/secrets/*
```

Ключ `oidc-token-key` не меняйте без необходимости: при смене ключа сохранённые
refresh token IdP становятся нечитаемыми, и пользователи один раз входят заново
после `CC_AUTH_RECHECK_GRACE_HOURS`.

### Microsoft Entra ID

1. Entra admin center → **App registrations → New registration**: имя
   «ConsoleCrypt Sync», **Accounts in this organizational directory only**
   (single tenant), Redirect URI — платформа **Web**,
   `https://sync.acme.com/v1/auth/oidc/callback`.
2. **Certificates & secrets → New client secret** — значение в файл
   `oidc-client-secret` (помните о сроке действия секрета).
3. **Token configuration → Add optional claim → ID → `email`**,
   `preferred_username` уже есть. По умолчанию пресет использует
   `preferred_username` (UPN) как email; если UPN не совпадает с почтой, задайте
   `CC_OIDC_EMAIL_CLAIM=email`.
4. Доступ только группе — один из вариантов:
   - **App roles** (рекомендуется): создайте роль `ConsoleCrypt.User`, назначьте её
     группе в **Enterprise applications → Users and groups**, задайте
     `CC_OIDC_REQUIRED_CLAIM=roles=ConsoleCrypt.User`;
   - **groups claim**: **Token configuration → Add groups claim → Security groups**
     (ID token, Group ID), задайте `CC_OIDC_REQUIRED_CLAIM=groups=<object-id группы>`.
     Если пользователь состоит более чем в 200 группах, Entra не кладёт `groups` в
     токен (overage) — тогда используйте app roles или «Groups assigned to the
     application».
   Дополнительно можно включить **Enterprise applications → Properties →
   Assignment required = Yes**.
5. MFA: Conditional Access для приложения; `CC_OIDC_REQUIRE_MFA=true` проверит
   `amr` = `mfa`.

```dotenv
CC_AUTH_MODE=enterprise
CC_AUTH_PROVIDER=oidc
CC_AUTH_DISPLAY_NAME=Acme SSO
CC_AUTH_ALLOWED_DOMAINS=acme.com
CC_PUBLIC_URL=https://sync.acme.com
CC_OIDC_PRESET=entra
CC_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
CC_OIDC_CLIENT_ID=<application (client) id>
CC_OIDC_CLIENT_SECRET_FILE=/etc/consolecrypt/secrets/oidc-client-secret
CC_OIDC_TOKEN_KEY_FILE=/etc/consolecrypt/secrets/oidc-token-key
CC_OIDC_REQUIRED_CLAIM=roles=ConsoleCrypt.User
```

Issuer `/common` и `/organizations` пресет отклоняет: нужен tenant id (Directory
(tenant) ID на странице Overview).

### AD FS 2016+

1. AD FS Management → **Application Groups → Add Application Group →
   Server application** (или «Web browser accessing a web application» с
   confidential client). Redirect URI — `https://sync.acme.com/v1/auth/oidc/callback`.
2. **Configure Application Credentials → Generate a shared secret** — в файл
   `oidc-client-secret`.
3. Добавьте к группе **Web API** с identifier = client id сервера, политика
   доступа (например, «Permit specific group»), разрешения `openid`, `profile`,
   `email`, `allatclaims`.
4. Issuance Transform Rules для Web API: «Send LDAP Attributes as Claims» —
   `E-Mail-Addresses → email`, `User-Principal-Name → upn`; для доступа по группе —
   «Send Group Membership as a Claim» (например, `group` = `ConsoleCrypt`).
5. Если сертификат AD FS выпущен внутренним CA, положите корневой сертификат в
   `CC_OIDC_CA_FILE`.

```dotenv
CC_OIDC_PRESET=adfs
CC_OIDC_ISSUER=https://adfs.acme.com/adfs
CC_OIDC_CLIENT_ID=<client id>
CC_OIDC_EMAIL_CLAIM=upn
CC_OIDC_REQUIRED_CLAIM=group=ConsoleCrypt
# CC_OIDC_TOKEN_AUTH_METHOD=client_secret_post   # если AD FS отклоняет Basic
```

AD FS сообщает MFA в `amr` как `http://schemas.microsoft.com/claims/multipleauthn`;
`CC_OIDC_REQUIRE_MFA=true` это понимает.

### Keycloak

1. Realm → **Clients → Create client**: OpenID Connect, Client ID
   `consolecrypt-server`, **Client authentication: On**, Standard flow: On,
   Direct access grants: Off.
2. **Valid redirect URIs**: `https://sync.acme.com/v1/auth/oidc/callback`.
   **Advanced → Proof Key for Code Exchange Code Challenge Method: S256**.
3. **Credentials** → Client secret — в файл.
4. Группа: **Client scopes → consolecrypt-server-dedicated → Add mapper → Group
   Membership**, Token Claim Name `groups`, **Full group path: Off**, Add to ID
   token: On. Затем `CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users`.
5. Пользователь отключается в **Users → Enabled: Off** — его refresh token
   перестаёт работать, и сервер отзывает сессии при ближайшей перепроверке.

```dotenv
CC_OIDC_PRESET=keycloak
CC_OIDC_ISSUER=https://sso.acme.com/realms/acme
CC_OIDC_CLIENT_ID=consolecrypt-server
CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users
```

### Google Workspace

1. Google Cloud Console → **APIs & Services → OAuth consent screen**: User type
   **Internal** (только пользователи вашей организации).
2. **Credentials → Create credentials → OAuth client ID → Web application**,
   Authorized redirect URI — `https://sync.acme.com/v1/auth/oidc/callback`.
   Client secret — в файл.
3. Пресет сам запрашивает offline access (`access_type=offline`, `prompt=consent`)
   и требует, чтобы `hd` из ID token был в `CC_AUTH_ALLOWED_DOMAINS`.
4. Google не передаёт группы и MFA в ID token: ограничьте доступ к приложению в
   Admin console, 2-Step Verification включите политикой Workspace.
   `CC_OIDC_REQUIRE_MFA=true` для google сервер не примет.

```dotenv
CC_OIDC_PRESET=google
CC_AUTH_ALLOWED_DOMAINS=acme.com
CC_OIDC_CLIENT_ID=<…>.apps.googleusercontent.com
```

### Okta

1. Admin Console → **Applications → Create App Integration → OIDC → Web
   Application**. Grant type: Authorization Code и **Refresh Token**.
   Sign-in redirect URI — `https://sync.acme.com/v1/auth/oidc/callback`.
2. **Client authentication: Client secret**, **Require PKCE** включите.
3. Назначьте приложение группе. Для claim групп: **Sign On → OpenID Connect ID
   Token → Groups claim filter** `groups` Matches regex `ConsoleCrypt.*`.
4. Issuer — домен org (`https://acme.okta.com`) или authorization server
   (`https://acme.okta.com/oauth2/default`); он должен точно совпадать с `issuer`
   в discovery.

```dotenv
CC_OIDC_PRESET=okta
CC_OIDC_ISSUER=https://acme.okta.com
CC_OIDC_REQUIRED_CLAIM=groups=ConsoleCrypt-Users
```

### Active Directory по LDAPS

1. Сервисная учётка с минимальными правами (обычный пользователь домена может
   читать каталог), пароль без срока действия:

   ```powershell
   New-ADUser -Name svc-consolecrypt -Path "OU=Service,DC=acme,DC=local" `
     -AccountPassword (Read-Host -AsSecureString) -Enabled $true -PasswordNeverExpires $true
   ```

   Пароль — в файл `ldap-bind-password`, DN — в `CC_LDAP_BIND_DN`.
2. LDAPS: у контроллеров домена должен быть сертификат (AD CS «Domain Controller»
   или «Kerberos Authentication»). Экспортируйте корневой сертификат CA в PEM —
   `CC_LDAP_CA_FILE`. Имя в `CC_LDAP_URL` должно совпадать с именем в сертификате
   контроллера (лучше DNS-имя, а не IP).
3. Группа доступа, например `CN=ConsoleCrypt,OU=Groups,DC=acme,DC=local`;
   вложенные группы учитываются.
4. Стабильный идентификатор — `objectGUID`: смена email, UPN или переименование
   учётки не ломает привязку. Для `admin identity link` берите его так:
   `(Get-ADUser alice).ObjectGUID`.
5. Проверьте политику блокировки домена и задайте `CC_LDAP_MAX_FAILURES` меньше
   порога блокировки (см. выше).

```dotenv
CC_AUTH_MODE=enterprise
CC_AUTH_PROVIDER=ldap
CC_AUTH_DISPLAY_NAME=ACME
CC_AUTH_ALLOWED_DOMAINS=acme.com
CC_LDAP_URL=ldaps://dc1.acme.local:636
CC_LDAP_CA_FILE=/etc/consolecrypt/secrets/ad-ca.pem
CC_LDAP_BIND_DN=CN=svc-consolecrypt,OU=Service,DC=acme,DC=local
CC_LDAP_BIND_PASSWORD_FILE=/etc/consolecrypt/secrets/ldap-bind-password
CC_LDAP_BASE_DN=DC=acme,DC=local
CC_LDAP_REQUIRED_GROUP=CN=ConsoleCrypt,OU=Groups,DC=acme,DC=local
CC_LDAP_MAX_FAILURES=3
CC_LDAP_FAILURE_WINDOW_MINUTES=30
```

Вариант с STARTTLS: `CC_LDAP_URL=ldap://dc1.acme.local:389` и
`CC_LDAP_STARTTLS=true`. Пользователи вводят email, UPN или `ACME\alice`.

## Развёртывание

### Helm

```yaml
config:
  publicUrl: https://sync.acme.com
auth:
  mode: enterprise
  provider: oidc            # или ldap
  displayName: Acme SSO
  allowedDomains: [acme.com]
  oidc:
    preset: entra
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    clientId: <client id>
    requiredClaim: roles=ConsoleCrypt.User
    existingSecret: consolecrypt-oidc   # ключи client-secret, token-key
  ldap:
    url: ldaps://dc1.acme.local:636
    bindDn: CN=svc-consolecrypt,OU=Service,DC=acme,DC=local
    baseDn: DC=acme,DC=local
    requiredGroup: CN=ConsoleCrypt,OU=Groups,DC=acme,DC=local
    existingSecret: consolecrypt-ldap   # ключ bind-password; caKey: ca.pem
    caKey: ca.pem
```

```sh
kubectl -n consolecrypt create secret generic consolecrypt-oidc \
  --from-file=client-secret=./oidc-client-secret --from-file=token-key=./oidc-token-key
kubectl -n consolecrypt create secret generic consolecrypt-ldap \
  --from-file=bind-password=./ldap-bind-password --from-file=ca.pem=./ad-ca.pem
```

Secret монтируется только для чтения в `/run/secrets/consolecrypt-auth`; чарт
проверяет обязательные поля и отклоняет `ldap://` без `starttls: true`. Остальные
ключи (`scopes`, `emailClaim`, `requireMfa`, `userFilter`, `maxFailures`,
`failureWindowMinutes`, `maxFailuresPerIp`, …) описаны в `values.yaml`.

### Docker Compose

Основной `compose.yaml` не меняется. Добавьте рядом `compose.override.yaml` со
своими значениями и секретами:

```yaml
services:
  server:
    environment:
      CC_PUBLIC_URL: https://sync.acme.com
      CC_AUTH_MODE: enterprise
      CC_AUTH_PROVIDER: oidc
      CC_AUTH_ALLOWED_DOMAINS: acme.com
      CC_OIDC_PRESET: keycloak
      CC_OIDC_ISSUER: https://sso.acme.com/realms/acme
      CC_OIDC_CLIENT_ID: consolecrypt-server
      CC_OIDC_CLIENT_SECRET_FILE: /run/secrets/oidc-client-secret
      CC_OIDC_TOKEN_KEY_FILE: /run/secrets/oidc-token-key
    secrets: [oidc-client-secret, oidc-token-key]
secrets:
  oidc-client-secret:
    file: ./secrets/oidc-client-secret
  oidc-token-key:
    file: ./secrets/oidc-token-key
```

Файлы секретов должны быть читаемы пользователем контейнера (UID 65532).

### Бинарный файл

Те же ключи в приватном JSON (`--config /etc/consolecrypt/server.json`, права
0600) или в окружении службы; пути `*_FILE` указывают на файлы с правами 0600,
принадлежащие пользователю службы.

## Ошибки для приложений (протокол 1.9)

| Код | HTTP | Когда |
|---|---|---|
| `enterprise_auth_required` | 403 | вход/регистрация/сброс по паролю на enterprise-сервере; сессия без привязки |
| `identity_conflict` | 409 | email принадлежит аккаунту другого источника или привязка требует администратора |
| `domain_not_allowed` | 403 | домен email не в `CC_AUTH_ALLOWED_DOMAINS` или у учётки нет email |
| `group_required` | 403 | нет обязательной группы/роли/claim |
| `mfa_required` | 403 | IdP не сообщил MFA |
| `idp_unavailable` | 503 | IdP или AD недоступен (повторить позже) |
| `account_disabled` | 403 | учётка отключена; все сессии отозваны |
| `invalid_credentials` | 401 | неверный логин/пароль AD, недействительный ID token, повтор или подмена `login_code` |
| `rate_limited` | 429 | лимит попыток (в том числе защита учёток AD от блокировки) |

Подробности протокола — в [PROTOCOL_CHANGELOG.md](../../PROTOCOL_CHANGELOG.md),
типы — в `cc_protocol::enterprise_auth`.
