# Enterprise-режим: вход через IdP (OIDC) или Active Directory (LDAP)

> То же самое на сайте: [корпоративный вход — рецепты](https://consolecrypt.dev/guide#server-idp).
> Same on the website: [corporate sign-in recipes](https://consolecrypt.dev/guide#server-idp).

Начиная с сервера **0.2.0** (протокол **1.9**) у сервера синхронизации два режима
входа в аккаунт:

- **standard** (по умолчанию, как раньше) — регистрация и вход по email и паролю
  аккаунта, подтверждение почты, сброс пароля;
- **enterprise** — вход только через корпоративный источник учётных записей:
  IdP по OpenID Connect (Entra ID, AD FS, Keycloak, Google Workspace, Okta, любой
  OIDC) или Active Directory / LDAP (логин и пароль домена).

Меняется **только способ входа в аккаунт** на сервере синхронизации. Хранилища,
шифрование, устройства, защита от входа с нового устройства, совместный доступ и
команды работают как раньше. Синхронизации каталога, групп, ролей, SCIM и
админки нет. Режим — часть открытого сервера, без отдельной сборки или лицензии.
Пользователям нужен клиент 0.9.0 или новее.

Содержание: [как это работает](#как-это-работает) ·
[что нужно серверу](#что-нужно-серверу-от-idp) ·
[конфигурация](#конфигурация) ·
[рецепты IdP](#рецепты-oidc) ·
[Active Directory](#active-directory-и-ldap) ·
[первый вход и привязка](#первый-вход-и-привязка-аккаунтов) ·
[команды](#проверка-при-старте-и-команды-администратора) ·
[развёртывание](#развёртывание) ·
[ошибки](#диагностика-ошибок) ·
[возврат в standard](#возврат-в-режим-standard) ·
[English](#english).

Полный справочник всех ключей с путями Helm и проверками — в
[CONFIGURATION.md](CONFIGURATION.md#enterprise-вход-cc_auth_-cc_oidc_-cc_ldap_).

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
(Android, iOS). Остальные отклоняются. В IdP регистрируется **только** адрес
сервера `/v1/auth/oidc/callback`, адреса приложений в IdP не нужны.

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

## Что нужно серверу от IdP

Для любого OIDC-провайдера подготовьте:

| Что | Значение | Ключ |
|---|---|---|
| Публичный адрес сервера | `https://sync.acme.com` (тот, что вводится в клиенте, без `/v1`) | `CC_PUBLIC_URL` |
| Redirect URI в IdP | `https://sync.acme.com/v1/auth/oidc/callback` — посимвольно `CC_PUBLIC_URL` + `/v1/auth/oidc/callback`, тип клиента «Web» / confidential | — |
| Issuer | точно как в `https://<issuer>/.well-known/openid-configuration` (поле `issuer`, с завершающим `/` или без — как у IdP) | `CC_OIDC_ISSUER` |
| Client ID | идентификатор зарегистрированного приложения | `CC_OIDC_CLIENT_ID` |
| Client secret | файл с секретом; аутентификация `client_secret_basic` или `client_secret_post` | `CC_OIDC_CLIENT_SECRET_FILE`, `CC_OIDC_TOKEN_AUTH_METHOD` |
| Ключ шифрования refresh token | файл с 32 случайными байтами (`openssl rand -hex 32`) | `CC_OIDC_TOKEN_KEY_FILE` |
| Grant types | Authorization Code с PKCE S256 и Refresh Token | — |
| Scopes | `openid email profile offline_access` (у пресетов свои значения) | `CC_OIDC_SCOPES` |
| Claims в **ID token** | `sub`; адрес почты (`email`, `preferred_username` или `upn`); для ограничения доступа — `groups` или `roles`; для MFA — `amr`/`acr` | `CC_OIDC_EMAIL_CLAIM`, `CC_OIDC_REQUIRED_CLAIM`, `CC_OIDC_REQUIRE_MFA` |

Требования к IdP, которые сервер проверяет при старте: discovery по HTTPS,
совпадение `issuer`, `authorization_endpoint`, `token_endpoint` и `jwks_uri` по
HTTPS, хотя бы один ключ RS256/PS256/ES256 в JWKS и, если IdP перечисляет
методы PKCE, поддержка S256. Сервер читает claims только из ID token (userinfo не
запрашивается), поэтому группы, роли и почта должны попадать именно в ID token.

**Refresh token IdP** нужен для перепроверки отключённых сотрудников. Если IdP его
не выдал, пользователь просто входит через IdP заново раз в
`CC_AUTH_RECHECK_GRACE_HOURS`; `admin auth test --login <email>` в этом случае
сообщает `no IdP refresh token stored (request offline access)`.

## Конфигурация

Как остальные настройки: переменные `CC_*`, приватный JSON-файл (`--config`) или
Helm (блок `auth:`). Секреты — **только в файлах** (Kubernetes Secret, Docker
secret, файл с правами 0600); в журнал они не попадают. Как задать ключи в
Docker Compose, Helm и systemd — в [HOSTING.md](HOSTING.md#как-задать-любой-параметр).

### Общие ключи

| Ключ | По умолчанию | Назначение |
|---|---|---|
| `CC_AUTH_MODE` | `standard` | `standard` или `enterprise` |
| `CC_AUTH_PROVIDER` | — | `oidc` или `ldap` (только в enterprise) |
| `CC_AUTH_DISPLAY_NAME` | — | подпись кнопки «Войти через …» в приложении, до 64 символов |
| `CC_AUTH_ALLOWED_DOMAINS` | — (любые) | допустимые домены email через запятую; нужен для автоматической привязки существующих аккаунтов |
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
| `CC_OIDC_REQUIRED_CLAIM` | `claim=значение`: пускать только эту группу/роль, например `groups=<object-id>`; для массива достаточно одного совпадающего элемента |
| `CC_OIDC_REQUIRE_MFA` | `true`: требовать `mfa` (или `http://schemas.microsoft.com/claims/multipleauthn`) в `amr`, или одно из `CC_OIDC_MFA_ACR_VALUES` в `acr` |
| `CC_OIDC_MFA_ACR_VALUES` | значения `acr`, которые считаются многофакторными |
| `CC_OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic` (по умолчанию) или `client_secret_post` |
| `CC_OIDC_CA_FILE` | дополнительный корневой сертификат IdP (внутренний CA) |

Пресет подставляет значения по умолчанию и проверяет типичные ошибки при старте:
для Entra запрещены `/common`, `/organizations` и `/consumers` (нужен tenant id),
для AD FS issuer должен заканчиваться на `/adfs`, для Keycloak — содержать
`/realms/`, для Google обязателен `CC_AUTH_ALLOWED_DOMAINS`, а `hd` из ID token
должен входить в этот список (иначе вошёл бы любой аккаунт Google).

Refresh token IdP хранится в БД только зашифрованным (ChaCha20-Poly1305) ключом
из `CC_OIDC_TOKEN_KEY_FILE`.

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
| `CC_LDAP_TIMEOUT_SECS` | `10` | таймаут соединения и операций (1–60) |
| `CC_LDAP_MAX_FAILURES` | `3` | попыток на логин и на пользователя AD за окно (1–100, см. ниже) |
| `CC_LDAP_FAILURE_WINDOW_MINUTES` | `15` | окно счётчика неудачных входов (1–1440) |
| `CC_LDAP_MAX_FAILURES_PER_IP` | `30` | неудачных входов с одного IP за окно (0 — без ограничения) |

## Рецепты OIDC

Во всех рецептах сервер доступен по `https://sync.acme.com`, redirect URI в IdP —
`https://sync.acme.com/v1/auth/oidc/callback` (подставьте свой `CC_PUBLIC_URL`).
Сначала подготовьте файлы секретов:

```sh
install -d -m 700 /etc/consolecrypt/secrets
( umask 077
  openssl rand -hex 32 > /etc/consolecrypt/secrets/oidc-token-key
  # client secret из IdP, без перевода строки и без отображения на экране:
  read -rs CC_SECRET && printf '%s' "$CC_SECRET" > /etc/consolecrypt/secrets/oidc-client-secret
  unset CC_SECRET )
```

Владельцем файлов должен быть пользователь процесса сервера (в контейнере —
UID 65532, см. [развёртывание](#развёртывание)). Ключ `oidc-token-key` не меняйте
без необходимости: при смене ключа сохранённые refresh token IdP становятся
нечитаемыми, и пользователи один раз входят заново. Client secret у многих IdP
имеет срок действия: заведите напоминание, при замене обновите файл и
перезапустите сервер.

Общий для всех рецептов набор ключей:

```dotenv
CC_AUTH_MODE=enterprise
CC_AUTH_PROVIDER=oidc
CC_AUTH_DISPLAY_NAME=Acme SSO
CC_AUTH_ALLOWED_DOMAINS=acme.com
CC_PUBLIC_URL=https://sync.acme.com
CC_OIDC_CLIENT_SECRET_FILE=/etc/consolecrypt/secrets/oidc-client-secret
CC_OIDC_TOKEN_KEY_FILE=/etc/consolecrypt/secrets/oidc-token-key
```

### Microsoft Entra ID

1. Microsoft Entra admin center → **App registrations → New registration**:
   имя «ConsoleCrypt Sync», **Accounts in this organizational directory only**
   (single tenant), Redirect URI — платформа **Web**,
   `https://sync.acme.com/v1/auth/oidc/callback`. Не выбирайте платформы «SPA» или
   «Mobile and desktop» — сервер является конфиденциальным клиентом.
2. На странице **Overview** скопируйте **Application (client) ID** →
   `CC_OIDC_CLIENT_ID` и **Directory (tenant) ID** → issuer
   `https://login.microsoftonline.com/<tenant-id>/v2.0`.
3. **Certificates & secrets → Client secrets → New client secret** — значение
   (не Secret ID) сохраните в файл `oidc-client-secret`. Запомните срок действия.
4. **API permissions**: Microsoft Graph, delegated `openid`, `email`, `profile`,
   `offline_access`. Нажмите **Grant admin consent**, чтобы сотрудники не видели
   запроса согласия.
5. **Token configuration → Add optional claim → ID → `email`**. По умолчанию
   пресет использует `preferred_username` (обычно UPN) как email. Если UPN не
   совпадает с почтовым адресом, задайте `CC_OIDC_EMAIL_CLAIM=email` — у
   пользователя должен быть заполнен атрибут mail.
6. Доступ только нужным людям — один из вариантов:
   - **App roles** (рекомендуется): **App roles → Create app role**, Allowed member
     types — Users/Groups, Value `ConsoleCrypt.User`; затем **Enterprise
     applications → ConsoleCrypt Sync → Users and groups → Add user/group** и
     назначьте роль группе. На сервере `CC_OIDC_REQUIRED_CLAIM=roles=ConsoleCrypt.User`;
   - **groups claim**: **Token configuration → Add groups claim → Security groups**,
     в ID token — **Group ID**; на сервере
     `CC_OIDC_REQUIRED_CLAIM=groups=<object-id группы>`. Если пользователь состоит
     более чем в 200 группах, Entra не кладёт `groups` в токен (overage), сервер
     пишет об этом предупреждение в журнал — используйте app roles или «Groups
     assigned to the application».
   Дополнительно включите **Enterprise applications → Properties → Assignment
   required = Yes**: тогда Entra не выдаст токен неназначенным пользователям.
7. MFA: требуйте её политикой **Conditional Access** для этого приложения.
   `CC_OIDC_REQUIRE_MFA=true` дополнительно проверяет `amr`/`acr` в ID token;
   включайте его, только если тестовый вход проходит — если IdP не сообщает
   метод входа, все входы получат `mfa_required`.

```dotenv
CC_OIDC_PRESET=entra
CC_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
CC_OIDC_CLIENT_ID=<application-client-id>
CC_OIDC_REQUIRED_CLAIM=roles=ConsoleCrypt.User
```

Issuer `/common`, `/organizations` и `/consumers` пресет отклоняет: нужен tenant id.
Отключённый в Entra пользователь не может обновить refresh token, и сервер
отзывает его сессии при ближайшей перепроверке.

### AD FS 2016+

1. AD FS Management → **Application Groups → Add Application Group →
   Server application** (или «Web browser accessing a web application» с
   confidential client). Скопируйте Client Identifier → `CC_OIDC_CLIENT_ID`.
   Redirect URI — `https://sync.acme.com/v1/auth/oidc/callback`.
2. **Configure Application Credentials → Generate a shared secret** — в файл
   `oidc-client-secret`.
3. Добавьте к группе **Web API** с identifier = client id сервера, политика
   доступа (например, «Permit specific group»), разрешения `openid`, `profile`,
   `email`, `allatclaims`.
4. Issuance Transform Rules для Web API: «Send LDAP Attributes as Claims» —
   `E-Mail-Addresses → email`, `User-Principal-Name → upn`; для доступа по группе —
   «Send Group Membership as a Claim» (например, `group` = `ConsoleCrypt`).
   Scope `allatclaims` (есть в пресете) нужен, чтобы эти claims попали в ID token.
5. Если сертификат AD FS выпущен внутренним CA, положите корневой сертификат (PEM)
   в `CC_OIDC_CA_FILE`.
6. Issuer — `https://adfs.acme.com/adfs`: проверьте поле `issuer` в
   `https://adfs.acme.com/adfs/.well-known/openid-configuration`.

```dotenv
CC_OIDC_PRESET=adfs
CC_OIDC_ISSUER=https://adfs.acme.com/adfs
CC_OIDC_CLIENT_ID=<client-id>
CC_OIDC_EMAIL_CLAIM=upn
CC_OIDC_REQUIRED_CLAIM=group=ConsoleCrypt
CC_OIDC_CA_FILE=/etc/consolecrypt/secrets/adfs-ca.pem
# CC_OIDC_TOKEN_AUTH_METHOD=client_secret_post   # если AD FS отклоняет Basic
```

AD FS сообщает MFA в `amr` как `http://schemas.microsoft.com/claims/multipleauthn`;
`CC_OIDC_REQUIRE_MFA=true` это понимает.

### Keycloak

1. Выберите realm (например, `acme`) → **Clients → Create client**: OpenID
   Connect, Client ID `consolecrypt-server`, **Client authentication: On**,
   Standard flow: On, Direct access grants: Off.
2. **Valid redirect URIs**: `https://sync.acme.com/v1/auth/oidc/callback`.
   **Advanced → Proof Key for Code Exchange Code Challenge Method: S256**.
3. **Credentials** → Client secret — в файл.
4. Почта: client scopes `email` и `profile` должны быть Default для клиента.
   Keycloak передаёт `email_verified`: если адрес не подтверждён, существующий
   аккаунт с паролем автоматически не привяжется (`email_not_verified`).
5. Группа: **Client scopes → consolecrypt-server-dedicated → Add mapper → By
   configuration → Group Membership**, Token Claim Name `groups`, **Full group
   path: Off** (иначе значение будет `/consolecrypt-users`), Add to ID token: On.
   Затем `CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users`. Вместо группы можно
   использовать роль клиента и mapper «User Client Role».
6. Пользователь отключается в **Users → Enabled: Off** — его refresh token
   перестаёт работать, и сервер отзывает сессии при ближайшей перепроверке.

```dotenv
CC_OIDC_PRESET=keycloak
CC_OIDC_ISSUER=https://sso.acme.com/realms/acme
CC_OIDC_CLIENT_ID=consolecrypt-server
CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users
```

### Google Workspace

1. Google Cloud Console (проект вашей организации) → **APIs & Services → OAuth
   consent screen**: User type **Internal** (только пользователи вашей
   организации), scopes `openid`, `email`, `profile`.
2. **Credentials → Create credentials → OAuth client ID → Web application**,
   Authorized redirect URI — `https://sync.acme.com/v1/auth/oidc/callback`.
   Client ID → `CC_OIDC_CLIENT_ID`, Client secret — в файл.
3. Issuer задавать не нужно (`https://accounts.google.com`). Пресет сам запрашивает
   offline access (`access_type=offline`, `prompt=consent`); `offline_access` в
   `CC_OIDC_SCOPES` Google отвергает, и сервер не запустится с ним.
4. `CC_AUTH_ALLOWED_DOMAINS` обязателен: сервер пускает только аккаунты Workspace,
   чей `hd` из ID token входит в список. Личный аккаунт Google с «корпоративным»
   адресом `hd` не имеет и не войдёт.
5. Google не передаёт группы и MFA в ID token: ограничьте круг пользователей
   приложения средствами Admin console, 2-Step Verification включите политикой
   Workspace. `CC_OIDC_REQUIRE_MFA=true` для google сервер не примет.

```dotenv
CC_OIDC_PRESET=google
CC_AUTH_ALLOWED_DOMAINS=acme.com
CC_OIDC_CLIENT_ID=<client-id>.apps.googleusercontent.com
```

### Okta

1. Admin Console → **Applications → Create App Integration → OIDC - OpenID
   Connect → Web Application**. Grant type: Authorization Code и **Refresh Token**.
   Sign-in redirect URI — `https://sync.acme.com/v1/auth/oidc/callback`.
2. **Client authentication: Client secret**, **Require PKCE as additional
   verification** включите. Client ID и secret — в `CC_OIDC_CLIENT_ID` и файл.
3. **Assignments**: назначьте приложение группе. Для claim групп в ID token:
   **Sign On → OpenID Connect ID Token → Groups claim** — имя `groups`, фильтр
   Matches regex `ConsoleCrypt.*` (для собственного authorization server claim
   `groups` добавляется в **Security → API → Authorization Servers → Claims**).
4. Issuer — домен org (`https://acme.okta.com`) или authorization server
   (`https://acme.okta.com/oauth2/default`); он должен точно совпадать с `issuer`
   в discovery. Для `offline_access` на собственном authorization server scope
   должен быть разрешён политикой доступа.

```dotenv
CC_OIDC_PRESET=okta
CC_OIDC_ISSUER=https://acme.okta.com
CC_OIDC_CLIENT_ID=<client-id>
CC_OIDC_REQUIRED_CLAIM=groups=ConsoleCrypt-Users
```

### Любой другой OIDC-провайдер

Используйте `CC_OIDC_PRESET=generic` (значение по умолчанию). Проверьте:

1. Клиент — confidential, Authorization Code + PKCE S256, Refresh Token,
   redirect URI `https://sync.acme.com/v1/auth/oidc/callback`.
2. ID token подписан RS256, PS256 или ES256 и содержит `sub`, адрес почты
   (`email` или другой claim — `CC_OIDC_EMAIL_CLAIM`) и, если нужно, claim
   группы для `CC_OIDC_REQUIRED_CLAIM`.
3. Discovery `<issuer>/.well-known/openid-configuration` доступен серверу по
   HTTPS (внутренний CA — `CC_OIDC_CA_FILE`), его `issuer` посимвольно равен
   `CC_OIDC_ISSUER`.
4. Если IdP не принимает секрет в заголовке Basic, задайте
   `CC_OIDC_TOKEN_AUTH_METHOD=client_secret_post`.
5. Для MFA узнайте, какие `amr` или `acr` IdP пишет в ID token; нестандартные
   значения `acr` перечислите в `CC_OIDC_MFA_ACR_VALUES`.

```dotenv
CC_OIDC_PRESET=generic
CC_OIDC_ISSUER=https://idp.acme.com
CC_OIDC_CLIENT_ID=consolecrypt-server
CC_OIDC_SCOPES=openid email profile offline_access
CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users
```

## Active Directory и LDAP

1. **Сервисная учётка** с минимальными правами: обычный пользователь домена
   может читать каталог, административные права не нужны. Пароль без срока
   действия (или с вашей процедурой смены: обновите файл и перезапустите сервер):

   ```powershell
   New-ADUser -Name svc-consolecrypt -Path "OU=Service,DC=acme,DC=local" `
     -AccountPassword (Read-Host -AsSecureString) -Enabled $true -PasswordNeverExpires $true
   ```

   Пароль — в файл `ldap-bind-password`, DN — в `CC_LDAP_BIND_DN`.
2. **LDAPS**: у контроллеров домена должен быть сертификат (AD CS «Domain
   Controller» или «Kerberos Authentication»). Экспортируйте корневой сертификат CA
   в PEM — `CC_LDAP_CA_FILE`. Имя в `CC_LDAP_URL` должно совпадать с именем в
   сертификате контроллера (DNS-имя, а не IP). Проверить цепочку можно с хоста
   сервера: `openssl s_client -connect dc1.acme.local:636 -CAfile ad-ca.pem </dev/null`
   (ожидается `Verify return code: 0 (ok)`). Если доступен только порт 389,
   используйте `ldap://dc1.acme.local:389` и `CC_LDAP_STARTTLS=true`; простой
   `ldap://` без TLS сервер не примет.
3. **Фильтр поиска**: по умолчанию пользователь находится по `mail`,
   `userPrincipalName` или `sAMAccountName`, поэтому вводить можно email, UPN или
   `ACME\alice`. Если поиск находит несколько записей, вход отклоняется. Свой
   фильтр обязан содержать `{login}`.
4. **Группа доступа**, например `CN=ConsoleCrypt,OU=Groups,DC=acme,DC=local`;
   вложенные группы учитываются через правило AD `LDAP_MATCHING_RULE_IN_CHAIN`.
   Членство проверяется при входе и при каждой перепроверке.
5. **Стабильный идентификатор** — `objectGUID`: смена email, UPN или
   переименование учётки не ломает привязку. Для `admin identity link` берите его
   так: `(Get-ADUser alice).ObjectGUID`. Отключённые учётки (`userAccountControl`
   с флагом `ACCOUNTDISABLE`) не входят и теряют сессии при перепроверке.
6. **Проверка поиска** до включения режима (пароль запрашивается, а не
   передаётся аргументом):

   ```sh
   ldapsearch -H ldaps://dc1.acme.local:636 -D 'CN=svc-consolecrypt,OU=Service,DC=acme,DC=local' -W \
     -b 'DC=acme,DC=local' '(sAMAccountName=alice)' mail objectGUID userAccountControl
   ```

7. **Политика блокировки домена**: задайте `CC_LDAP_MAX_FAILURES` меньше порога
   блокировки (см. ниже).

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

Простой `ldap://` без STARTTLS сервер отклоняет при старте: пароль домена не должен
идти по сети открытым текстом. Пустой пароль отклоняется до обращения к AD (иначе
это был бы анонимный bind).

Сервер рассчитан на Active Directory. С другим LDAP-каталогом задайте свой
`CC_LDAP_USER_FILTER`, `CC_LDAP_EMAIL_ATTR` и стабильный `CC_LDAP_ID_ATTR`
(например, `entryUUID`); проверка `CC_LDAP_REQUIRED_GROUP` использует правило AD
`LDAP_MATCHING_RULE_IN_CHAIN`, которое другой каталог может не поддерживать —
проверьте вход командой `admin auth test --login`.

**Защита учёток AD от блокировки через сервер.** Неудачные bind учитываются в
политике блокировки домена, поэтому злоумышленник мог бы блокировать сотрудников
через `/v1/auth/ldap/login`. Сервер считает попытки в PostgreSQL (общие для всех
реплик) — на введённый логин и на найденного пользователя AD (разные написания
одного логина — email, UPN, `DOMAIN\user` — считаются вместе): после
`CC_LDAP_MAX_FAILURES` попыток за `CC_LDAP_FAILURE_WINDOW_MINUTES` дальнейшие
попытки отклоняются **без обращения к AD** (`429 rate_limited` с `Retry-After`),
пока окно не пройдёт. Неизвестный логин ведёт себя так же, существование
пользователя не раскрывается. Успешный вход сбрасывает счётчик. Отдельно
считаются неудачные входы с одного IP (`CC_LDAP_MAX_FAILURES_PER_IP`).

> **Важно:** `CC_LDAP_MAX_FAILURES` должен быть **меньше порога блокировки учётной
> записи** в политике домена (Account lockout threshold), а
> `CC_LDAP_FAILURE_WINDOW_MINUTES` — не меньше окна сброса счётчика блокировки
> (Reset account lockout counter after). Иначе вход через сервер всё ещё может
> заблокировать учётку. Пример: порог домена 5 попыток за 30 минут →
> `CC_LDAP_MAX_FAILURES=3`, `CC_LDAP_FAILURE_WINDOW_MINUTES=30`.

## Первый вход и привязка аккаунтов

При каждом входе сервер ищет аккаунт так:

1. **Известная учётная запись** (`(iss, sub)` для OIDC, `objectGUID` для LDAP) —
   вход в привязанный аккаунт. Если адрес почты в IdP/AD изменился и не занят
   другим аккаунтом, адрес аккаунта обновляется.
2. **Новая учётная запись, а аккаунт с тем же адресом уже есть** (например,
   созданный в режиме standard). Он привязывается автоматически, только если:
   домен адреса есть в `CC_AUTH_ALLOWED_DOMAINS`; у аккаунта ещё нет внешней
   привязки; IdP не сообщил `email_verified=false`; аккаунт не отключён. Пароль
   аккаунта удаляется, сеансы, открытые паролем, завершаются, устройства и
   хранилища сохраняются. Иначе вход получает `409 identity_conflict` с причиной в
   журнале: `linked_to_other_identity`, `link_requires_allowed_domain` или
   `email_not_verified` — привяжите вручную:

   ```sh
   consolecrypt-server admin identity link --email alice@acme.com --subject <sub или objectGUID>
   ```

   `--subject` — значение claim `sub` из ID token пользователя (в Keycloak — ID
   пользователя в консоли, в Okta — id пользователя `00u…`; у Entra ID `sub` не
   совпадает с Object ID `oid`) или `objectGUID` для AD. Без `--issuer` используется
   настроенный `CC_OIDC_ISSUER` или base DN.
3. **Новая учётная запись без аккаунта** — создаётся аккаунт с подтверждённым
   адресом, если `CC_AUTH_AUTO_CREATE=true`. При `false` вход получает `403` с
   причиной `not_provisioned`: тогда входят только аккаунты, созданные заранее
   (в режиме standard) или привязанные командой `admin identity link`.

У учётной записи без адреса почты (`email_missing`) или с доменом вне
`CC_AUTH_ALLOWED_DOMAINS` вход отклоняется с `403 domain_not_allowed`.

## Переход со standard на enterprise

1. Обновите сервер до 0.2.0 или новее и сделайте резервную копию базы (миграция
   `0011_enterprise_auth` только добавляет таблицы и делает
   `users.password_hash` необязательным).
2. Зарегистрируйте приложение в IdP или создайте сервисную учётку в AD (рецепты
   выше), положите секреты в файлы/Secret.
3. Проверьте список аккаунтов: `admin list-users`. Решите, какие домены
   перечислить в `CC_AUTH_ALLOWED_DOMAINS`, чтобы существующие аккаунты
   привязались сами.
4. Включите `CC_AUTH_MODE=enterprise` и перезапустите сервер. Проверьте
   `admin auth status`, `admin auth test` и `"auth": {"mode": "enterprise", …}` в
   `/v1/meta`. Обновите приложения до версии с поддержкой enterprise-входа
   (клиент 0.9.0).
5. Выполните тестовый вход своим аккаунтом и проверьте `admin list-users`
   (колонка `sign_in`).

После включения:

- регистрация, вход по паролю аккаунта, сброс и смена пароля, подтверждение почты
  отвечают `403 enterprise_auth_required`; старые приложения показывают ошибку
  входа с текстом «обновите приложение»;
- сессии, открытые паролем до переключения, не обновляются
  (`enterprise_auth_required`): пользователь один раз входит через IdP/AD;
- существующие аккаунты привязываются по правилам
  [выше](#первый-вход-и-привязка-аккаунтов);
- устройства и хранилища аккаунта сохраняются; устройство, которое уже было
  зарегистрировано, входит с подписью ключа устройства, как раньше.

## Проверка при старте и команды администратора

При старте сервер проверяет конфигурацию и падает с понятной ошибкой: для OIDC —
файлы секретов, discovery, совпадение `issuer`, JWKS с ключами RS256/PS256/ES256;
для LDAP — файлы, соединение, TLS, bind сервисной учётки, наличие base DN и группы.

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
учитывается в политике блокировки домена. В Docker Compose и Kubernetes команды
запускаются внутри контейнера: `cc_compose exec -T server
/usr/local/bin/consolecrypt-server admin auth status` или `kubectl -n consolecrypt
exec deployment/consolecrypt -- /usr/local/bin/consolecrypt-server admin auth status`.

## Журнал

В журнал сервера (и в `audit_events`) пишутся входы (`login`, `metadata.method` =
`oidc`/`ldap`), создание аккаунтов, привязки (`identity_linked`/`identity_unlinked`),
отказы с причиной (`login_failed`, `metadata.reason`: `domain_not_allowed`,
`email_missing`, `group_required`, `mfa_required`, `account_disabled`,
`not_provisioned`, `linked_to_other_identity`, `link_requires_allowed_domain`,
`email_not_verified`, а для неверного ID token — `iss`, `aud`, `azp`, `exp`,
`iat`, `nbf`, `nonce`, `sub`, `unknown_kid`, `bad_signature`, `unsupported_alg`,
`malformed`), отзывы сессий перепроверкой (`enterprise_access_revoked`) и
администратором. Пароли, client secret, токены и коды входа в журнал не попадают.
Метрики: `cc_enterprise_logins_total{method,result}`,
`cc_enterprise_rechecks_total{result}`, `cc_ldap_lockout_guard_total{scope}`,
`cc_oidc_jwks_refetch_total`.

## Развёртывание

Полные примеры для каждого способа установки — в
[HOSTING.md](HOSTING.md#пример-корпоративный-вход-через-entra-id).

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
    clientId: <client-id>
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

Secret монтируется только для чтения в `/run/secrets/consolecrypt-auth`
(`defaultMode: 0440`, группа pod — 65532); chart сам подставляет пути `*_FILE`,
проверяет обязательные поля и отклоняет `ldap://` без `starttls: true` и OIDC без
`config.publicUrl` с `https://`. Остальные ключи (`scopes`, `emailClaim`,
`requireMfa`, `mfaAcrValues`, `tokenAuthMethod`, `caKey`, `userFilter`,
`emailAttr`, `idAttr`, `timeoutSecs`, `maxFailures`, `failureWindowMinutes`,
`maxFailuresPerIp`) описаны в `values.yaml` и [CONFIGURATION.md](CONFIGURATION.md).

### Docker Compose

Основной `compose.yaml` из исходников не меняется. Настройки и секреты
enterprise-режима держите в **приватном** каталоге установки рядом с
`server.env` (`$CC_INSTALL_DIR` из [HOSTING.md](HOSTING.md#docker-compose)), а не в
клоне репозитория.

1. Сохраните секреты OIDC (или пароль служебной учётки LDAP и CA каталога) в
   `$CC_INSTALL_DIR/secrets/`. Compose без Swarm монтирует их как обычные файлы с
   владельцем и правами хоста, а сервер работает как UID 65532 — сделайте файлы
   читаемыми только для него:

   ```sh
   mkdir -p "$CC_INSTALL_DIR/secrets"
   ( umask 077
     openssl rand -hex 32 > "$CC_INSTALL_DIR/secrets/oidc-token-key"
     # client secret из IdP, без перевода строки:
     read -rs CC_SECRET && printf '%s' "$CC_SECRET" > "$CC_INSTALL_DIR/secrets/oidc-client-secret" )
   sudo chown 65532:65532 "$CC_INSTALL_DIR"/secrets/*
   sudo chmod 0400 "$CC_INSTALL_DIR"/secrets/*
   ```

2. Создайте `$CC_INSTALL_DIR/compose.override.yaml`. Пути указывайте
   **абсолютными**: относительные Compose отсчитывает от каталога первого
   файла, то есть от исходников. Замените `/home/admin/.config/consolecrypt-docker`
   на свой `$CC_INSTALL_DIR`:

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
       file: /home/admin/.config/consolecrypt-docker/secrets/oidc-client-secret
     oidc-token-key:
       file: /home/admin/.config/consolecrypt-docker/secrets/oidc-token-key
   ```

3. Подключите override-файл. Автоматически Compose подхватывает
   `compose.override.yaml` только из каталога проекта и только без `-f`; функция
   `cc_compose` из HOSTING.md передаёт `-f`, поэтому добавьте второй `-f`:

   ```sh
   cc_compose() {
     docker compose --env-file "$CC_INSTALL_DIR/server.env" \
       -f "$CC_COMPOSE_FILE" -f "$CC_INSTALL_DIR/compose.override.yaml" \
       --profile https "$@"
   }
   cc_compose config --quiet
   cc_compose up -d --wait --wait-timeout 180 server
   curl --fail --silent --show-error "$CC_API_ORIGIN/v1/meta" | python3 -m json.tool
   ```

   В `/v1/meta` должно появиться `"auth": {"mode": "enterprise", …}`. Проверьте
   настройку командой `cc_compose exec -T server /usr/local/bin/consolecrypt-server
   admin auth test`. Для LDAP вместо `CC_OIDC_*` задайте `CC_LDAP_*` и секреты
   `ldap-bind-password` (`CC_LDAP_BIND_PASSWORD_FILE`) и при необходимости
   `ldap-ca.pem` (`CC_LDAP_CA_FILE`).

Используйте эту же функцию для всех дальнейших команд (обновление, `admin`,
резервные копии): без второго `-f` Compose пересоздаст сервер в стандартном
режиме.

### Бинарный файл

Те же ключи в приватном JSON (`--config /etc/consolecrypt/server.json`, права
0600) или в окружении службы; пути `*_FILE` указывают на файлы с правами 0600,
принадлежащие пользователю службы.

## Диагностика ошибок

| Что видно | Причина | Что сделать |
|---|---|---|
| Сервер не стартует: `OIDC sign-in requires CC_PUBLIC_URL (https://…)` | нет `CC_PUBLIC_URL` или он не `https://` | задайте публичный адрес сервера; в Helm — `config.publicUrl` |
| `CC_OIDC_ISSUER: Entra ID multi-tenant endpoints … are not allowed` | issuer с `/common`, `/organizations` или `/consumers` | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `CC_OIDC_ISSUER: for adfs expected …/adfs`, `for keycloak expected …/realms/<realm>` | issuer не соответствует пресету | скопируйте `issuer` из discovery IdP |
| `OIDC discovery: issuer mismatch` | `CC_OIDC_ISSUER` отличается от `issuer` в discovery (часто — завершающий `/`) | скопируйте значение посимвольно |
| `OIDC discovery at …`: ошибка запроса или сертификата | сервер не достаёт IdP по HTTPS или не доверяет его CA | проверьте DNS, исходящий доступ и proxy; внутренний CA — `CC_OIDC_CA_FILE` |
| `… none of RS256, PS256, ES256` или `does not support PKCE S256` | IdP подписывает токены другим алгоритмом или без PKCE S256 | включите RS256/ES256 и PKCE S256 для клиента |
| `CC_OIDC_CLIENT_SECRET_FILE (…): cannot open the file` / `file is empty` | неверный путь, нет прав у UID 65532, пустой файл | проверьте монтирование, `chown 65532:65532`, `chmod 0400`, содержимое |
| `CC_OIDC_TOKEN_KEY_FILE (…): expected 32 random bytes …` | ключ не 64 hex, не base64 32 байт | `openssl rand -hex 32 > oidc-token-key` |
| `CC_OIDC_PRESET=google requires CC_AUTH_ALLOWED_DOMAINS` | для Google нет списка доменов | задайте домены Workspace |
| IdP показывает ошибку redirect URI | в IdP зарегистрирован другой адрес возврата | `CC_PUBLIC_URL` + `/v1/auth/oidc/callback`, тип клиента Web |
| `403 domain_not_allowed` (`email_missing`) | домен вне `CC_AUTH_ALLOWED_DOMAINS` или в ID token нет адреса | проверьте `CC_OIDC_EMAIL_CLAIM` (Entra: `email` vs `preferred_username`), атрибут mail, список доменов |
| `403 group_required` | нет claim из `CC_OIDC_REQUIRED_CLAIM` или пользователь вне группы `CC_LDAP_REQUIRED_GROUP` | добавьте claim в **ID token**, проверьте имя (Keycloak: Full group path Off), Entra: overage > 200 групп → app roles |
| `403 mfa_required` | IdP не сообщил MFA в `amr`/`acr` | включите MFA в политике IdP; при нестандартном `acr` — `CC_OIDC_MFA_ACR_VALUES`; иначе выключите `CC_OIDC_REQUIRE_MFA` |
| `409 identity_conflict` | адрес принадлежит аккаунту, привязанному к другой учётной записи, или домена нет в списке, или `email_verified=false` | `admin identity link` / `unlink`; добавьте домен в `CC_AUTH_ALLOWED_DOMAINS` |
| `403` с причиной `not_provisioned` | `CC_AUTH_AUTO_CREATE=false`, аккаунта нет | создайте/привяжите аккаунт или включите автосоздание |
| `503 idp_unavailable` | IdP/каталог недоступен дольше `CC_AUTH_RECHECK_GRACE_HOURS` | восстановите доступ; `admin auth status` покажет последнюю проверку |
| Сотрудник отключён, но ещё синхронизируется | перепроверка ещё не прошла или нет refresh token IdP | подождите до `CC_AUTH_RECHECK_MINUTES` + 1 мин; `admin session revoke`; `admin auth test --login` |
| `CC_LDAP_URL: plain ldap:// is refused` | `ldap://` без STARTTLS | `ldaps://…:636` или `CC_LDAP_STARTTLS=true` |
| `LDAP …: cannot connect (network or TLS certificate problem)` | сеть, порт, имя не совпадает с сертификатом, не тот CA | DNS-имя из сертификата, `CC_LDAP_CA_FILE`, `openssl s_client` |
| `LDAP TLS: no system root certificates found` | в образе нет нужного корня | задайте `CC_LDAP_CA_FILE` |
| `service account bind rejected (check CC_LDAP_BIND_DN and password)` | неверный DN или пароль сервисной учётки, учётка отключена | проверьте DN, файл пароля без лишних символов, состояние учётки |
| `LDAP base DN … not found` / `CC_LDAP_REQUIRED_GROUP … not found` | опечатка в DN | скопируйте DN из каталога |
| `401 invalid_credentials` при верном пароле | учётка отключена, заблокирована, пароль истёк или поиск нашёл несколько записей | проверьте учётку в AD; уточните `CC_LDAP_USER_FILTER` |
| `429 rate_limited` при входе LDAP | сработала защита от блокировки (`CC_LDAP_MAX_FAILURES` или `CC_LDAP_MAX_FAILURES_PER_IP`) | дождитесь окна `CC_LDAP_FAILURE_WINDOW_MINUTES`; проверьте, кто подбирает пароль |

## Возврат в режим standard

**Аварийного входа по паролю в enterprise-режиме нет.** Если IdP или AD недоступен
или настроен неверно, сначала `admin auth status` и `admin auth test`. Чтобы
временно пустить людей по паролю:

1. Задайте `CC_AUTH_MODE=standard` (в Helm — `auth.mode: standard`) и перезапустите
   сервер. Ключи `CC_OIDC_*` и `CC_LDAP_*` можно не удалять: в standard они не
   читаются, поэтому обратное переключение — смена одного ключа.
2. У привязанных аккаунтов пароля нет: задайте его командой
   `admin set-password --email … --password-stdin` (или выдайте код
   `admin reset-token --email …`). Пароль аккаунта по-прежнему не открывает
   хранилище.
3. Привязки к IdP/AD сохраняются. При повторном включении enterprise вход снова
   только через IdP/AD, а пароль удаляется при следующем входе пользователя.
   Чтобы снять привязку навсегда — `admin identity unlink --email …`.

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

---

## English

Since server **0.2.0** (protocol **1.9**) the sync server has two sign-in modes:

- **standard** (default, as before): registration and sign-in with an e-mail
  address and an account password, address verification, password reset;
- **enterprise**: sign-in only through the organisation's identity source — an
  OpenID Connect IdP (Entra ID, AD FS, Keycloak, Google Workspace, Okta, any OIDC
  provider) or Active Directory / LDAP (domain login and password).

Only **how an account signs in** changes. Vaults, encryption, devices, new-device
protection, sharing and teams work as before. There is no directory sync, no
group/role sync, no SCIM and no admin console. The mode is part of the
open-source server, with no separate build or licence. Users need client 0.9.0 or
later. Every key with its Helm path and validation is listed in
[CONFIGURATION.md](CONFIGURATION.md#enterprise-sign-in-cc_auth_-cc_oidc_-cc_ldap_).

### Encryption does not change

The account password — or now the IdP or AD — only proves identity to the server.
Data is opened by the vault passphrase (Argon2id on the client), the Recovery Key
or approval from a trusted device. Neither the IdP, AD nor the server receives
anything that decrypts a vault. After an IdP/AD sign-in the device is an ordinary
new device, covered by new-device protection.

### How it works

**OIDC.** The server is a confidential client of the IdP and the app is a public
client of the server, with PKCE (S256) on both legs. The app opens the system
browser at `/v1/auth/oidc/start`; the server redirects to the IdP with its own
`state`, `nonce` and PKCE; the IdP returns the browser to
`https://<server>/v1/auth/oidc/callback`; the server exchanges the code, verifies
the ID token (RS256/PS256/ES256 signature via JWKS, exact `iss`, `aud`, `azp`,
`exp`, `iat`, `nonce`, 60 s clock skew), the domain, group and MFA, and finds or
creates the account; the browser returns to the app with a one-time `login_code`
(60 s, bound to the app's PKCE and device). Only the server's
`/v1/auth/oidc/callback` is registered at the IdP; the app's loopback and
`consolecrypt://auth/callback` addresses are not.

**LDAP / AD.** The app sends the login (e-mail, UPN or `DOMAIN\user`) and the
domain password to `POST /v1/auth/ldap/login` over TLS. The server finds the user
with the service account, then binds as that user's DN with the given password.
The password is never stored or logged. "No such user" and "wrong password" look
the same.

**Account link.** An account is tied to an external identity — OIDC `(iss, sub)`
or the AD `objectGUID`. The e-mail is only an attribute: a changed address does
not break the account, and someone else's account with the same address is never
taken over (`identity_conflict`).

**Re-checks (leavers).** At most every `CC_AUTH_RECHECK_MINUTES` the server asks
the IdP (by refreshing the IdP refresh token) or AD (by searching the
`objectGUID`) whether the user may still work — on app token refresh and in a
background pass every minute for accounts with active sessions. A disabled or
deleted user, a user who left the group or lost the required claim, has all
sessions revoked; the app receives `account_disabled` and locks the synced
profile within `CC_AUTH_RECHECK_MINUTES` + 1 minute. While the IdP or AD is
unreachable, sessions keep working for `CC_AUTH_RECHECK_GRACE_HOURS` after the
last successful check; then refresh answers `503 idp_unavailable` (without
revoking) until the source is back.

### What the server needs from the IdP

| What | Value | Key |
|---|---|---|
| Public server URL | `https://sync.acme.com` (what users enter in the client, without `/v1`) | `CC_PUBLIC_URL` |
| Redirect URI at the IdP | `https://sync.acme.com/v1/auth/oidc/callback` — exactly `CC_PUBLIC_URL` + `/v1/auth/oidc/callback`, client type "Web" / confidential | — |
| Issuer | exactly as in `https://<issuer>/.well-known/openid-configuration` (the `issuer` field, with or without a trailing `/` as the IdP writes it) | `CC_OIDC_ISSUER` |
| Client ID | the registered application's id | `CC_OIDC_CLIENT_ID` |
| Client secret | a file with the secret; `client_secret_basic` or `client_secret_post` | `CC_OIDC_CLIENT_SECRET_FILE`, `CC_OIDC_TOKEN_AUTH_METHOD` |
| Refresh token sealing key | a file with 32 random bytes (`openssl rand -hex 32`) | `CC_OIDC_TOKEN_KEY_FILE` |
| Grant types | Authorization Code with PKCE S256, and Refresh Token | — |
| Scopes | `openid email profile offline_access` (presets have their own) | `CC_OIDC_SCOPES` |
| Claims in the **ID token** | `sub`; an e-mail (`email`, `preferred_username` or `upn`); `groups` or `roles` to restrict access; `amr`/`acr` for MFA | `CC_OIDC_EMAIL_CLAIM`, `CC_OIDC_REQUIRED_CLAIM`, `CC_OIDC_REQUIRE_MFA` |

At start-up the server checks: discovery over HTTPS, a matching `issuer`, HTTPS
`authorization_endpoint`, `token_endpoint` and `jwks_uri`, at least one RS256,
PS256 or ES256 key in the JWKS, and S256 if the IdP lists PKCE methods. Claims are
read only from the ID token (no userinfo call), so groups, roles and the e-mail
must be in the ID token. The IdP **refresh token** powers leaver re-checks; without
it users simply sign in through the IdP again every `CC_AUTH_RECHECK_GRACE_HOURS`,
and `admin auth test --login <email>` reports `no IdP refresh token stored
(request offline access)`.

### OIDC recipes

All recipes assume the server at `https://sync.acme.com`, so the IdP redirect URI
is `https://sync.acme.com/v1/auth/oidc/callback`. Prepare the secret files first
(owned by the server process user — UID 65532 in the container):

```sh
install -d -m 700 /etc/consolecrypt/secrets
( umask 077
  openssl rand -hex 32 > /etc/consolecrypt/secrets/oidc-token-key
  # the IdP client secret, without a newline and without echoing it:
  read -rs CC_SECRET && printf '%s' "$CC_SECRET" > /etc/consolecrypt/secrets/oidc-client-secret
  unset CC_SECRET )
```

Do not rotate `oidc-token-key` without need: stored IdP refresh tokens become
unreadable and users sign in once more. Many IdPs expire client secrets: set a
reminder, then replace the file and restart the server. Keys shared by every
recipe:

```dotenv
CC_AUTH_MODE=enterprise
CC_AUTH_PROVIDER=oidc
CC_AUTH_DISPLAY_NAME=Acme SSO
CC_AUTH_ALLOWED_DOMAINS=acme.com
CC_PUBLIC_URL=https://sync.acme.com
CC_OIDC_CLIENT_SECRET_FILE=/etc/consolecrypt/secrets/oidc-client-secret
CC_OIDC_TOKEN_KEY_FILE=/etc/consolecrypt/secrets/oidc-token-key
```

#### Microsoft Entra ID

1. Microsoft Entra admin center → **App registrations → New registration**: name
   "ConsoleCrypt Sync", **Accounts in this organizational directory only**
   (single tenant), redirect URI on the **Web** platform:
   `https://sync.acme.com/v1/auth/oidc/callback`. Do not pick "SPA" or "Mobile and
   desktop" — the server is a confidential client.
2. On **Overview** copy the **Application (client) ID** → `CC_OIDC_CLIENT_ID` and
   the **Directory (tenant) ID** → issuer
   `https://login.microsoftonline.com/<tenant-id>/v2.0`.
3. **Certificates & secrets → Client secrets → New client secret**: store the value
   (not the Secret ID) in `oidc-client-secret`. Note its expiry date.
4. **API permissions**: Microsoft Graph delegated `openid`, `email`, `profile`,
   `offline_access`; **Grant admin consent** so employees see no consent prompt.
5. **Token configuration → Add optional claim → ID → `email`**. The preset uses
   `preferred_username` (usually the UPN) as the e-mail; if UPNs differ from mail
   addresses, set `CC_OIDC_EMAIL_CLAIM=email` (users need the mail attribute).
6. Restrict access — one of:
   - **App roles** (recommended): **App roles → Create app role**, allowed member
     types Users/Groups, value `ConsoleCrypt.User`; then **Enterprise applications
     → ConsoleCrypt Sync → Users and groups → Add user/group** and assign the role
     to a group. On the server: `CC_OIDC_REQUIRED_CLAIM=roles=ConsoleCrypt.User`;
   - **groups claim**: **Token configuration → Add groups claim → Security
     groups**, **Group ID** in the ID token; on the server
     `CC_OIDC_REQUIRED_CLAIM=groups=<group-object-id>`. For users in more than 200
     groups Entra omits `groups` (overage) and the server logs a warning — use app
     roles or "Groups assigned to the application".
   Also set **Enterprise applications → Properties → Assignment required = Yes** so
   Entra issues no token to unassigned users.
7. MFA: require it with a **Conditional Access** policy for the app.
   `CC_OIDC_REQUIRE_MFA=true` additionally checks `amr`/`acr` in the ID token;
   enable it only after a test sign-in succeeds — if the IdP does not report the
   method, every sign-in gets `mfa_required`.

```dotenv
CC_OIDC_PRESET=entra
CC_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
CC_OIDC_CLIENT_ID=<application-client-id>
CC_OIDC_REQUIRED_CLAIM=roles=ConsoleCrypt.User
```

The preset refuses `/common`, `/organizations` and `/consumers` issuers: a tenant
id is required. A user disabled in Entra can no longer refresh, and the server
revokes their sessions at the next re-check.

#### AD FS 2016+

1. AD FS Management → **Application Groups → Add Application Group → Server
   application** (or "Web browser accessing a web application" with a confidential
   client). Copy the Client Identifier → `CC_OIDC_CLIENT_ID`. Redirect URI:
   `https://sync.acme.com/v1/auth/oidc/callback`.
2. **Configure Application Credentials → Generate a shared secret** → the
   `oidc-client-secret` file.
3. Add a **Web API** to the group with identifier = the server's client id, an
   access control policy (e.g. "Permit specific group") and the permissions
   `openid`, `profile`, `email`, `allatclaims`.
4. Issuance Transform Rules of the Web API: "Send LDAP Attributes as Claims" —
   `E-Mail-Addresses → email`, `User-Principal-Name → upn`; to restrict by group,
   "Send Group Membership as a Claim" (e.g. `group` = `ConsoleCrypt`). The
   `allatclaims` scope (in the preset) puts these claims into the ID token.
5. If the AD FS certificate comes from an internal CA, put the root certificate
   (PEM) in `CC_OIDC_CA_FILE`.
6. The issuer is `https://adfs.acme.com/adfs` — check the `issuer` field of
   `https://adfs.acme.com/adfs/.well-known/openid-configuration`.

```dotenv
CC_OIDC_PRESET=adfs
CC_OIDC_ISSUER=https://adfs.acme.com/adfs
CC_OIDC_CLIENT_ID=<client-id>
CC_OIDC_EMAIL_CLAIM=upn
CC_OIDC_REQUIRED_CLAIM=group=ConsoleCrypt
CC_OIDC_CA_FILE=/etc/consolecrypt/secrets/adfs-ca.pem
# CC_OIDC_TOKEN_AUTH_METHOD=client_secret_post   # if AD FS rejects Basic
```

AD FS reports MFA in `amr` as `http://schemas.microsoft.com/claims/multipleauthn`,
which `CC_OIDC_REQUIRE_MFA=true` accepts.

#### Keycloak

1. Pick the realm (e.g. `acme`) → **Clients → Create client**: OpenID Connect,
   Client ID `consolecrypt-server`, **Client authentication: On**, Standard flow:
   On, Direct access grants: Off.
2. **Valid redirect URIs**: `https://sync.acme.com/v1/auth/oidc/callback`.
   **Advanced → Proof Key for Code Exchange Code Challenge Method: S256**.
3. **Credentials** → client secret → the secret file.
4. E-mail: the `email` and `profile` client scopes must be Default for the client.
   Keycloak sends `email_verified`; an unverified address blocks automatic linking
   of an existing password account (`email_not_verified`).
5. Group: **Client scopes → consolecrypt-server-dedicated → Add mapper → By
   configuration → Group Membership**, Token Claim Name `groups`, **Full group
   path: Off** (otherwise the value is `/consolecrypt-users`), Add to ID token: On.
   Then `CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users`. A client role with the
   "User Client Role" mapper works too.
6. Disable a user with **Users → Enabled: Off**: their refresh token stops working
   and the server revokes the sessions at the next re-check.

```dotenv
CC_OIDC_PRESET=keycloak
CC_OIDC_ISSUER=https://sso.acme.com/realms/acme
CC_OIDC_CLIENT_ID=consolecrypt-server
CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users
```

#### Google Workspace

1. Google Cloud Console (a project of your organisation) → **APIs & Services →
   OAuth consent screen**: User type **Internal**, scopes `openid`, `email`,
   `profile`.
2. **Credentials → Create credentials → OAuth client ID → Web application**,
   authorized redirect URI `https://sync.acme.com/v1/auth/oidc/callback`. Client ID
   → `CC_OIDC_CLIENT_ID`, client secret → the file.
3. No issuer is needed (`https://accounts.google.com`). The preset requests offline
   access itself (`access_type=offline`, `prompt=consent`); Google rejects
   `offline_access` in `CC_OIDC_SCOPES` and the server refuses to start with it.
4. `CC_AUTH_ALLOWED_DOMAINS` is mandatory: only Workspace accounts whose ID token
   `hd` is in the list may sign in. A consumer Google account with a
   corporate-looking address has no `hd` and is refused.
5. Google puts neither groups nor MFA into the ID token: restrict who may use the
   app in the Admin console and enforce 2-Step Verification by Workspace policy.
   The server refuses `CC_OIDC_REQUIRE_MFA=true` for google.

```dotenv
CC_OIDC_PRESET=google
CC_AUTH_ALLOWED_DOMAINS=acme.com
CC_OIDC_CLIENT_ID=<client-id>.apps.googleusercontent.com
```

#### Okta

1. Admin Console → **Applications → Create App Integration → OIDC - OpenID
   Connect → Web Application**. Grant types: Authorization Code and **Refresh
   Token**. Sign-in redirect URI: `https://sync.acme.com/v1/auth/oidc/callback`.
2. **Client authentication: Client secret**; turn on **Require PKCE as additional
   verification**. Client ID and secret → `CC_OIDC_CLIENT_ID` and the file.
3. **Assignments**: assign the app to a group. For a groups claim in the ID token:
   **Sign On → OpenID Connect ID Token → Groups claim** named `groups`, filter
   Matches regex `ConsoleCrypt.*` (on a custom authorization server add the
   `groups` claim under **Security → API → Authorization Servers → Claims**).
4. The issuer is the org domain (`https://acme.okta.com`) or an authorization
   server (`https://acme.okta.com/oauth2/default`) and must match `issuer` in
   discovery exactly. On a custom authorization server the access policy must
   allow the `offline_access` scope.

```dotenv
CC_OIDC_PRESET=okta
CC_OIDC_ISSUER=https://acme.okta.com
CC_OIDC_CLIENT_ID=<client-id>
CC_OIDC_REQUIRED_CLAIM=groups=ConsoleCrypt-Users
```

#### Any other OIDC provider

Use `CC_OIDC_PRESET=generic` (the default) and check that: the client is
confidential with Authorization Code + PKCE S256 and Refresh Token and the
redirect URI above; the ID token is signed with RS256, PS256 or ES256 and carries
`sub`, an e-mail (`email` or another claim — `CC_OIDC_EMAIL_CLAIM`) and, if
needed, the group claim for `CC_OIDC_REQUIRED_CLAIM`; discovery
`<issuer>/.well-known/openid-configuration` is reachable over HTTPS (internal CA:
`CC_OIDC_CA_FILE`) and its `issuer` equals `CC_OIDC_ISSUER`. If the IdP rejects
the secret in a Basic header, set `CC_OIDC_TOKEN_AUTH_METHOD=client_secret_post`.
For MFA find out which `amr`/`acr` the IdP writes and list non-standard `acr`
values in `CC_OIDC_MFA_ACR_VALUES`.

```dotenv
CC_OIDC_PRESET=generic
CC_OIDC_ISSUER=https://idp.acme.com
CC_OIDC_CLIENT_ID=consolecrypt-server
CC_OIDC_SCOPES=openid email profile offline_access
CC_OIDC_REQUIRED_CLAIM=groups=consolecrypt-users
```

### Active Directory and LDAP

1. **Service account** with minimal rights: an ordinary domain user can read the
   directory; no admin rights are needed. Use a non-expiring password (or your
   rotation procedure: update the file, restart the server). Store the password in
   `ldap-bind-password`, the DN in `CC_LDAP_BIND_DN`.
2. **LDAPS**: domain controllers need a certificate (AD CS "Domain Controller" or
   "Kerberos Authentication"). Export the root CA as PEM → `CC_LDAP_CA_FILE`. The
   host in `CC_LDAP_URL` must match the controller certificate (a DNS name, not an
   IP). Check from the server host:
   `openssl s_client -connect dc1.acme.local:636 -CAfile ad-ca.pem </dev/null`
   (expect `Verify return code: 0 (ok)`). With only port 389 available use
   `ldap://dc1.acme.local:389` and `CC_LDAP_STARTTLS=true`; plain `ldap://` without
   TLS is refused.
3. **Search filter**: by default a user is found by `mail`, `userPrincipalName` or
   `sAMAccountName`, so people may type an e-mail, a UPN or `ACME\alice`. Several
   matches refuse the sign-in. A custom filter must contain `{login}`.
4. **Access group**, e.g. `CN=ConsoleCrypt,OU=Groups,DC=acme,DC=local`; nested
   groups count through the AD rule `LDAP_MATCHING_RULE_IN_CHAIN`. Membership is
   checked at sign-in and every re-check.
5. **Stable id**: `objectGUID` — a changed e-mail, UPN or account rename does not
   break the link. For `admin identity link` take it with
   `(Get-ADUser alice).ObjectGUID`. Disabled accounts (`userAccountControl` with
   `ACCOUNTDISABLE`) cannot sign in and lose their sessions at the next re-check.
6. **Test the search** before switching (the password is prompted, not passed as
   an argument):
   `ldapsearch -H ldaps://dc1.acme.local:636 -D '<service account DN>' -W -b 'DC=acme,DC=local' '(sAMAccountName=alice)' mail objectGUID userAccountControl`.
7. **Domain lockout policy**: keep `CC_LDAP_MAX_FAILURES` below the lockout
   threshold (see below).

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

An empty password is refused before AD is contacted (it would be an anonymous
bind). The server is built for Active Directory; with another LDAP directory set
your own `CC_LDAP_USER_FILTER`, `CC_LDAP_EMAIL_ATTR` and a stable
`CC_LDAP_ID_ATTR` (such as `entryUUID`); `CC_LDAP_REQUIRED_GROUP` uses the AD rule
`LDAP_MATCHING_RULE_IN_CHAIN`, which another directory may not support — test with
`admin auth test --login`.

**Lockout guard.** Failed binds count towards the domain lockout policy, so an
attacker could lock employees out through `/v1/auth/ldap/login`. The server counts
attempts in PostgreSQL (shared by all replicas) per typed login and per directory
user (e-mail, UPN and `DOMAIN\user` spellings count together). After
`CC_LDAP_MAX_FAILURES` failures within `CC_LDAP_FAILURE_WINDOW_MINUTES` further
attempts are refused **without contacting AD** (`429 rate_limited` with
`Retry-After`) until the window passes; unknown logins behave the same, so
existence is not revealed, and a successful sign-in resets the counter. Failures
per client IP are counted separately (`CC_LDAP_MAX_FAILURES_PER_IP`). **Keep
`CC_LDAP_MAX_FAILURES` below the domain's Account lockout threshold and
`CC_LDAP_FAILURE_WINDOW_MINUTES` at least the "Reset account lockout counter
after" time** — e.g. a domain threshold of 5 per 30 minutes → `CC_LDAP_MAX_FAILURES=3`,
`CC_LDAP_FAILURE_WINDOW_MINUTES=30`.

### First sign-in and account linking

1. **Known identity** (`(iss, sub)` or `objectGUID`): sign in to the linked
   account. If the IdP/AD e-mail changed and no other account uses it, the
   account's address is updated.
2. **New identity, an account with the same address exists** (e.g. created in
   standard mode): it is linked automatically only if the domain is in
   `CC_AUTH_ALLOWED_DOMAINS`, the account has no external identity yet, the IdP did
   not report `email_verified=false`, and the account is not disabled. The account
   password is removed, password sessions end, devices and vaults stay. Otherwise
   sign-in answers `409 identity_conflict` with the reason in the log
   (`linked_to_other_identity`, `link_requires_allowed_domain`,
   `email_not_verified`) — link by hand with
   `consolecrypt-server admin identity link --email alice@acme.com --subject <sub or objectGUID>`
   (`--subject` is the user's ID token `sub` claim — the user ID in the Keycloak
   console, the `00u…` user id in Okta; in Entra ID `sub` is not the Object ID
   `oid` — or the AD `objectGUID`; without `--issuer` the configured
   `CC_OIDC_ISSUER` or base DN is used).
3. **New identity, no account**: an account with a verified address is created
   when `CC_AUTH_AUTO_CREATE=true`. With `false` sign-in answers `403` with reason
   `not_provisioned`; only accounts created beforehand (in standard mode) or linked
   with `admin identity link` may sign in.

An identity without an e-mail (`email_missing`) or with a domain outside
`CC_AUTH_ALLOWED_DOMAINS` is refused with `403 domain_not_allowed`.

### Switching from standard to enterprise

1. Upgrade to server 0.2.0 or later and back up the database (migration
   `0011_enterprise_auth` only adds tables and makes `users.password_hash`
   optional).
2. Register the app at the IdP or create the AD service account (recipes above);
   put the secrets into files / a Secret.
3. Review the accounts with `admin list-users` and decide which domains go into
   `CC_AUTH_ALLOWED_DOMAINS` so existing accounts link themselves.
4. Set `CC_AUTH_MODE=enterprise` and restart. Check `admin auth status`,
   `admin auth test` and `"auth": {"mode": "enterprise", …}` in `/v1/meta`.
   Update the apps to a version with enterprise sign-in (client 0.9.0).
5. Sign in with your own account and check the `sign_in` column of
   `admin list-users`.

Afterwards registration, password sign-in, password reset and change and address
verification answer `403 enterprise_auth_required`; sessions opened with a password
stop refreshing, so every user signs in once through the IdP/AD; devices and vaults
are kept, and an already registered device signs in with its device key as before.

### Start-up checks and admin commands

At start-up the server validates the configuration and fails with a clear
message: for OIDC the secret files, discovery, the matching `issuer` and a JWKS
with RS256/PS256/ES256 keys; for LDAP the files, connection, TLS, the service
account bind, the base DN and the group.

```sh
consolecrypt-server admin auth status                       # mode, provider, last check, linked accounts
consolecrypt-server admin auth test                         # repeat the start-up checks
consolecrypt-server admin auth test --login alice@acme.com  # LDAP: find the user, group, disabled state
consolecrypt-server admin auth test --login alice@acme.com --password-stdin   # LDAP: a real bind
consolecrypt-server admin auth test --login alice@acme.com  # OIDC: re-check the account at the IdP now
consolecrypt-server admin identity link --email alice@acme.com --subject <sub or objectGUID>
consolecrypt-server admin identity unlink --email alice@acme.com
consolecrypt-server admin session revoke --email alice@acme.com
consolecrypt-server admin list-users                        # sign_in column: password, oidc, ldap
```

OIDC `admin auth test --login` performs a real re-check: if the IdP refuses, the
account's sessions are revoked. LDAP `--password-stdin` performs a real bind that
counts towards the domain lockout policy. With Docker Compose or Kubernetes run the
commands inside the container (`cc_compose exec -T server
/usr/local/bin/consolecrypt-server admin …`, `kubectl -n consolecrypt exec
deployment/consolecrypt -- /usr/local/bin/consolecrypt-server admin …`).

The log and `audit_events` record sign-ins (`login`, `metadata.method`), account
creation, links, refusals (`login_failed` with `metadata.reason`, the same values
as in the Russian section above), re-check revocations
(`enterprise_access_revoked`) and admin revocations — never passwords, client
secrets, tokens or login codes. Metrics: `cc_enterprise_logins_total{method,result}`,
`cc_enterprise_rechecks_total{result}`, `cc_ldap_lockout_guard_total{scope}`,
`cc_oidc_jwks_refetch_total`.

### Deployment

- **Helm**: the `auth:` block shown in the Russian section; secrets come from an
  existing Secret (`client-secret` and `token-key` for OIDC, `bind-password` and
  an optional CA key for LDAP) mounted read-only at
  `/run/secrets/consolecrypt-auth`. The chart fills in the `*_FILE` paths and
  refuses `ldap://` without `starttls: true` and OIDC without an `https://`
  `config.publicUrl`.
- **Docker Compose**: keep the keys and secrets in a private
  `compose.override.yaml` next to `server.env`, mount the secrets as Compose
  secrets owned by UID 65532 with mode 0400, and add the override as a second `-f`
  to `cc_compose` (the Russian section shows the full files).
- **Binary**: the same keys in a private JSON file (`--config`, mode 0600) or the
  service environment; `*_FILE` paths point at files owned by the service user
  with mode 0600.

Complete worked examples: [HOSTING.md](HOSTING.md#english).

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No start: `OIDC sign-in requires CC_PUBLIC_URL (https://…)` | `CC_PUBLIC_URL` missing or not `https://` | set the public server URL; in Helm `config.publicUrl` |
| `CC_OIDC_ISSUER: Entra ID multi-tenant endpoints … are not allowed` | `/common`, `/organizations` or `/consumers` issuer | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `CC_OIDC_ISSUER: for adfs expected …/adfs`, `for keycloak expected …/realms/<realm>` | issuer does not fit the preset | copy `issuer` from the IdP's discovery |
| `OIDC discovery: issuer mismatch` | `CC_OIDC_ISSUER` differs from discovery `issuer` (often a trailing `/`) | copy it character for character |
| `OIDC discovery at …`: request or certificate error | the server cannot reach the IdP over HTTPS or does not trust its CA | check DNS, egress and proxies; internal CA → `CC_OIDC_CA_FILE` |
| `… none of RS256, PS256, ES256` or `does not support PKCE S256` | another signing algorithm or no PKCE S256 | enable RS256/ES256 and PKCE S256 for the client |
| `CC_OIDC_CLIENT_SECRET_FILE (…): cannot open the file` / `file is empty` | wrong path, UID 65532 cannot read it, empty file | check the mount, `chown 65532:65532`, `chmod 0400`, the content |
| `CC_OIDC_TOKEN_KEY_FILE (…): expected 32 random bytes …` | not 64 hex characters or base64 of 32 bytes | `openssl rand -hex 32 > oidc-token-key` |
| `CC_OIDC_PRESET=google requires CC_AUTH_ALLOWED_DOMAINS` | no domain list for Google | list your Workspace domains |
| The IdP shows a redirect URI error | another redirect URI is registered | `CC_PUBLIC_URL` + `/v1/auth/oidc/callback`, Web client type |
| `403 domain_not_allowed` (`email_missing`) | domain outside `CC_AUTH_ALLOWED_DOMAINS` or no address in the ID token | check `CC_OIDC_EMAIL_CLAIM` (Entra: `email` vs `preferred_username`), the mail attribute, the domain list |
| `403 group_required` | the `CC_OIDC_REQUIRED_CLAIM` claim is missing, or the user is outside `CC_LDAP_REQUIRED_GROUP` | put the claim into the **ID token**, check its value (Keycloak: Full group path Off); Entra overage above 200 groups → app roles |
| `403 mfa_required` | the IdP reported no MFA in `amr`/`acr` | enforce MFA at the IdP; non-standard `acr` → `CC_OIDC_MFA_ACR_VALUES`; otherwise turn `CC_OIDC_REQUIRE_MFA` off |
| `409 identity_conflict` | the address belongs to an account linked elsewhere, the domain is not listed, or `email_verified=false` | `admin identity link` / `unlink`; add the domain to `CC_AUTH_ALLOWED_DOMAINS` |
| `403` with reason `not_provisioned` | `CC_AUTH_AUTO_CREATE=false` and no account | create/link the account or enable auto-creation |
| `503 idp_unavailable` | IdP/directory unreachable for longer than `CC_AUTH_RECHECK_GRACE_HOURS` | restore access; `admin auth status` shows the last check |
| A leaver still syncs | the re-check has not run yet, or no IdP refresh token | wait up to `CC_AUTH_RECHECK_MINUTES` + 1 min; `admin session revoke`; `admin auth test --login` |
| `CC_LDAP_URL: plain ldap:// is refused` | `ldap://` without STARTTLS | `ldaps://…:636` or `CC_LDAP_STARTTLS=true` |
| `LDAP …: cannot connect (network or TLS certificate problem)` | network, port, a host name not in the certificate, wrong CA | the certificate's DNS name, `CC_LDAP_CA_FILE`, `openssl s_client` |
| `LDAP TLS: no system root certificates found` | the image lacks the needed root | set `CC_LDAP_CA_FILE` |
| `service account bind rejected (check CC_LDAP_BIND_DN and password)` | wrong DN or password, disabled service account | check the DN, a password file without extra characters, the account state |
| `LDAP base DN … not found` / `CC_LDAP_REQUIRED_GROUP … not found` | a typo in the DN | copy the DN from the directory |
| `401 invalid_credentials` with the right password | the account is disabled, locked, its password expired, or the search found several entries | check the account in AD; narrow `CC_LDAP_USER_FILTER` |
| `429 rate_limited` at LDAP sign-in | the lockout guard (`CC_LDAP_MAX_FAILURES` or `CC_LDAP_MAX_FAILURES_PER_IP`) | wait for `CC_LDAP_FAILURE_WINDOW_MINUTES`; find out who is guessing passwords |

### Switching back to standard mode

There is **no emergency password sign-in in enterprise mode**. If the IdP or AD
is down or misconfigured, start with `admin auth status` and `admin auth test`. To
let people in with passwords for a while:

1. Set `CC_AUTH_MODE=standard` (Helm: `auth.mode: standard`) and restart. The
   `CC_OIDC_*` and `CC_LDAP_*` keys may stay: standard mode does not read them, so
   switching back is a one-key change.
2. Linked accounts have no password: set one with
   `admin set-password --email … --password-stdin` (or issue a code with
   `admin reset-token --email …`). The account password still does not open a
   vault.
3. Links are kept. Once enterprise mode is back on, sign-in is IdP/AD only again
   and the password is removed at the user's next sign-in. To remove a link for
   good: `admin identity unlink --email …`.

### Errors for apps (protocol 1.9)

`enterprise_auth_required` (403), `identity_conflict` (409), `domain_not_allowed`
(403), `group_required` (403), `mfa_required` (403), `idp_unavailable` (503),
`account_disabled` (403), `invalid_credentials` (401), `rate_limited` (429) — see
the table in the Russian section and [PROTOCOL_CHANGELOG.md](../../PROTOCOL_CHANGELOG.md).
