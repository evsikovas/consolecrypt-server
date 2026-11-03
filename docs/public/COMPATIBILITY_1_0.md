# Совместимость сервера с ConsoleCrypt 1.0.0

## Что изменилось

Клиент 1.0.0 добавляет менеджер KDBX и синхронизацию параметров WebDAV.
Сервер не получает мастер-пароль, записи KDBX или материал биометрических ключей.
Сам KDBX находится локально либо на выбранном WebDAV; он не загружается в
ConsoleCrypt Sync как отдельный файл.

В зашифрованный клиентский объект `VaultSettings` добавлен `password_vaults`:
id, название, HTTPS URL, логин и ссылка на отдельный зашифрованный credential.
Сервер хранит объект как существующий `EncryptedBody`, без разбора новых полей.
Пути к локальным файлам, конверты быстрого открытия и Docker/Kubernetes-профили
пробросов остаются на устройстве.

## Нужна ли доработка сервера

Для этих изменений не нужны новые endpoints, таблицы, миграции, разрешения,
ключи шифрования или изменение wire-протокола. Версия сервера остаётся независимой
от версии клиента; текущая база проверки — сервер 0.2.4 / протокол 1.13.
Существующие ограничения размера зашифрованных объектов и прав доступа сохраняются.

Проверки клиента выполняют сериализацию новых настроек и зашифрованный обмен
между клиентами. Серверные проверки синхронизации, конфликтов, прав, совместного
доступа и backup/restore запускаются в отдельном GitHub workflow
[Client compatibility](https://github.com/evsikovas/consolecrypt-server/actions/workflows/client-compatibility.yml)
на временном PostgreSQL. Workflow не публикует образы и не меняет production.

Обновите все устройства до клиента 1.0.0 перед сохранением WebDAV-подключений.
Старые клиенты не знают новое поле и при перезаписи `VaultSettings` могут
сбросить список подключений. Сервер не может дополнять расшифрованные настройки
или восстанавливать их поля: это нарушило бы модель E2EE.

## English

Client 1.0 adds KDBX management and encrypted WebDAV connection settings.
The sync server receives neither KDBX master passwords/entries nor biometric
key material. The KDBX file stays on the device or the chosen WebDAV server.

`VaultSettings.password_vaults` carries connection IDs, names, HTTPS URLs,
usernames and references to separate encrypted credentials. It travels inside
the existing opaque `EncryptedBody`. No endpoints, database tables, migrations,
permissions, encryption keys or wire-protocol changes are needed. The server
version remains independent; the current verification baseline is server
0.2.4 / protocol 1.13. Existing payload limits and authorisation apply.

Local file paths, quick-unlock envelopes and saved Docker/Kubernetes forward
presets stay on the device. Client tests cover typed settings and encrypted
round trips; the independent Client compatibility workflow runs server sync,
conflict, permission, sharing and backup/restore tests against disposable
PostgreSQL without deployment.

Update every device to client 1.0 before saving WebDAV settings. Older clients
may drop the unknown field when rewriting shared settings; the server cannot
merge decrypted settings without breaking the E2EE boundary.

## Проверка / Verification

[Client compatibility, 3 November 2026](https://github.com/evsikovas/consolecrypt-server/actions/runs/41619884664)
passed on server commit `58709b5`: dependency policy, formatting, lint,
protocol/configuration checks and server integration tests with PostgreSQL,
including sync, permissions, sharing and backup/restore. No production
deployment or data migration was performed by that workflow.
