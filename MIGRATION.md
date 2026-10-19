# Source migration / Перенос исходников

This repository was extracted from the published ConsoleCrypt GitLab main history on 2026-10-04.
The original source history is at https://git.evsikov.net/publics/consolecrypt;
legacy GitLab configuration is retained for compatibility.

The current [Server workflow](.github/workflows/server.yml) runs in GitHub Actions.
It starts only on pushed `vX.Y.Z` tags; branch pushes, PRs and manual workflow
dispatch do not start it. Only matching tags whose commits belong to main may build,
verify and publish native AMD64/ARM64 images and their multi-platform manifest.
Existing image references are not overwritten; deployments select the recorded
digest. The legacy GitLab workflow is disabled.

[Release and rollback instructions](server/docs/GITHUB_ACTIONS.md) describe the
existing Compose-service updater. Publishing an image does not move the database
or change DNS, SMTP, analytics or client update delivery. Production configuration
and credentials remain outside the repository.

Перенесены необходимые исходники и публичная документация. Внутренние ТЗ, планы,
локальные настройки, секреты и рабочие данные не включены. История отфильтрована:
идентификаторы коммитов отличаются от монорепозитория, авторство сохранено.
Теги прежних выпусков сохраняют свою исходную структуру зависимостей для сборки;
актуальная структура разделённых проектов описана в README.

Client release 0.3.1 binaries are byte-for-byte copies of the published GitLab release,
built from original source commit `02ba6a8a28c04741b80ce0086f8411a6cfa08ff4`.
This migration does not announce a new application update or change installed clients.
Historical license notices remain applicable to their original versions.
