-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
-- Runs once, on an EMPTY pgdata volume. psql reads the password from the
-- environment, never from an argument, shell expansion or committed literal.
\getenv cc_database_password CC_DATABASE_PASSWORD
CREATE ROLE consolecrypt LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    PASSWORD :'cc_database_password';
ALTER DATABASE consolecrypt OWNER TO consolecrypt;
