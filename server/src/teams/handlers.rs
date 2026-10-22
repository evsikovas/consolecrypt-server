// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `/v1/teams/*` (protocol 1.9).

use super::log::{self, LiveMember, LogState};
use crate::audit::{AuditEvent, AuditType};
use crate::auth::AuthContext;
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::extract::{ApiJson, ApiPath, ApiQuery, ClientIp};
use crate::state::AppState;
use crate::util::{enum_str, normalize_email, parse_enum};
use crate::vaults::envelopes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use cc_protocol::envelopes::{NewEnvelope, RecipientType};
use cc_protocol::events::ServerEvent;
use cc_protocol::teams::{
    AcceptTeamInvitationRequest, CreateTeamRequest, InviteTeamMemberRequest,
    ListTeamInvitationsResponse, ListTeamsResponse, SignedTeamLogEntry, SubmitTeamLogRequest,
    SubmitTeamLogResponse, TeamDetail, TeamInfo, TeamInvitation, TeamKeyChainLink, TeamKeyMaterial,
    TeamLogOp, TeamLogPage, TeamLogQuery, TeamMember, TeamMemberKeys, MAX_INVITATION_NOTE_CHARS,
    MAX_TEAM_LOG_PAGE,
};
use cc_protocol::vaults::VaultRole;
use cc_protocol::{limits, paths, Bytes, ErrorCode, TeamInvitationId, UserId, VaultId};
use chrono::{DateTime, Utc};
use sqlx::types::Json as SqlJson;
use sqlx::{PgConnection, PgExecutor};
use std::collections::HashMap;
use uuid::Uuid;

/// Invitation lifetime.
const INVITATION_TTL_DAYS: i64 = 7;
/// Invitations a team may create per hour.
const INVITATIONS_PER_HOUR: i64 = 20;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(paths::TEAMS, get(list_teams).post(create_team))
        .route(paths::TEAM_INVITATIONS_INBOX, get(list_inbox))
        .route(
            paths::TEAM_INVITATION,
            axum::routing::delete(close_invitation),
        )
        .route(paths::TEAM_INVITATION_ACCEPT, post(accept_invitation))
        .route(paths::TEAM, get(get_team))
        .route(paths::TEAM_LOG, get(get_log).post(submit_log))
        .route(paths::TEAM_KEY, get(get_key))
        .route(
            paths::TEAM_INVITATIONS,
            get(list_team_invitations).post(invite),
        )
}

fn require_enabled(state: &AppState) -> AppResult<()> {
    if state.config.teams_enabled {
        Ok(())
    } else {
        Err(AppError::not_found())
    }
}

// ---- loading -----------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct TeamRow {
    id: Uuid,
    role: String,
    key_epoch: i32,
    log_seq: Option<i64>,
    log_head: Option<Vec<u8>>,
    rotation_required: bool,
    trusted: bool,
    last_sequence: i64,
    epoch: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    members_count: i64,
    access_key_verifier: Vec<u8>,
}

const TEAM_SELECT: &str = "SELECT v.id, m.role, v.key_epoch, v.log_seq, v.log_head,
        v.rotation_required, v.epoch, v.created_at, v.updated_at, v.access_key_verifier,
        s.last_sequence,
        EXISTS (SELECT 1 FROM vault_key_envelopes e
                 WHERE e.vault_id = v.id AND e.recipient_type = 'device'
                   AND e.recipient_id = $2 AND e.revoked_at IS NULL) AS trusted,
        (SELECT count(*) FROM vault_members c
          WHERE c.vault_id = v.id AND c.revoked_at IS NULL) AS members_count
   FROM vaults v
   JOIN vault_members m ON m.vault_id = v.id AND m.user_id = $1 AND m.revoked_at IS NULL
   JOIN vault_sequences s ON s.vault_id = v.id
  WHERE v.kind = 'team' AND v.state = 'active'";

impl TeamRow {
    fn role(&self) -> AppResult<VaultRole> {
        parse_enum(&self.role)
    }

    fn info(&self) -> AppResult<TeamInfo> {
        Ok(TeamInfo {
            vault_id: self.id.into(),
            role: self.role()?,
            key_epoch: u32::try_from(self.key_epoch).unwrap_or(0),
            log_seq: u64::try_from(self.log_seq.unwrap_or(0)).unwrap_or(0),
            log_head: Bytes::new(self.log_head.clone().unwrap_or_else(|| vec![0; 32])),
            members_count: u32::try_from(self.members_count).unwrap_or(u32::MAX),
            rotation_required: self.rotation_required,
            caller_trusted: self.trusted,
            latest_sequence: self.last_sequence,
            epoch: self.epoch,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

async fn load_team<'e>(
    db: impl PgExecutor<'e>,
    auth: &AuthContext,
    vault_id: VaultId,
) -> AppResult<TeamRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{TEAM_SELECT} AND v.id = $3")))
        .bind(Uuid::from(auth.user_id))
        .bind(Uuid::from(auth.device_id))
        .bind(Uuid::from(vault_id))
        .fetch_optional(db)
        .await?
        .ok_or_else(AppError::not_found)
}

fn require_admin(row: &TeamRow) -> AppResult<VaultRole> {
    let role = row.role()?;
    if matches!(role, VaultRole::Owner | VaultRole::Admin) {
        Ok(role)
    } else {
        Err(AppError::forbidden("team admins only")
            .with_details(serde_json::json!({"reason": "team_role"})))
    }
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    user_id: Uuid,
    email: String,
    role: String,
    identity_encryption_key: Option<Vec<u8>>,
    identity_signing_key: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
}

async fn live_members(conn: &mut PgConnection, vault_id: VaultId) -> AppResult<Vec<MemberRow>> {
    Ok(sqlx::query_as(
        "SELECT m.user_id, u.email, m.role, m.identity_encryption_key,
                m.identity_signing_key, m.created_at
           FROM vault_members m JOIN users u ON u.id = m.user_id
          WHERE m.vault_id = $1 AND m.revoked_at IS NULL
          ORDER BY m.created_at, m.user_id",
    )
    .bind(Uuid::from(vault_id))
    .fetch_all(&mut *conn)
    .await?)
}

fn member_dto(r: MemberRow) -> AppResult<TeamMember> {
    Ok(TeamMember {
        user_id: r.user_id.into(),
        email: r.email,
        role: parse_enum(&r.role)?,
        encryption_key: Bytes::new(r.identity_encryption_key.unwrap_or_default()),
        signing_key: Bytes::new(r.identity_signing_key.unwrap_or_default()),
        joined_at: r.created_at,
    })
}

fn validate_user_envelope(env: &NewEnvelope, user: UserId) -> AppResult<()> {
    envelopes::validate(env, RecipientType::User)?;
    if env.recipient_id != Some(Uuid::from(user)) {
        return Err(AppError::bad_request(
            "user envelope must be addressed to the member",
        ));
    }
    Ok(())
}

/// Store a user envelope of `key_epoch` (revokes the member's previous one).
async fn store_user_envelope(
    conn: &mut PgConnection,
    vault_id: VaultId,
    env: &NewEnvelope,
    auth: &AuthContext,
    key_epoch: u32,
) -> AppResult<()> {
    let stored = envelopes::store(&mut *conn, vault_id, env, auth.device_id, "rotated").await?;
    sqlx::query("UPDATE vault_key_envelopes SET key_epoch = $2 WHERE id = $1")
        .bind(Uuid::from(stored.envelope_id))
        .bind(i32::try_from(key_epoch).unwrap_or(i32::MAX))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

// ---- teams ---------------------------------------------------------------------------

/// `POST /v1/teams` → `201 TeamInfo`.
pub async fn create_team(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<CreateTeamRequest>,
) -> AppResult<(StatusCode, Json<TeamInfo>)> {
    require_enabled(&state)?;
    if state.config.require_email_verification && !auth.email_verified {
        return Err(AppError::new(
            ErrorCode::EmailNotVerified,
            "verify your email address before creating a team",
        ));
    }
    if req.vault_id.as_uuid().is_nil() {
        return Err(AppError::bad_request("invalid vault_id"));
    }
    if req.vault_access_key.len() != limits::VAULT_ACCESS_KEY_LEN {
        return Err(AppError::bad_request("vault_access_key must be 32 bytes"));
    }
    let now = Utc::now();
    let head = log::check_genesis(req.vault_id, auth.user_id, &req.genesis, now.timestamp())?;
    let TeamLogOp::Genesis { owner } = &req.genesis.entry.op else {
        return Err(AppError::bad_request("the first entry must be genesis"));
    };
    validate_member_keys(owner)?;
    validate_user_envelope(&req.owner_envelope, auth.user_id)?;
    envelopes::validate(&req.device_envelope, RecipientType::Device)?;
    if req.device_envelope.recipient_id != Some(auth.device_id.into()) {
        return Err(AppError::bad_request(
            "device_envelope must be addressed to the calling device",
        ));
    }

    let verifier = crypto::vault_access_key_verifier(req.vault_access_key.as_slice());
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(Uuid::from(auth.user_id))
        .execute(&mut *tx)
        .await?;
    let teams: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM vault_members m JOIN vaults v ON v.id = m.vault_id
          WHERE m.user_id = $1 AND m.revoked_at IS NULL
            AND v.kind = 'team' AND v.state <> 'deleted'",
    )
    .bind(Uuid::from(auth.user_id))
    .fetch_one(&mut *tx)
    .await?;
    if teams >= state.config.max_teams_per_account {
        return Err(
            AppError::forbidden("team limit reached for this account").with_details(
                serde_json::json!({
                    "reason": "team_limit",
                    "limit": state.config.max_teams_per_account,
                }),
            ),
        );
    }
    let inserted = sqlx::query(
        "INSERT INTO vaults (id, owner_user_id, access_key_verifier, created_by_device_id,
                             kind, key_epoch, log_seq, log_head)
         VALUES ($1, $2, $3, $4, 'team', 0, 0, $5)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(Uuid::from(req.vault_id))
    .bind(Uuid::from(auth.user_id))
    .bind(&verifier[..])
    .bind(Uuid::from(auth.device_id))
    .bind(&head[..])
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(AppError::already_exists(
            "vault_id",
            "a vault with this id already exists",
        ));
    }
    sqlx::query(
        "INSERT INTO vault_members (vault_id, user_id, role, identity_encryption_key,
                                    identity_signing_key)
         VALUES ($1, $2, 'owner', $3, $4)",
    )
    .bind(Uuid::from(req.vault_id))
    .bind(Uuid::from(auth.user_id))
    .bind(owner.encryption_key.as_slice())
    .bind(owner.signing_key.as_slice())
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO vault_sequences (vault_id, last_sequence) VALUES ($1, 0)")
        .bind(Uuid::from(req.vault_id))
        .execute(&mut *tx)
        .await?;
    insert_log(&mut tx, req.vault_id, &req.genesis, &head).await?;
    store_user_envelope(&mut tx, req.vault_id, &req.owner_envelope, &auth, 0).await?;
    envelopes::store(
        &mut tx,
        req.vault_id,
        &req.device_envelope,
        auth.device_id,
        "replaced",
    )
    .await?;
    AuditEvent::new(AuditType::TeamCreated)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(req.vault_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    let row = load_team(&mut *tx, &auth, req.vault_id).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row.info()?)))
}

fn validate_member_keys(keys: &TeamMemberKeys) -> AppResult<()> {
    keys.validate()
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    if !crypto::is_valid_encryption_public_key(keys.encryption_key.as_slice())
        || !crypto::is_valid_signing_public_key(keys.signing_key.as_slice())
    {
        return Err(AppError::bad_request("invalid member keys"));
    }
    Ok(())
}

async fn insert_log(
    conn: &mut PgConnection,
    vault_id: VaultId,
    signed: &SignedTeamLogEntry,
    hash: &[u8; 32],
) -> AppResult<()> {
    sqlx::query("INSERT INTO team_log (vault_id, seq, entry, hash) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::from(vault_id))
        .bind(i64::try_from(signed.entry.seq).map_err(|_| AppError::bad_request("seq"))?)
        .bind(SqlJson(signed))
        .bind(&hash[..])
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `GET /v1/teams` → teams the caller is a member of.
pub async fn list_teams(
    State(state): State<AppState>,
    auth: AuthContext,
) -> AppResult<Json<ListTeamsResponse>> {
    require_enabled(&state)?;
    let rows: Vec<TeamRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{TEAM_SELECT} ORDER BY v.created_at, v.id"
    )))
    .bind(Uuid::from(auth.user_id))
    .bind(Uuid::from(auth.device_id))
    .fetch_all(&state.db)
    .await?;
    let teams = rows.iter().map(TeamRow::info).collect::<AppResult<_>>()?;
    Ok(Json(ListTeamsResponse { teams }))
}

/// `GET /v1/teams/{vault_id}` → the team and its members.
pub async fn get_team(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(vault_id): ApiPath<VaultId>,
) -> AppResult<Json<TeamDetail>> {
    require_enabled(&state)?;
    let mut conn = state.db.acquire().await?;
    let row = load_team(&mut *conn, &auth, vault_id).await?;
    let members = live_members(&mut conn, vault_id)
        .await?
        .into_iter()
        .map(member_dto)
        .collect::<AppResult<_>>()?;
    Ok(Json(TeamDetail {
        team: row.info()?,
        members,
    }))
}

/// `GET /v1/teams/{vault_id}/log?after=` → signed entries in order.
pub async fn get_log(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(vault_id): ApiPath<VaultId>,
    ApiQuery(q): ApiQuery<TeamLogQuery>,
) -> AppResult<Json<TeamLogPage>> {
    require_enabled(&state)?;
    let row = load_team(&state.db, &auth, vault_id).await?;
    let after = q.after.map_or(-1, |a| i64::try_from(a).unwrap_or(i64::MAX));
    let entries: Vec<SqlJson<SignedTeamLogEntry>> = sqlx::query_scalar(
        "SELECT entry FROM team_log WHERE vault_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
    )
    .bind(Uuid::from(vault_id))
    .bind(after)
    .bind(i64::try_from(MAX_TEAM_LOG_PAGE + 1).unwrap_or(501))
    .fetch_all(&state.db)
    .await?;
    let mut entries: Vec<SignedTeamLogEntry> = entries.into_iter().map(|e| e.0).collect();
    let has_more = entries.len() > MAX_TEAM_LOG_PAGE;
    entries.truncate(MAX_TEAM_LOG_PAGE);
    Ok(Json(TeamLogPage {
        entries,
        head_seq: u64::try_from(row.log_seq.unwrap_or(0)).unwrap_or(0),
        has_more,
    }))
}

/// `GET /v1/teams/{vault_id}/key` → the caller's user envelope and the
/// key-epoch chain.
pub async fn get_key(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(vault_id): ApiPath<VaultId>,
) -> AppResult<Json<TeamKeyMaterial>> {
    require_enabled(&state)?;
    let row = load_team(&state.db, &auth, vault_id).await?;
    let envelope = envelopes::live_for(
        &state.db,
        vault_id,
        RecipientType::User,
        Some(Uuid::from(auth.user_id)),
    )
    .await?
    .ok_or_else(AppError::not_found)?;
    let chain: Vec<(i32, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT key_epoch, nonce, ciphertext FROM team_key_chain
          WHERE vault_id = $1 ORDER BY key_epoch DESC",
    )
    .bind(Uuid::from(vault_id))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(TeamKeyMaterial {
        key_epoch: u32::try_from(row.key_epoch).unwrap_or(0),
        envelope,
        chain: chain
            .into_iter()
            .map(|(e, nonce, ciphertext)| TeamKeyChainLink {
                key_epoch: u32::try_from(e).unwrap_or(0),
                nonce: Bytes::new(nonce),
                ciphertext: Bytes::new(ciphertext),
            })
            .collect(),
    }))
}

// ---- invitations ---------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    vault_id: Uuid,
    inviter_user_id: Uuid,
    inviter_email: String,
    inviter_signing_key: Option<Vec<u8>>,
    invitee_user_id: Uuid,
    invitee_email: String,
    role: String,
    note: Option<String>,
    status: String,
    identity_encryption_key: Option<Vec<u8>>,
    identity_signing_key: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

const INVITATION_SELECT: &str = "SELECT i.id, i.vault_id, i.inviter_user_id,
        ur.email AS inviter_email, mr.identity_signing_key AS inviter_signing_key,
        i.invitee_user_id, ue.email AS invitee_email, i.role, i.note,
        CASE WHEN i.status IN ('pending', 'accepted') AND i.expires_at <= now()
             THEN 'expired' ELSE i.status END AS status,
        i.identity_encryption_key, i.identity_signing_key, i.created_at, i.expires_at
   FROM team_invitations i
   JOIN users ur ON ur.id = i.inviter_user_id
   JOIN users ue ON ue.id = i.invitee_user_id
   LEFT JOIN vault_members mr ON mr.vault_id = i.vault_id AND mr.user_id = i.inviter_user_id";

impl InvitationRow {
    fn dto(self) -> AppResult<TeamInvitation> {
        let member_keys = match (self.identity_encryption_key, self.identity_signing_key) {
            (Some(enc), Some(sign)) => Some(TeamMemberKeys {
                user_id: self.invitee_user_id.into(),
                encryption_key: Bytes::new(enc),
                signing_key: Bytes::new(sign),
            }),
            _ => None,
        };
        Ok(TeamInvitation {
            invitation_id: self.id.into(),
            vault_id: self.vault_id.into(),
            inviter_user_id: self.inviter_user_id.into(),
            inviter_email: self.inviter_email,
            inviter_signing_key: Bytes::new(self.inviter_signing_key.unwrap_or_default()),
            invitee_user_id: self.invitee_user_id.into(),
            invitee_email: self.invitee_email,
            role: parse_enum(&self.role)?,
            note: self.note,
            status: parse_enum(&self.status)?,
            member_keys,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }

    fn open(&self) -> bool {
        matches!(self.status.as_str(), "pending" | "accepted")
    }
}

async fn load_invitation<'e>(
    db: impl PgExecutor<'e>,
    id: TeamInvitationId,
) -> AppResult<InvitationRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{INVITATION_SELECT} WHERE i.id = $1"
    )))
    .bind(Uuid::from(id))
    .fetch_optional(db)
    .await?
    .ok_or_else(AppError::not_found)
}

fn validate_note(note: &Option<String>) -> AppResult<Option<String>> {
    let Some(n) = note.as_deref().map(str::trim).filter(|n| !n.is_empty()) else {
        return Ok(None);
    };
    if n.chars().count() > MAX_INVITATION_NOTE_CHARS || n.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "invitation note is too long or invalid",
        ));
    }
    Ok(Some(n.to_owned()))
}

/// `POST /v1/teams/{vault_id}/invitations` → always `202` (no account
/// enumeration).
pub async fn invite(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(vault_id): ApiPath<VaultId>,
    ApiJson(req): ApiJson<InviteTeamMemberRequest>,
) -> AppResult<StatusCode> {
    require_enabled(&state)?;
    if req.role == VaultRole::Owner {
        return Err(AppError::bad_request("invite as admin, editor or viewer"));
    }
    let note = validate_note(&req.note)?;
    let email = normalize_email(&req.email)?;
    let mut tx = state.db.begin().await?;
    let row = load_team(&mut *tx, &auth, vault_id).await?;
    let my_role = require_admin(&row)?;
    if req.role == VaultRole::Admin && my_role != VaultRole::Owner {
        return Err(AppError::forbidden("only the owner invites admins")
            .with_details(serde_json::json!({"reason": "team_role"})));
    }
    sqlx::query("SELECT 1 FROM vaults WHERE id = $1 FOR UPDATE")
        .bind(Uuid::from(vault_id))
        .execute(&mut *tx)
        .await?;
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM team_invitations
          WHERE vault_id = $1 AND created_at > now() - interval '1 hour'",
    )
    .bind(Uuid::from(vault_id))
    .fetch_one(&mut *tx)
    .await?;
    if recent >= INVITATIONS_PER_HOUR {
        return Err(AppError::rate_limited(3600));
    }
    if row.members_count >= state.config.max_team_members {
        return Err(
            AppError::forbidden("member limit reached for this team").with_details(
                serde_json::json!({
                    "reason": "team_member_limit",
                    "limit": state.config.max_team_members,
                }),
            ),
        );
    }
    let invitee: Option<Uuid> = sqlx::query_scalar(
        "SELECT u.id FROM users u
          WHERE lower(u.email) = lower($1) AND u.status = 'active'
            AND NOT EXISTS (SELECT 1 FROM vault_members m WHERE m.vault_id = $2
                             AND m.user_id = u.id AND m.revoked_at IS NULL)",
    )
    .bind(&email)
    .bind(Uuid::from(vault_id))
    .fetch_optional(&mut *tx)
    .await?;
    let mut created = None;
    if let Some(invitee) = invitee {
        // Expired open invitations no longer block a new one.
        sqlx::query(
            "UPDATE team_invitations SET status = 'expired', decided_at = now()
              WHERE vault_id = $1 AND invitee_user_id = $2
                AND status IN ('pending', 'accepted') AND expires_at <= now()",
        )
        .bind(Uuid::from(vault_id))
        .bind(invitee)
        .execute(&mut *tx)
        .await?;
        let id = TeamInvitationId::new();
        let inserted = sqlx::query(
            "INSERT INTO team_invitations (id, vault_id, inviter_user_id, invitee_user_id,
                                           role, note, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(days => $7))
             ON CONFLICT DO NOTHING",
        )
        .bind(Uuid::from(id))
        .bind(Uuid::from(vault_id))
        .bind(Uuid::from(auth.user_id))
        .bind(invitee)
        .bind(enum_str(&req.role))
        .bind(&note)
        .bind(i32::try_from(INVITATION_TTL_DAYS).unwrap_or(7))
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 1 {
            created = Some((UserId::from(invitee), id));
        }
    }
    AuditEvent::new(AuditType::TeamInvited)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(vault_id)
        .ip(ip)
        .meta(serde_json::json!({"role": enum_str(&req.role), "delivered": created.is_some()}))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Some((user, invitation_id)) = created {
        state
            .events
            .publish_user(user, ServerEvent::TeamInvitationReceived { invitation_id })
            .await;
    }
    Ok(StatusCode::ACCEPTED)
}

/// `GET /v1/teams/invitations` → open invitations addressed to the caller.
pub async fn list_inbox(
    State(state): State<AppState>,
    auth: AuthContext,
) -> AppResult<Json<ListTeamInvitationsResponse>> {
    require_enabled(&state)?;
    let rows: Vec<InvitationRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{INVITATION_SELECT} WHERE i.invitee_user_id = $1
            AND i.status IN ('pending', 'accepted') AND i.expires_at > now()
          ORDER BY i.created_at"
    )))
    .bind(Uuid::from(auth.user_id))
    .fetch_all(&state.db)
    .await?;
    let invitations = rows
        .into_iter()
        .map(InvitationRow::dto)
        .collect::<AppResult<_>>()?;
    Ok(Json(ListTeamInvitationsResponse { invitations }))
}

/// `GET /v1/teams/{vault_id}/invitations` (admins) → open invitations.
pub async fn list_team_invitations(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(vault_id): ApiPath<VaultId>,
) -> AppResult<Json<ListTeamInvitationsResponse>> {
    require_enabled(&state)?;
    let row = load_team(&state.db, &auth, vault_id).await?;
    require_admin(&row)?;
    let rows: Vec<InvitationRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{INVITATION_SELECT} WHERE i.vault_id = $1
            AND i.status IN ('pending', 'accepted') AND i.expires_at > now()
          ORDER BY i.created_at"
    )))
    .bind(Uuid::from(vault_id))
    .fetch_all(&state.db)
    .await?;
    let invitations = rows
        .into_iter()
        .map(InvitationRow::dto)
        .collect::<AppResult<_>>()?;
    Ok(Json(ListTeamInvitationsResponse { invitations }))
}

/// `POST /v1/teams/invitations/{id}/accept` (invitee) → the invitation with
/// the submitted keys; the inviter is notified to compare the code.
pub async fn accept_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(id): ApiPath<TeamInvitationId>,
    ApiJson(req): ApiJson<AcceptTeamInvitationRequest>,
) -> AppResult<Json<TeamInvitation>> {
    require_enabled(&state)?;
    let keys = TeamMemberKeys {
        user_id: auth.user_id,
        encryption_key: req.encryption_key,
        signing_key: req.signing_key,
    };
    validate_member_keys(&keys)?;
    let mut tx = state.db.begin().await?;
    let inv = load_invitation(&mut *tx, id).await?;
    if inv.invitee_user_id != Uuid::from(auth.user_id) {
        return Err(AppError::not_found());
    }
    if inv.status != "pending" {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "the invitation is no longer pending",
        ));
    }
    sqlx::query(
        "UPDATE team_invitations SET status = 'accepted', identity_encryption_key = $2,
                identity_signing_key = $3, decided_at = now()
          WHERE id = $1",
    )
    .bind(Uuid::from(id))
    .bind(keys.encryption_key.as_slice())
    .bind(keys.signing_key.as_slice())
    .execute(&mut *tx)
    .await?;
    let inv = load_invitation(&mut *tx, id).await?;
    tx.commit().await?;
    let inviter = UserId::from(inv.inviter_user_id);
    let vault_id = VaultId::from(inv.vault_id);
    state
        .events
        .publish_user(
            inviter,
            ServerEvent::TeamJoinRequested {
                vault_id,
                invitation_id: id,
            },
        )
        .await;
    Ok(Json(inv.dto()?))
}

/// `DELETE /v1/teams/invitations/{id}`: the invitee declines, an admin of
/// the team cancels.
pub async fn close_invitation(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(id): ApiPath<TeamInvitationId>,
) -> AppResult<StatusCode> {
    require_enabled(&state)?;
    let mut tx = state.db.begin().await?;
    let inv = load_invitation(&mut *tx, id).await?;
    let status = if inv.invitee_user_id == Uuid::from(auth.user_id) {
        "declined"
    } else {
        let row = load_team(&mut *tx, &auth, inv.vault_id.into()).await?;
        require_admin(&row)?;
        "cancelled"
    };
    if !inv.open() {
        return Ok(StatusCode::NO_CONTENT);
    }
    sqlx::query("UPDATE team_invitations SET status = $2, decided_at = now() WHERE id = $1")
        .bind(Uuid::from(id))
        .bind(status)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- membership log ------------------------------------------------------------------

async fn log_state(conn: &mut PgConnection, vault_id: VaultId) -> AppResult<LogState> {
    let (log_seq, log_head, key_epoch): (Option<i64>, Option<Vec<u8>>, i32) = sqlx::query_as(
        "SELECT log_seq, log_head, key_epoch FROM vaults
          WHERE id = $1 AND kind = 'team' AND state = 'active' FOR UPDATE",
    )
    .bind(Uuid::from(vault_id))
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(AppError::not_found)?;
    let mut members = HashMap::new();
    for m in live_members(conn, vault_id).await? {
        members.insert(
            UserId::from(m.user_id),
            LiveMember {
                role: parse_enum(&m.role)?,
                signing_key: m.identity_signing_key.unwrap_or_default(),
            },
        );
    }
    let head: [u8; 32] = log_head
        .as_deref()
        .and_then(|h| h.try_into().ok())
        .ok_or_else(|| AppError::internal("team without a log head"))?;
    Ok(LogState {
        vault_id,
        log_seq: u64::try_from(log_seq.unwrap_or(0)).unwrap_or(0),
        log_head: head,
        key_epoch: u32::try_from(key_epoch).unwrap_or(0),
        members,
    })
}

/// Revoke a member's access to the team: membership, user envelope and the
/// trust markers of every device of that user.
async fn revoke_member(conn: &mut PgConnection, vault_id: VaultId, user: UserId) -> AppResult<()> {
    sqlx::query(
        "UPDATE vault_members SET revoked_at = now()
          WHERE vault_id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(Uuid::from(vault_id))
    .bind(Uuid::from(user))
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE vault_key_envelopes SET revoked_at = now(), revoke_reason = 'team_member_removed'
          WHERE vault_id = $1 AND revoked_at IS NULL
            AND ((recipient_type = 'user' AND recipient_id = $2)
                 OR (recipient_type = 'device'
                     AND recipient_id IN (SELECT id FROM devices WHERE user_id = $2)))",
    )
    .bind(Uuid::from(vault_id))
    .bind(Uuid::from(user))
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE vaults SET rotation_required = true WHERE id = $1")
        .bind(Uuid::from(vault_id))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `POST /v1/teams/{vault_id}/log` → the log head and the members.
pub async fn submit_log(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(vault_id): ApiPath<VaultId>,
    ApiJson(req): ApiJson<SubmitTeamLogRequest>,
) -> AppResult<Json<SubmitTeamLogResponse>> {
    require_enabled(&state)?;
    let now = Utc::now();
    let mut tx = state.db.begin().await?;
    let st = log_state(&mut tx, vault_id).await?;
    let row = load_team(&mut *tx, &auth, vault_id).await?;
    if !crypto::verify_vault_access_key(req.vault_access_key.as_slice(), &row.access_key_verifier) {
        state
            .limits
            .proof_device
            .check(&Uuid::from(auth.device_id))?;
        return Err(AppError::invalid_proof("invalid vault access key"));
    }
    let head = log::check_append(&st, auth.user_id, &req.entry, now.timestamp())?;
    let op = req.entry.entry.op.clone();
    let mut removed: Option<UserId> = None;
    let mut rotated: Option<u32> = None;
    let audit = match &op {
        TeamLogOp::Genesis { .. } => return Err(AppError::bad_request("genesis exists")),
        TeamLogOp::AddMember { member, role } => {
            let inv_id = req
                .invitation_id
                .ok_or_else(|| AppError::bad_request("invitation_id is required"))?;
            let inv = load_invitation(&mut *tx, inv_id).await?;
            let keys_match = inv.identity_encryption_key.as_deref()
                == Some(member.encryption_key.as_slice())
                && inv.identity_signing_key.as_deref() == Some(member.signing_key.as_slice());
            if inv.vault_id != Uuid::from(vault_id)
                || inv.status != "accepted"
                || inv.invitee_user_id != Uuid::from(member.user_id)
                || inv.inviter_user_id != Uuid::from(auth.user_id)
                || !keys_match
                || inv.role != enum_str(role)
            {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "the entry does not match the accepted invitation",
                ));
            }
            let [env] = req.envelopes.as_slice() else {
                return Err(AppError::bad_request(
                    "exactly one user envelope is required",
                ));
            };
            validate_user_envelope(env, member.user_id)?;
            sqlx::query(
                "INSERT INTO vault_members (vault_id, user_id, role, identity_encryption_key,
                                            identity_signing_key)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (vault_id, user_id) DO UPDATE
                    SET role = EXCLUDED.role,
                        identity_encryption_key = EXCLUDED.identity_encryption_key,
                        identity_signing_key = EXCLUDED.identity_signing_key,
                        created_at = now(), revoked_at = NULL",
            )
            .bind(Uuid::from(vault_id))
            .bind(Uuid::from(member.user_id))
            .bind(enum_str(role))
            .bind(member.encryption_key.as_slice())
            .bind(member.signing_key.as_slice())
            .execute(&mut *tx)
            .await?;
            store_user_envelope(&mut tx, vault_id, env, &auth, st.key_epoch).await?;
            sqlx::query(
                "UPDATE team_invitations SET status = 'completed', decided_at = now() WHERE id = $1",
            )
            .bind(Uuid::from(inv_id))
            .execute(&mut *tx)
            .await?;
            AuditType::TeamMemberAdded
        }
        TeamLogOp::ChangeRole { user_id, role } => {
            sqlx::query(
                "UPDATE vault_members SET role = $3
                  WHERE vault_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            )
            .bind(Uuid::from(vault_id))
            .bind(Uuid::from(*user_id))
            .bind(enum_str(role))
            .execute(&mut *tx)
            .await?;
            AuditType::TeamRoleChanged
        }
        TeamLogOp::RemoveMember { user_id } => {
            revoke_member(&mut tx, vault_id, *user_id).await?;
            removed = Some(*user_id);
            AuditType::TeamMemberRemoved
        }
        TeamLogOp::Leave => {
            revoke_member(&mut tx, vault_id, auth.user_id).await?;
            removed = Some(auth.user_id);
            AuditType::TeamLeft
        }
        TeamLogOp::TransferOwner { user_id } => {
            sqlx::query(
                "UPDATE vault_members SET role = 'admin'
                  WHERE vault_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            )
            .bind(Uuid::from(vault_id))
            .bind(Uuid::from(auth.user_id))
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE vault_members SET role = 'owner'
                  WHERE vault_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            )
            .bind(Uuid::from(vault_id))
            .bind(Uuid::from(*user_id))
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE vaults SET owner_user_id = $2 WHERE id = $1")
                .bind(Uuid::from(vault_id))
                .bind(Uuid::from(*user_id))
                .execute(&mut *tx)
                .await?;
            AuditType::TeamOwnerTransferred
        }
        TeamLogOp::RotateKey { key_epoch } => {
            let new_vak = req
                .new_vault_access_key
                .as_ref()
                .ok_or_else(|| AppError::bad_request("new_vault_access_key is required"))?;
            if new_vak.len() != limits::VAULT_ACCESS_KEY_LEN {
                return Err(AppError::bad_request("vault_access_key must be 32 bytes"));
            }
            let link = req
                .chain_link
                .as_ref()
                .ok_or_else(|| AppError::bad_request("chain_link is required"))?;
            link.validate()
                .map_err(|e| AppError::bad_request(e.to_string()))?;
            if link.key_epoch != *key_epoch {
                return Err(AppError::bad_request("chain link epoch mismatch"));
            }
            // Exactly one envelope per live member.
            let mut expected: Vec<UserId> = st.members.keys().copied().collect();
            let mut got: Vec<UserId> = Vec::with_capacity(req.envelopes.len());
            for env in &req.envelopes {
                let user = env
                    .recipient_id
                    .map(UserId::from)
                    .ok_or_else(|| AppError::bad_request("user envelope without recipient"))?;
                validate_user_envelope(env, user)?;
                got.push(user);
            }
            expected.sort();
            got.sort();
            if expected != got {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "rotation must cover exactly the current members",
                ));
            }
            for env in &req.envelopes {
                store_user_envelope(&mut tx, vault_id, env, &auth, *key_epoch).await?;
            }
            sqlx::query(
                "INSERT INTO team_key_chain (vault_id, key_epoch, nonce, ciphertext)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(Uuid::from(vault_id))
            .bind(i32::try_from(*key_epoch).unwrap_or(i32::MAX))
            .bind(link.nonce.as_slice())
            .bind(link.ciphertext.as_slice())
            .execute(&mut *tx)
            .await?;
            let verifier = crypto::vault_access_key_verifier(new_vak.as_slice());
            sqlx::query(
                "UPDATE vaults SET key_epoch = $2, access_key_verifier = $3,
                                   rotation_required = false
                  WHERE id = $1",
            )
            .bind(Uuid::from(vault_id))
            .bind(i32::try_from(*key_epoch).unwrap_or(i32::MAX))
            .bind(&verifier[..])
            .execute(&mut *tx)
            .await?;
            rotated = Some(*key_epoch);
            AuditType::TeamKeyRotated
        }
    };
    insert_log(&mut tx, vault_id, &req.entry, &head).await?;
    sqlx::query("UPDATE vaults SET log_seq = $2, log_head = $3, updated_at = now() WHERE id = $1")
        .bind(Uuid::from(vault_id))
        .bind(i64::try_from(req.entry.entry.seq).unwrap_or(i64::MAX))
        .bind(&head[..])
        .execute(&mut *tx)
        .await?;
    AuditEvent::new(audit)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(vault_id)
        .ip(ip)
        .meta(serde_json::json!({"seq": req.entry.entry.seq}))
        .record(&mut *tx)
        .await?;
    let mut members = Vec::new();
    for m in live_members(&mut tx, vault_id).await? {
        members.push(member_dto(m)?);
    }
    // The leaving member can no longer load the team.
    let team = if removed == Some(auth.user_id) {
        None
    } else {
        Some(load_team(&mut *tx, &auth, vault_id).await?.info()?)
    };
    tx.commit().await?;

    let seq = req.entry.entry.seq;
    state
        .events
        .publish_vault(
            &state.db,
            vault_id,
            ServerEvent::TeamMembershipChanged {
                vault_id,
                log_seq: seq,
            },
        )
        .await;
    if let Some(user) = removed {
        state
            .events
            .publish_user(user, ServerEvent::TeamRemoved { vault_id })
            .await;
    }
    if let Some(key_epoch) = rotated {
        state
            .events
            .publish_vault(
                &state.db,
                vault_id,
                ServerEvent::TeamKeyRotated {
                    vault_id,
                    key_epoch,
                },
            )
            .await;
    }
    Ok(Json(SubmitTeamLogResponse {
        log_seq: seq,
        team,
        members: if team_visible(&removed, auth.user_id) {
            members
        } else {
            Vec::new()
        },
    }))
}

fn team_visible(removed: &Option<UserId>, caller: UserId) -> bool {
    *removed != Some(caller)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_are_bounded() {
        assert_eq!(validate_note(&None).unwrap(), None);
        assert_eq!(validate_note(&Some("  ".into())).unwrap(), None);
        assert_eq!(
            validate_note(&Some(" Ops ".into())).unwrap().as_deref(),
            Some("Ops")
        );
        assert!(validate_note(&Some("x".repeat(201))).is_err());
        assert!(validate_note(&Some("a\nb".into())).is_err());
    }
}
