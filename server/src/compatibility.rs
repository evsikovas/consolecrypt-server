//! Explicit personal-account compatibility opt-in. Versions are self-reports,
//! not software attestation. This metadata never decrypts/inspects vault objects.
use crate::error::{AppError, AppResult};
use axum::http::HeaderMap;
use cc_protocol::{ErrorCode, UserId, VaultId};
use semver::Version;
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

pub mod handlers;
pub mod restore;
/// Fixed, bounded current-request version carried with AuthContext. No raw
/// header/PII retained and no registration-version fallback for missing headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClientVersion(pub u64, pub u64, pub u64);
impl ClientVersion {
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > 64 || text.trim() != text {
            return None;
        }
        let version = Version::parse(text).ok()?;
        version
            .pre
            .is_empty()
            .then_some(Self(version.major, version.minor, version.patch))
    }
    pub fn release(text: &str) -> Option<Self> {
        if text.len() > 64 || text.trim() != text {
            return None;
        }
        let version = Version::parse(text).ok()?;
        if !version.build.is_empty() {
            return None;
        }
        Self::parse(text)
    }
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        Self::parse(
            headers
                .get(cc_protocol::version::HEADER_CLIENT_VERSION)?
                .to_str()
                .ok()?,
        )
    }
}
impl std::fmt::Display for ClientVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}
pub fn required() -> AppError {
    AppError::new(
        ErrorCode::UpgradeRequired,
        "compatible application required",
    )
    .with_details(serde_json::json!({"reason":"monitoring_compatibility_required"}))
}
pub fn quarantined() -> AppError {
    AppError::new(
        ErrorCode::UpgradeRequired,
        "restored compatibility scope requires review",
    )
    .with_details(serde_json::json!({"reason":"monitoring_compatibility_quarantined"}))
}
/// Existing account row is the common transaction boundary; never a process
/// mutex or database-wide lock. Take BEFORE vault sequences/device/session rows.
pub async fn lock_account(conn: &mut PgConnection, user: UserId) -> AppResult<()> {
    let found: Option<Uuid> =
        sqlx::query_scalar("/* cc.compat.account */ SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(Uuid::from(user))
            .fetch_optional(conn)
            .await?;
    if found.is_none() {
        return Err(AppError::not_found());
    }
    Ok(())
}
/// Checks are unconditional for stored opted scopes, including if an operator
/// later removes the configured offer. Removing configuration is NOT opt-out.
pub async fn check<'e>(
    db: impl PgExecutor<'e>,
    user: UserId,
    version: Option<ClientVersion>,
) -> AppResult<()> {
    let row:Option<(i32,Option<String>,bool)>=sqlx::query_as(
      "SELECT version,minimum_client_version,quarantined FROM account_monitoring_compatibility WHERE user_id=$1")
      .bind(Uuid::from(user)).fetch_optional(db).await?;
    if let Some((schema, minimum, is_quarantined)) = row {
        if schema != 1 {
            return Err(quarantined());
        }
        if is_quarantined {
            return Err(quarantined());
        }
        let floor = minimum
            .as_deref()
            .and_then(ClientVersion::release)
            .ok_or_else(quarantined)?;
        if version.is_none_or(|actual| actual < floor) {
            return Err(required());
        }
    }
    Ok(())
}
/// Compatible sign-in/refresh may obtain account metadata during quarantine,
/// so the owner can review/reconcile. Vault data remains blocked by check().
pub async fn check_admission<'e>(
    db: impl PgExecutor<'e>,
    user: UserId,
    version: Option<ClientVersion>,
) -> AppResult<()> {
    let row: Option<(i32,Option<String>)> = sqlx::query_as(
        "SELECT version,minimum_client_version FROM account_monitoring_compatibility WHERE user_id=$1",
    )
    .bind(Uuid::from(user))
    .fetch_optional(db)
    .await?;
    if let Some((schema, minimum)) = row {
        if schema != 1 {
            return Err(quarantined());
        }
        let floor = minimum
            .as_deref()
            .and_then(ClientVersion::release)
            .ok_or_else(quarantined)?;
        if version.is_none_or(|actual| actual < floor) {
            return Err(required());
        }
    }
    Ok(())
}
pub async fn check_vault<'e>(
    db: impl PgExecutor<'e>,
    vault: VaultId,
    version: Option<ClientVersion>,
) -> AppResult<()> {
    // One statement, so the owner/policy pair is coherent even for page reads.
    let row: Option<(i32, Option<String>, bool)> = sqlx::query_as(
        "SELECT p.version,p.minimum_client_version,p.quarantined FROM account_monitoring_compatibility p
       JOIN vaults v ON v.owner_user_id=p.user_id WHERE v.id=$1 AND v.kind='personal'",
    )
    .bind(Uuid::from(vault))
    .fetch_optional(db)
    .await?;
    if let Some((schema, minimum, is_quarantined)) = row {
        if schema != 1 {
            return Err(quarantined());
        }
        if is_quarantined {
            return Err(quarantined());
        }
        if version.is_none_or(|actual| {
            minimum
                .as_deref()
                .and_then(ClientVersion::release)
                .is_none_or(|floor| actual < floor)
        }) {
            return Err(required());
        }
    }
    Ok(())
}
/// Called in account-locked grant transactions, before any target envelope.
/// Existing stored target metadata is checked as well as the caller header.
pub async fn check_device(
    conn: &mut PgConnection,
    user: UserId,
    device: cc_protocol::DeviceId,
) -> AppResult<()> {
    let row: Option<(Option<String>, bool)> = sqlx::query_as(
        "SELECT client_version,revoked_at IS NOT NULL FROM devices WHERE id=$1 AND user_id=$2",
    )
    .bind(Uuid::from(device))
    .bind(Uuid::from(user))
    .fetch_optional(&mut *conn)
    .await?;
    let (version, revoked) = row.ok_or_else(AppError::not_found)?;
    if revoked {
        return Err(AppError::device_revoked());
    }
    check(
        conn,
        user,
        version.as_deref().and_then(ClientVersion::parse),
    )
    .await
}
/// Exact typed recovery allowlist. No starts_with route-family exemptions.
#[derive(Clone, Copy, Debug)]
enum Bootstrap {
    AccountMetadata,
    Roster,
    PersonalList,
    PersonalVault(VaultId),
    RecoveryEnvelope,
    SelfAttest,
}
fn canonical_vault(text: &str) -> Option<VaultId> {
    let id = Uuid::parse_str(text).ok()?;
    (!id.is_nil() && id.to_string() == text).then_some(VaultId::from(id))
}
fn bootstrap(
    method: &axum::http::Method,
    path: &str,
    own: cc_protocol::DeviceId,
) -> Option<Bootstrap> {
    use axum::http::Method;
    if path.len() > 128 {
        return None;
    }
    let parts: Vec<_> = path.split('/').collect();
    match (method, parts.as_slice()) {
        (&Method::GET, ["", "v1", "auth", "me"]) => Some(Bootstrap::AccountMetadata),
        (&Method::GET, ["", "v1", "devices"]) => Some(Bootstrap::Roster),
        (&Method::GET, ["", "v1", "vaults"]) => Some(Bootstrap::PersonalList),
        (&Method::GET, ["", "v1", "vaults", id]) => {
            canonical_vault(id).map(Bootstrap::PersonalVault)
        }
        (&Method::GET, ["", "v1", "vaults", id, "envelopes"]) => {
            canonical_vault(id).map(Bootstrap::PersonalVault)
        }
        (&Method::GET, ["", "v1", "recovery", "vault", "envelope"]) => {
            Some(Bootstrap::RecoveryEnvelope)
        }
        (&Method::POST, ["", "v1", "devices", id, "attest"]) if *id == own.to_string() => {
            Some(Bootstrap::SelfAttest)
        }
        _ => None,
    }
}
pub async fn is_quarantined<'e>(db: impl PgExecutor<'e>, user: UserId) -> AppResult<bool> {
    let row: Option<(i32, bool)> = sqlx::query_as(
        "SELECT version,quarantined FROM account_monitoring_compatibility WHERE user_id=$1",
    )
    .bind(Uuid::from(user))
    .fetch_optional(db)
    .await?;
    match row {
        Some((version, _)) if version != 1 => Err(quarantined()),
        Some((_, value)) => Ok(value),
        None => Ok(false),
    }
}
/// Only during quarantine: this exact bootstrap vault must be OWN personal,
/// not a team or another account's vault. Existing key/access proofs still run.
pub async fn bootstrap_vault<'e>(
    db: impl PgExecutor<'e>,
    user: UserId,
    vault: VaultId,
) -> AppResult<()> {
    let allowed:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM account_monitoring_compatibility WHERE user_id=$1 AND quarantined)
       OR EXISTS(SELECT 1 FROM vaults WHERE id=$2 AND owner_user_id=$1 AND kind='personal' AND state<>'deleted')")
      .bind(Uuid::from(user)).bind(Uuid::from(vault)).fetch_one(db).await?;
    if !allowed {
        return Err(AppError::not_found());
    }
    Ok(())
}
/// Policy check after request-proof verification; legacy security logout remains
/// available. Stored version touches share the account transaction barrier too.
pub async fn observe_request(
    state: &crate::AppState,
    auth: &crate::auth::AuthContext,
    parts: &axum::http::request::Parts,
) -> AppResult<()> {
    let path = parts.uri.path();
    let security_revoke = path
        .strip_prefix("/v1/devices/")
        .and_then(|p| p.strip_suffix("/revoke"))
        .is_some_and(|id| {
            Uuid::parse_str(id).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == id)
        });
    if path == cc_protocol::paths::AUTH_LOGOUT || security_revoke {
        return Ok(());
    }
    let compatibility = path
        .strip_prefix("/v1/vaults/")
        .and_then(|p| p.strip_suffix("/compatibility/monitoring-settings"))
        .is_some_and(|id| {
            Uuid::parse_str(id).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == id)
        });
    let recovery = bootstrap(&parts.method, path, auth.device_id);
    if compatibility || recovery.is_some() {
        check_admission(&state.db, auth.user_id, auth.client_version).await?;
    } else {
        check(&state.db, auth.user_id, auth.client_version).await?;
    }
    if let Some(Bootstrap::PersonalVault(vault)) = recovery {
        bootstrap_vault(&state.db, auth.user_id, vault).await?;
    }
    if compatibility || state.should_touch_device(auth.device_id) {
        let raw = parts
            .headers
            .get(cc_protocol::version::HEADER_CLIENT_VERSION)
            .and_then(|h| h.to_str().ok())
            // Persist the honest bounded report even when it is prerelease/
            // unknown: do not leave an obsolete stable roster value behind.
            // Admission above still requires parsed CURRENT stable version.
            .map(str::trim)
            .filter(|text| {
                !text.is_empty() && text.len() <= 64 && text.bytes().all(|b| b.is_ascii_graphic())
            });
        let mut tx = state.db.begin().await?;
        lock_account(&mut tx, auth.user_id).await?;
        if compatibility || recovery.is_some() {
            check_admission(&mut *tx, auth.user_id, auth.client_version).await?;
        } else {
            check(&mut *tx, auth.user_id, auth.client_version).await?;
        }
        sqlx::query("UPDATE devices SET last_seen_at=now(),client_version=COALESCE($2,client_version) WHERE id=$1 AND user_id=$3")
          .bind(Uuid::from(auth.device_id)).bind(raw).bind(Uuid::from(auth.user_id)).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offer_defaults_off_and_requires_an_explicit_stable_floor_and_strict_proofs() {
        let mut config = crate::Config::for_tests("postgres://localhost/owned-config-fixture");
        assert!(config.monitoring_preservation_minimum.is_none());
        config.monitoring_preservation_minimum = Some("2.0.0-beta".into());
        assert!(config.validate().is_err());
        config.monitoring_preservation_minimum = Some("2.0.0".into());
        assert!(config.validate().is_ok());
        config.require_request_proof = false;
        assert!(config.validate().is_err());
    }
    #[test]
    fn stable_reports_are_bounded_and_release_floor_has_no_prerelease_or_build() {
        assert_eq!(
            ClientVersion::parse("2.3.4+build.7"),
            Some(ClientVersion(2, 3, 4))
        );
        assert_eq!(
            ClientVersion::release("2.3.4"),
            Some(ClientVersion(2, 3, 4))
        );
        for invalid in ["", " 2.3.4", "02.3.4", "2.3", "2.3.4-beta", "3.0.0-beta.1"] {
            assert!(ClientVersion::parse(invalid).is_none());
        }
        assert!(ClientVersion::parse(&"x".repeat(65)).is_none());
        assert!(ClientVersion::release("2.3.4+build").is_none());
    }
}
