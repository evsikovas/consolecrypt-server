//! Explicit operator restore reconciliation. Ordinary rotate-epoch semantics
//! remain unchanged. NEVER infer a missing highest policy from a rolled-back DB.
use super::*;
use crate::events::Events;
use cc_protocol::events::ServerEvent;
use std::collections::BTreeSet;
#[derive(Debug)]
pub struct RestoreQuarantineReport {
    pub accounts: usize,
    pub vaults: usize,
}
/// Caller is the local admin CLI, never a guest/HTTP policy boolean. Accounts
/// are explicit restored UserIds, not ProfileIds, names or an implicit all-users
/// scope. Floor is an explicit operator declaration from a trusted outside
/// witness/manual release review; correctness cannot be proven by this DB.
pub async fn quarantine_restored_accounts(
    pool: &sqlx::PgPool,
    accounts: &[UserId],
    declared_floor: &str,
) -> AppResult<RestoreQuarantineReport> {
    let declared = ClientVersion::release(declared_floor)
        .ok_or_else(|| AppError::bad_request("a stable declared restore floor is required"))?;
    let ids: BTreeSet<Uuid> = accounts.iter().map(|id| Uuid::from(*id)).collect();
    if ids.is_empty()
        || ids.len() > 64
        || ids.len() != accounts.len()
        || ids.iter().any(Uuid::is_nil)
    {
        return Err(AppError::bad_request(
            "explicit unique restored accounts are required",
        ));
    }
    let ids: Vec<_> = ids.into_iter().collect();
    let mut tx = pool.begin().await?;
    // Same universal order as opt-in/push/registration, account IDs sorted.
    let found: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
    if found != ids {
        return Err(AppError::not_found());
    }
    let vaults: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT s.vault_id,s.last_sequence FROM vault_sequences s JOIN vaults v ON v.id=s.vault_id
       WHERE v.owner_user_id=ANY($1) AND v.kind='personal' AND v.state='active'
       ORDER BY s.vault_id LIMIT 1025 FOR UPDATE OF s",
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;
    let active_accounts:i64=sqlx::query_scalar("SELECT count(DISTINCT owner_user_id) FROM vaults WHERE owner_user_id=ANY($1) AND kind='personal' AND state='active'")
      .bind(&ids).fetch_one(&mut *tx).await?;
    if active_accounts as usize != ids.len() {
        return Err(AppError::bad_request(
            "each restored account requires an active personal vault",
        ));
    }
    if vaults.len() > 1024 {
        return Err(AppError::bad_request("restored scope exceeds vault budget"));
    }
    for id in &ids {
        let previous:Option<(i32,i64,Option<String>)>=sqlx::query_as("SELECT version,revision,minimum_client_version FROM account_monitoring_compatibility WHERE user_id=$1")
          .bind(id).fetch_optional(&mut *tx).await?;
        let (revision, minimum) = match previous {
            None => (1, declared),
            Some((schema, revision, minimum)) => {
                if schema != 1 {
                    return Err(quarantined());
                }
                if revision < 1 || revision == i64::MAX {
                    return Err(quarantined());
                }
                let minimum = match minimum {
                    Some(text) => {
                        declared.max(ClientVersion::release(&text).ok_or_else(quarantined)?)
                    }
                    None => declared,
                };
                (revision + 1, minimum)
            }
        };
        sqlx::query("INSERT INTO account_monitoring_compatibility(user_id,revision,minimum_client_version,quarantined)
          VALUES($1,$2,$3,true) ON CONFLICT(user_id) DO UPDATE SET revision=EXCLUDED.revision,
          minimum_client_version=EXCLUDED.minimum_client_version,quarantined=true,updated_at=now()")
          .bind(id).bind(revision).bind(minimum.to_string()).execute(&mut *tx).await?;
    }
    crate::audit::AuditEvent::new(crate::audit::AuditType::MonitoringCompatibilityQuarantined)
      .meta(serde_json::json!({"accounts":ids.len(),"vaults":vaults.len(),"declared_minimum":declared.to_string(),
        "source":"explicit_operator_restore_declaration"})).record(&mut *tx).await?;
    let vault_ids: Vec<_> = vaults.iter().map(|(id, _)| *id).collect();
    sqlx::query("UPDATE vaults SET epoch=gen_random_uuid(),updated_at=now() WHERE id=ANY($1)")
        .bind(&vault_ids)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let events = Events::publisher(pool);
    for (id, sequence) in &vaults {
        let vault_id = VaultId::from(*id);
        events
            .publish_vault(
                pool,
                vault_id,
                ServerEvent::VaultChanged {
                    vault_id,
                    latest_sequence: *sequence,
                },
            )
            .await;
    }
    Ok(RestoreQuarantineReport {
        accounts: ids.len(),
        vaults: vaults.len(),
    })
}
