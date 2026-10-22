// SPDX-License-Identifier: AGPL-3.0-only
//! Protocol 1.8: recipient lookup with the e-mail in a POST body.
mod common;
use cc_protocol::sharing::{SharingRecipient, RECIPIENT_LOOKUP_PATH};
use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn post_lookup_matches_the_deprecated_get_without_a_query_string() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let other = srv.new_account().await;
    for user in [owner.user_id, other.user_id] {
        sqlx::query("UPDATE users SET email_verified_at=now() WHERE id=$1")
            .bind(Uuid::from(user))
            .execute(&srv.state.db)
            .await
            .unwrap();
    }
    let (_, meta) = srv.get("/v1/meta", &owner.access).await;
    assert_eq!(meta["capabilities"]["recipient_lookup_post"], true);

    let (code, posted) = srv
        .post(
            RECIPIENT_LOOKUP_PATH,
            Some(&owner.access),
            &json!({ "email": format!("  {}  ", other.email.to_uppercase()) }),
        )
        .await;
    assert_eq!(code, StatusCode::OK);
    let posted: SharingRecipient = serde_json::from_value(posted).unwrap();
    assert_eq!(posted.user_id, other.user_id);
    let (code, legacy) = srv
        .get(
            &format!("/v1/shares/recipients?email={}", other.email),
            &owner.access,
        )
        .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<SharingRecipient>(legacy).unwrap(),
        posted
    );

    let (code, body) = srv
        .post(
            RECIPIENT_LOOKUP_PATH,
            Some(&owner.access),
            &json!({ "email": "nobody@example.invalid" }),
        )
        .await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert!(!body.to_string().contains("nobody"));
    // Unknown fields and missing auth are refused without echoing input.
    let (code, body) = srv
        .post(
            RECIPIENT_LOOKUP_PATH,
            Some(&owner.access),
            &json!({ "email": other.email, "extra": "secret-marker" }),
        )
        .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(!body.to_string().contains("secret-marker"));
    assert!(!body.to_string().contains(&other.email));
    assert_eq!(
        srv.post(
            RECIPIENT_LOOKUP_PATH,
            None,
            &json!({ "email": other.email })
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );

    let off = server!();
    let account = off.new_account().await;
    let (_, meta) = off.get("/v1/meta", &account.access).await;
    assert_eq!(meta["capabilities"]["recipient_lookup_post"], false);
    assert_eq!(
        off.post(
            RECIPIENT_LOOKUP_PATH,
            Some(&account.access),
            &json!({ "email": other.email })
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}
