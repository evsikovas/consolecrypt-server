// SPDX-License-Identifier: AGPL-3.0-only
use super::service;
use crate::{
    auth::AuthContext,
    error::AppResult,
    extract::{ApiJson, ApiPath, ApiQuery},
    AppState,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use cc_protocol::{sharing::*, ShareId};
use serde::Deserialize;

pub const BODY_LIMIT: usize = 2 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/shares/capabilities", get(capabilities))
        .route("/v1/shares/recipients", get(recipient))
        .route("/v1/shares", get(list).post(create))
        .route("/v1/shares/{id}", get(read))
        .route("/v1/shares/{id}/revisions", post(put))
        .route("/v1/shares/{id}/access", post(rotate))
        .route("/v1/shares/{id}/history", get(history))
        .merge(super::enrollment_handlers::routes())
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}
async fn capabilities(
    State(s): State<AppState>,
    a: AuthContext,
) -> AppResult<Json<SharingCapabilities>> {
    Ok(Json(service::capabilities(&s, &a).await?))
}
async fn create(
    State(s): State<AppState>,
    a: AuthContext,
    ApiJson(req): ApiJson<CreateShareRequest>,
) -> AppResult<(StatusCode, Json<SharedItemState>)> {
    Ok((
        StatusCode::CREATED,
        Json(service::create(&s, &a, req).await?),
    ))
}
async fn read(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
) -> AppResult<Json<SharedItemState>> {
    Ok(Json(service::get(&s, &a, id).await?))
}
async fn put(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiJson(req): ApiJson<PutSharedRevisionRequest>,
) -> AppResult<Json<SharedItemState>> {
    Ok(Json(service::put(&s, &a, id, req).await?))
}
async fn rotate(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiJson(req): ApiJson<RotateShareAccessRequest>,
) -> AppResult<Json<SharedItemState>> {
    Ok(Json(service::rotate(&s, &a, id, req).await?))
}
fn page_limit() -> u32 {
    100
}
#[derive(Deserialize)]
struct ListQuery {
    after: Option<ShareId>,
    #[serde(default)]
    include_groups: bool,
    #[serde(default)]
    include_secrets: bool,
    #[serde(default = "page_limit")]
    limit: u32,
}
async fn list(
    State(s): State<AppState>,
    a: AuthContext,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> AppResult<Json<ShareListPage>> {
    Ok(Json(
        service::list_with_kinds(
            &s,
            &a,
            q.after,
            q.limit,
            service::ListKinds {
                include_groups: q.include_groups,
                include_secrets: q.include_secrets,
            },
        )
        .await?,
    ))
}
#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    after_manifest: u64,
    #[serde(default)]
    after_revision: i64,
    #[serde(default = "page_limit")]
    limit: u32,
}
async fn history(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiQuery(q): ApiQuery<HistoryQuery>,
) -> AppResult<Json<ShareHistoryPage>> {
    Ok(Json(
        service::history(&s, &a, id, q.after_manifest, q.after_revision, q.limit).await?,
    ))
}
#[derive(Deserialize)]
struct RecipientQuery {
    email: String,
}
async fn recipient(
    State(s): State<AppState>,
    a: AuthContext,
    ApiQuery(q): ApiQuery<RecipientQuery>,
) -> AppResult<Json<SharingRecipient>> {
    Ok(Json(service::recipient(&s, &a, &q.email).await?))
}
