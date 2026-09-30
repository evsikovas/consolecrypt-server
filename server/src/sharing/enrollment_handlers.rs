// SPDX-License-Identifier: AGPL-3.0-only
use super::enrollment;
use crate::{
    auth::AuthContext,
    error::AppResult,
    extract::{ApiJson, ApiPath, ApiQuery},
    AppState,
};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use cc_protocol::{sharing_enrollment::*, ShareId};
use serde::Deserialize;
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/shares/{id}/own-device-grants",
            get(list_grants).post(publish_grant),
        )
        .route("/v1/shares/{id}/own-device-grants/{grant}", get(get_grant))
        .route(
            "/v1/shares/{id}/own-device-grants/{grant}/history",
            get(grant_history),
        )
        .route(
            "/v1/shares/{id}/own-device-requests",
            get(list_requests).post(submit_request),
        )
        .route(
            "/v1/shares/{id}/own-device-requests/{request}",
            get(get_request),
        )
        .route(
            "/v1/shares/{id}/own-device-requests/{request}/challenge",
            post(publish_challenge),
        )
        .route(
            "/v1/shares/{id}/own-device-requests/{request}/response",
            post(submit_response),
        )
        .route(
            "/v1/shares/{id}/own-device-requests/{request}/accept",
            post(accept_request),
        )
}
fn page_limit() -> u32 {
    100
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    after: Option<Uuid>,
    #[serde(default = "page_limit")]
    limit: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    #[serde(default)]
    after_revision: u64,
    #[serde(default = "page_limit")]
    limit: u32,
}
async fn publish_grant(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiJson(req): ApiJson<PublishOwnDevicesGrantRequest>,
) -> AppResult<Json<SignedSharingOwnDevicesGrantState>> {
    Ok(Json(enrollment::publish_grant(&s, &a, id, req).await?))
}
async fn submit_request(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiJson(req): ApiJson<SubmitOwnDeviceRequest>,
) -> AppResult<Json<OwnDeviceRequestState>> {
    Ok(Json(enrollment::submit_request(&s, &a, id, req).await?))
}
async fn publish_challenge(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath((id, request)): ApiPath<(ShareId, Uuid)>,
    ApiJson(req): ApiJson<PublishOwnDeviceChallengeRequest>,
) -> AppResult<Json<OwnDeviceRequestState>> {
    Ok(Json(
        enrollment::publish_challenge(&s, &a, id, request, req).await?,
    ))
}
async fn submit_response(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath((id, request)): ApiPath<(ShareId, Uuid)>,
    ApiJson(req): ApiJson<SubmitOwnDeviceChallengeResponseRequest>,
) -> AppResult<Json<OwnDeviceRequestState>> {
    Ok(Json(
        enrollment::submit_response(&s, &a, id, request, req).await?,
    ))
}
async fn accept_request(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath((id, request)): ApiPath<(ShareId, Uuid)>,
    ApiJson(req): ApiJson<AcceptOwnDeviceRequest>,
) -> AppResult<Json<OwnDeviceAcceptanceResult>> {
    Ok(Json(
        enrollment::accept_request(&s, &a, id, request, req).await?,
    ))
}
async fn get_grant(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath((id, child)): ApiPath<(ShareId, Uuid)>,
) -> AppResult<Json<SignedSharingOwnDevicesGrantState>> {
    Ok(Json(enrollment::get_grant(&s, &a, id, child).await?))
}
async fn get_request(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath((id, child)): ApiPath<(ShareId, Uuid)>,
) -> AppResult<Json<OwnDeviceRequestState>> {
    Ok(Json(enrollment::get_request(&s, &a, id, child).await?))
}
async fn list_grants(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> AppResult<Json<OwnDevicesGrantPage>> {
    Ok(Json(
        enrollment::list_grants(&s, &a, id, q.after, q.limit).await?,
    ))
}
async fn list_requests(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> AppResult<Json<OwnDeviceRequestPage>> {
    Ok(Json(
        enrollment::list_requests(&s, &a, id, q.after, q.limit).await?,
    ))
}
async fn grant_history(
    State(s): State<AppState>,
    a: AuthContext,
    ApiPath((id, grant)): ApiPath<(ShareId, Uuid)>,
    ApiQuery(q): ApiQuery<HistoryQuery>,
) -> AppResult<Json<OwnDevicesGrantHistoryPage>> {
    Ok(Json(
        enrollment::grant_history(&s, &a, id, grant, q.after_revision, q.limit).await?,
    ))
}
