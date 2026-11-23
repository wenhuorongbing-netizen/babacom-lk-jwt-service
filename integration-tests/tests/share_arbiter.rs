// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::time::Duration;

use livekit_protocol::{ParticipantInfo, ParticipantPermission, TrackInfo, TrackSource};
use lk_jwt_service_integration_tests::{
    APP_SERVICE_AS_TOKEN, FakeHomeserver, FakeSfu, FakeUser, Service, ServiceConfig,
    app_service_env, decode_livekit_jwt, expect_is_joined_request, expect_matrix_error,
    legacy_livekit_identity, livekit_room_alias, send_sfu_webhook,
};
use serde_json::{Value, json};

const ROOM_ID: &str = "!room:example.com";
const SLOT_ID: &str = "m.call#ROOM";
const MEMBER_ID: &str = "member-1";
const DEVICE_ID: &str = "DEVICE";

fn share_request(hs: &FakeHomeserver, user: &FakeUser) -> Value {
    json!({
        "room_id": ROOM_ID,
        "slot_id": SLOT_ID,
        "member_id": MEMBER_ID,
        "device_id": DEVICE_ID,
        "attempt_id": format!("{}-1", user.user_id),
        "openid_token": {
            "access_token": user.openid_token,
            "token_type": "Bearer",
            "matrix_server_name": hs.server_name(),
            "expires_in": 3600,
        },
    })
}

async fn post(svc: &Service, path: &str, body: &Value) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("{}{path}", svc.base_url))
        .json(body)
        .send()
        .await
        .expect("request failed");
    (response.status().as_u16(), response.text().await.unwrap())
}

async fn start(hs: &FakeHomeserver, sfu: &FakeSfu, enabled: bool) -> Service {
    let mut extra_env = app_service_env(hs);
    extra_env.insert("BABACOM_SHARE_ARBITER".into(), enabled.to_string());
    extra_env.insert("BABACOM_SHARE_REVOKE_TIMEOUT_MS".into(), "750".into());
    Service::start(ServiceConfig {
        full_access_homeservers: vec![hs.server_name().to_owned()],
        cs_api_url_overrides: hs.cs_api_url_override(),
        livekit_url: Some(sfu.url().to_owned()),
        extra_env,
        ..Default::default()
    })
    .await
}

fn base_permission() -> ParticipantPermission {
    ParticipantPermission {
        can_publish_sources: vec![TrackSource::Camera as i32, TrackSource::Microphone as i32],
        can_publish: true,
        can_subscribe: true,
        can_publish_data: true,
        ..Default::default()
    }
}

/// Request a standalone join JWT, then simulate the participant joining the SFU.
///
/// The JWT identity must be the one MatrixRTC clients derive from a membership
/// (user, device, member); otherwise remote clients cannot match the participant.
async fn join(svc: &Service, sfu: &FakeSfu, hs: &FakeHomeserver, user: &FakeUser) -> String {
    let room = livekit_room_alias(ROOM_ID, SLOT_ID);
    let identity = legacy_livekit_identity(&user.user_id, DEVICE_ID, MEMBER_ID);
    let mut request = share_request(hs, user);
    let fields = request.as_object_mut().unwrap();
    fields.remove("member_id");
    fields.remove("device_id");
    fields.remove("attempt_id");
    request["member"] = json!({
        "id": MEMBER_ID,
        "claimed_user_id": user.user_id,
        "claimed_device_id": DEVICE_ID,
    });
    let (status, body) = post(svc, "/get_token", &request).await;
    assert_eq!(status, 200, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    let token = decode_livekit_jwt(response["jwt"].as_str().unwrap());
    assert_eq!(token["sub"], json!(&identity));
    assert_eq!(token["video"]["room"], json!(&room));
    assert_eq!(
        token["video"]["canPublishSources"],
        json!(["camera", "microphone"])
    );
    sfu.set_participant_info(
        &room,
        ParticipantInfo {
            identity: identity.clone(),
            permission: Some(base_permission()),
            ..Default::default()
        },
    );
    identity
}

#[track_caller]
fn expect_state((status, body): (u16, String), expected: &str) {
    assert_eq!(status, 200, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response, json!({ "state": expected }));
}

#[tokio::test]
async fn one_holder_can_share_until_release() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let bob = hs.new_user("bob");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, true).await;
    let room = livekit_room_alias(ROOM_ID, SLOT_ID);
    let alice_identity = join(&svc, &sfu, &hs, &alice).await;
    let bob_identity = join(&svc, &sfu, &hs, &bob).await;
    let alice_request = share_request(&hs, &alice);
    let bob_request = share_request(&hs, &bob);

    expect_state(
        post(&svc, "/babacom/share/claim", &alice_request).await,
        "held",
    );
    let mut granted = base_permission();
    granted.can_publish_sources.extend([
        TrackSource::ScreenShare as i32,
        TrackSource::ScreenShareAudio as i32,
    ]);
    assert_eq!(
        sfu.participant_info(&room, &alice_identity)
            .unwrap()
            .permission,
        Some(granted)
    );
    let (status, body) = post(&svc, "/babacom/share/claim", &bob_request).await;
    expect_matrix_error(status, &body, 409, "IO.BABACOM.SHARE_BUSY");
    assert_eq!(
        sfu.participant_info(&room, &bob_identity)
            .unwrap()
            .permission,
        Some(base_permission())
    );

    expect_state(
        post(&svc, "/babacom/share/release", &alice_request).await,
        "free",
    );
    assert_eq!(
        sfu.participant_info(&room, &alice_identity)
            .unwrap()
            .permission,
        Some(base_permission())
    );
    expect_state(
        post(&svc, "/babacom/share/claim", &bob_request).await,
        "held",
    );
}

#[tokio::test]
async fn lingering_screen_audio_blocks_claim_until_revocation_is_confirmed() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let bob = hs.new_user("bob");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, true).await;
    let room = livekit_room_alias(ROOM_ID, SLOT_ID);
    let alice_identity = join(&svc, &sfu, &hs, &alice).await;
    join(&svc, &sfu, &hs, &bob).await;
    let alice_request = share_request(&hs, &alice);
    let bob_request = share_request(&hs, &bob);

    expect_state(
        post(&svc, "/babacom/share/claim", &alice_request).await,
        "held",
    );
    let mut alice_participant = sfu.participant_info(&room, &alice_identity).unwrap();
    alice_participant.tracks.push(TrackInfo {
        source: TrackSource::ScreenShareAudio as i32,
        ..Default::default()
    });
    sfu.set_participant_info(&room, alice_participant);

    let (status, body) = post(&svc, "/babacom/share/release", &alice_request).await;
    expect_matrix_error(status, &body, 409, "IO.BABACOM.SHARE_UNKNOWN");
    let (status, body) = post(&svc, "/babacom/share/claim", &bob_request).await;
    expect_matrix_error(status, &body, 409, "IO.BABACOM.SHARE_UNKNOWN");
    let mut alice_participant = sfu.participant_info(&room, &alice_identity).unwrap();
    assert_eq!(alice_participant.permission, Some(base_permission()));
    alice_participant.tracks.clear();
    sfu.set_participant_info(&room, alice_participant);

    expect_state(
        post(&svc, "/babacom/share/release", &alice_request).await,
        "free",
    );
    expect_state(
        post(&svc, "/babacom/share/claim", &bob_request).await,
        "held",
    );
}

#[tokio::test]
async fn claim_requires_verified_room_membership_and_an_sfu_participant() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let bob = hs.new_user("bob");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, true).await;
    join(&svc, &sfu, &hs, &alice).await;
    hs.set_not_joined(ROOM_ID, &alice.user_id);
    let joined_checks_before_claim = hs.is_joined_requests().len();

    let (status, body) = post(&svc, "/babacom/share/claim", &share_request(&hs, &alice)).await;
    expect_matrix_error(status, &body, 403, "M_FORBIDDEN");
    assert_eq!(
        hs.is_joined_requests().len(),
        joined_checks_before_claim + 1
    );
    expect_is_joined_request(&hs, ROOM_ID, &alice.user_id, APP_SERVICE_AS_TOKEN);

    let (status, body) = post(&svc, "/babacom/share/claim", &share_request(&hs, &bob)).await;
    expect_matrix_error(status, &body, 409, "IO.BABACOM.NOT_IN_CALL");
}

#[tokio::test]
async fn claim_targets_the_device_that_joined() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, true).await;
    join(&svc, &sfu, &hs, &alice).await;

    let mut missing_device = share_request(&hs, &alice);
    missing_device.as_object_mut().unwrap().remove("device_id");
    let (status, body) = post(&svc, "/babacom/share/claim", &missing_device).await;
    expect_matrix_error(status, &body, 400, "M_BAD_JSON");

    // Another device of the same user is a different participant.
    let mut other_device = share_request(&hs, &alice);
    other_device["device_id"] = json!("OTHER");
    let (status, body) = post(&svc, "/babacom/share/claim", &other_device).await;
    expect_matrix_error(status, &body, 409, "IO.BABACOM.NOT_IN_CALL");

    expect_state(
        post(&svc, "/babacom/share/claim", &share_request(&hs, &alice)).await,
        "held",
    );
}

#[tokio::test]
async fn leave_webhook_checks_that_the_holder_is_absent() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let bob = hs.new_user("bob");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, true).await;
    let room = livekit_room_alias(ROOM_ID, SLOT_ID);
    let identity = join(&svc, &sfu, &hs, &alice).await;
    join(&svc, &sfu, &hs, &bob).await;

    expect_state(
        post(&svc, "/babacom/share/claim", &share_request(&hs, &alice)).await,
        "held",
    );
    let reads = sfu.get_participant_requests().len();
    sfu.set_participant_absent(&room, &identity);
    send_sfu_webhook(&svc, "participant_left", &room, &identity, None).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if sfu
                .get_participant_requests()
                .iter()
                .skip(reads)
                .any(|request| request.room == room && request.identity == identity)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("webhook should trigger a presence lookup");

    expect_state(
        post(&svc, "/babacom/share/claim", &share_request(&hs, &bob)).await,
        "held",
    );
}

#[tokio::test]
async fn a_claim_that_arrives_after_its_release_is_refused() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, true).await;
    join(&svc, &sfu, &hs, &alice).await;
    let request = share_request(&hs, &alice);

    expect_state(post(&svc, "/babacom/share/release", &request).await, "free");
    let (status, body) = post(&svc, "/babacom/share/claim", &request).await;
    expect_matrix_error(status, &body, 409, "IO.BABACOM.SHARE_STALE");

    let mut next_attempt = request;
    next_attempt["attempt_id"] = json!("alice-2");
    expect_state(
        post(&svc, "/babacom/share/claim", &next_attempt).await,
        "held",
    );
}

#[tokio::test]
async fn a_rejoin_with_stale_screen_rights_is_stripped() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let bob = hs.new_user("bob");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, true).await;
    let room = livekit_room_alias(ROOM_ID, SLOT_ID);
    let alice_identity = join(&svc, &sfu, &hs, &alice).await;
    let bob_identity = join(&svc, &sfu, &hs, &bob).await;
    expect_state(
        post(&svc, "/babacom/share/claim", &share_request(&hs, &bob)).await,
        "held",
    );

    // Alice reconnects with a refreshed token from an earlier share.
    let screen_sources = vec![
        TrackSource::Camera as i32,
        TrackSource::Microphone as i32,
        TrackSource::ScreenShare as i32,
        TrackSource::ScreenShareAudio as i32,
    ];
    sfu.set_participant_info(
        &room,
        ParticipantInfo {
            identity: alice_identity.clone(),
            permission: Some(ParticipantPermission {
                can_publish_sources: screen_sources.clone(),
                ..base_permission()
            }),
            ..Default::default()
        },
    );
    send_sfu_webhook(&svc, "participant_joined", &room, &alice_identity, None).await;

    let sources = |identity: &str| {
        sfu.participant_info(&room, identity)
            .and_then(|info| info.permission)
            .map(|permission| permission.can_publish_sources)
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while sources(&alice_identity) != Some(base_permission().can_publish_sources) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the stale screen rights should be removed");
    assert_eq!(sources(&bob_identity), Some(screen_sources));
}

#[tokio::test]
async fn share_routes_are_absent_when_disabled() {
    let hs = FakeHomeserver::new().await;
    let alice = hs.new_user("alice");
    let sfu = FakeSfu::new().await;
    let svc = start(&hs, &sfu, false).await;
    let request = share_request(&hs, &alice);

    assert_eq!(post(&svc, "/babacom/share/claim", &request).await.0, 404);
    assert_eq!(post(&svc, "/babacom/share/release", &request).await.0, 404);
}
