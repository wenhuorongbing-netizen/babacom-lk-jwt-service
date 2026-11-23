// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Serializes screen-share permission changes and reconciles them with LiveKit.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use livekit_protocol::{ParticipantInfo, ParticipantPermission, TrackSource};
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout, timeout_at};
use tracing::{debug, warn};

use crate::helper::{RoomServiceClient, RoomServiceError};

const SFU_TIMEOUT: Duration = Duration::from_secs(5);
const REVOKE_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How many finished share attempts each room remembers, so that a claim
/// arriving after its own release is refused.
const CLOSED_ATTEMPTS: usize = 64;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
enum Lease {
    #[default]
    Free,
    Held {
        identity: String,
        /// `None` when the lease was rebuilt from the SFU's state, e.g. after a
        /// restart; any release from that identity may then end it.
        attempt: Option<String>,
    },
    Unknown {
        identity: String,
    },
}

impl Lease {
    fn identity(&self) -> Option<&str> {
        match self {
            Self::Free => None,
            Self::Held { identity, .. } | Self::Unknown { identity } => Some(identity),
        }
    }

    fn block(&self) -> Option<ShareError> {
        match self {
            Self::Free => None,
            Self::Held { .. } => Some(ShareError::Busy),
            Self::Unknown { .. } => Some(ShareError::Unknown),
        }
    }

    fn held_by(identity: &str) -> Self {
        Self::Held {
            identity: identity.to_owned(),
            attempt: None,
        }
    }
}

#[derive(Debug, Default)]
struct RoomState {
    lease: Lease,
    /// Finished (identity, attempt) pairs, oldest first.
    closed: VecDeque<(String, String)>,
}

impl RoomState {
    fn is_closed(&self, identity: &str, attempt: &str) -> bool {
        self.closed.iter().any(|(closed_identity, closed_attempt)| {
            closed_identity == identity && closed_attempt == attempt
        })
    }

    fn close(&mut self, identity: &str, attempt: &str) {
        if self.is_closed(identity, attempt) {
            return;
        }
        if self.closed.len() == CLOSED_ATTEMPTS {
            self.closed.pop_front();
        }
        self.closed
            .push_back((identity.to_owned(), attempt.to_owned()));
    }
}

/// Outcomes that need distinct HTTP responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShareError {
    Busy,
    Unknown,
    NotInCall,
    SfuUnavailable,
    Forbidden,
    /// The request belongs to a share attempt that has already ended or been
    /// replaced.
    Stale,
}

/// Owns the per-room locks and the last known lease state.
pub(crate) struct ShareArbiter {
    sfu: Arc<dyn RoomServiceClient>,
    rooms: std::sync::Mutex<HashMap<String, Arc<Mutex<RoomState>>>>,
    revoke_timeout: Duration,
}

impl ShareArbiter {
    /// Creates an empty lease cache. The SFU remains authoritative.
    pub(crate) fn new(sfu: Arc<dyn RoomServiceClient>, revoke_timeout: Duration) -> Self {
        Self {
            sfu,
            rooms: std::sync::Mutex::new(HashMap::new()),
            revoke_timeout,
        }
    }

    fn room_state(&self, room: &str) -> Arc<Mutex<RoomState>> {
        self.rooms
            .lock()
            .unwrap()
            .entry(room.to_owned())
            .or_default()
            .clone()
    }

    /// Adds screen sources for one share attempt after checking the whole room.
    pub(crate) async fn claim(
        &self,
        room: &str,
        identity: &str,
        attempt: &str,
    ) -> Result<(), ShareError> {
        let room_state = self.room_state(room);
        let mut state = room_state.lock().await;
        if state.is_closed(identity, attempt) {
            return Err(ShareError::Stale);
        }
        // A new attempt from the holder replaces its previous one.
        if let Lease::Held {
            identity: holder,
            attempt: Some(previous),
        } = &state.lease
            && holder == identity
            && previous != attempt
        {
            let previous = previous.clone();
            state.close(identity, &previous);
        }
        let lease = &mut state.lease;
        let participants = self.list(room, identity, lease).await?;

        if matches!(*lease, Lease::Unknown { .. }) && participants.iter().any(has_screen_activity) {
            return Err(ShareError::Unknown);
        }
        let requester = participants
            .iter()
            .find(|participant| participant.identity == identity);
        if let Some(other) = participants.iter().find(|participant| {
            participant.identity != identity && has_screen_activity(participant)
        }) {
            if other.permission.is_none() {
                *lease = Lease::Unknown {
                    identity: other.identity.clone(),
                };
                return Err(ShareError::Unknown);
            }
            *lease = Lease::held_by(&other.identity);
            return Err(if requester.is_some() {
                ShareError::Busy
            } else {
                ShareError::NotInCall
            });
        }

        *lease = if requester.is_some_and(has_screen_activity) {
            Lease::held_by(identity)
        } else {
            Lease::Free
        };
        let requester = requester.ok_or(ShareError::NotInCall)?;
        let mut permission = requester.permission.clone().ok_or_else(|| {
            *lease = Lease::Unknown {
                identity: identity.to_owned(),
            };
            ShareError::Unknown
        })?;
        if !permission.can_publish {
            return Err(ShareError::Forbidden);
        }

        permission.can_publish_sources = with_screen_sources(&permission);
        *lease = Lease::Unknown {
            identity: identity.to_owned(),
        };
        let deadline = Instant::now() + SFU_TIMEOUT;
        self.update_permission(room, identity, permission.clone(), deadline)
            .await?;
        let confirmed = timeout(SFU_TIMEOUT, self.sfu.get_participant(room, identity)).await;
        match confirmed {
            Ok(Ok(participant)) if participant.permission.as_ref() == Some(&permission) => {
                *lease = Lease::Held {
                    identity: identity.to_owned(),
                    attempt: Some(attempt.to_owned()),
                };
                debug!(room, identity, attempt, "Share arbiter: grant confirmed");
                Ok(())
            }
            Ok(Ok(_)) => {
                warn!(
                    room,
                    identity, "Share arbiter: grant could not be confirmed"
                );
                Err(ShareError::Unknown)
            }
            Ok(Err(RoomServiceError::NotFound(_))) => Err(ShareError::NotInCall),
            Ok(Err(err)) => {
                warn!(room, identity, %err, "Share arbiter: error confirming grant");
                Err(ShareError::SfuUnavailable)
            }
            Err(err) => {
                warn!(room, identity, %err, "Share arbiter: grant confirmation timed out");
                Err(ShareError::SfuUnavailable)
            }
        }
    }

    /// Ends one share attempt: revokes screen sources and waits for every
    /// screen track to disappear.
    pub(crate) async fn release(
        &self,
        room: &str,
        identity: &str,
        attempt: &str,
    ) -> Result<(), ShareError> {
        let room_state = self.room_state(room);
        let mut state = room_state.lock().await;
        // Closing first means a claim for this attempt that is still in flight
        // will be refused when it gets the lock.
        state.close(identity, attempt);
        // A late release must not end a newer attempt by the same participant.
        if let Lease::Held {
            identity: holder,
            attempt: Some(current),
        } = &state.lease
            && holder == identity
            && current != attempt
        {
            return Err(ShareError::Stale);
        }
        let lease = &mut state.lease;
        let participants = self.list(room, identity, lease).await?;
        let requester = participants
            .iter()
            .find(|participant| participant.identity == identity);
        let other_sharer = participants.iter().find(|participant| {
            participant.identity != identity && has_screen_activity(participant)
        });
        let requester_is_holder = lease.identity() == Some(identity);
        let still_held_elsewhere = match (other_sharer, &*lease) {
            (None, _) => Lease::Free,
            (Some(_), Lease::Unknown { identity: holder }) if !requester_is_holder => {
                Lease::Unknown {
                    identity: holder.clone(),
                }
            }
            (Some(other), _) => Lease::held_by(&other.identity),
        };

        if !requester_is_holder && !requester.is_some_and(has_screen_activity) {
            *lease = still_held_elsewhere;
            return match lease.block() {
                Some(error) => Err(error),
                None if requester.is_none() => Err(ShareError::NotInCall),
                None => Ok(()),
            };
        }

        *lease = Lease::Unknown {
            identity: identity.to_owned(),
        };
        let deadline = Instant::now() + self.revoke_timeout;
        if let Some(participant) = requester {
            let permission = participant.permission.as_ref().ok_or(ShareError::Unknown)?;
            // A participant may leave between ListParticipants and UpdateParticipant.
            // Confirm absence below if the update reports that it couldn't find them.
            match self
                .update_permission(room, identity, without_screen_sources(permission), deadline)
                .await
            {
                Ok(()) | Err(ShareError::NotInCall) => {}
                Err(err) => return Err(err),
            }
        }
        match timeout_at(deadline, self.confirm_revocation(room, identity)).await {
            Ok(Ok(())) => {
                *lease = still_held_elsewhere;
                debug!(
                    room,
                    identity, attempt, "Share arbiter: revocation confirmed"
                );
                lease.block().map_or(Ok(()), Err)
            }
            Ok(Err(err)) => {
                warn!(room, identity, %err, "Share arbiter: error confirming revocation");
                Err(ShareError::SfuUnavailable)
            }
            Err(err) => {
                warn!(room, identity, %err, "Share arbiter: revocation could not be confirmed");
                Err(ShareError::Unknown)
            }
        }
    }

    /// Removes screen rights from a participant that does not hold the lease.
    ///
    /// LiveKit puts the current grants into the refreshed tokens it hands to
    /// clients, so a participant can come back with screen rights from an
    /// earlier share, or publish late. Called when a participant joins or
    /// publishes a screen track.
    pub(crate) async fn enforce(&self, room: &str, identity: &str) {
        let room_state = self.room_state(room);
        let mut state = room_state.lock().await;
        let lease = &mut state.lease;
        if lease.identity() == Some(identity) {
            return;
        }

        let participant = match timeout(SFU_TIMEOUT, self.sfu.get_participant(room, identity)).await
        {
            Ok(Ok(participant)) => participant,
            Ok(Err(RoomServiceError::NotFound(_))) => return,
            outcome => {
                warn!(
                    room,
                    identity,
                    ?outcome,
                    "Share arbiter: could not check a participant"
                );
                return;
            }
        };
        if !has_screen_activity(&participant) {
            return;
        }
        let Some(permission) = participant.permission.as_ref() else {
            warn!(
                room,
                identity, "Share arbiter: participant permissions are unknown"
            );
            if *lease == Lease::Free {
                *lease = Lease::Unknown {
                    identity: identity.to_owned(),
                };
            }
            return;
        };

        warn!(
            room,
            identity, "Share arbiter: removing screen rights from a non-holder"
        );
        let deadline = Instant::now() + self.revoke_timeout;
        let revoked = match self
            .update_permission(room, identity, without_screen_sources(permission), deadline)
            .await
        {
            Ok(()) => matches!(
                timeout_at(deadline, self.confirm_revocation(room, identity)).await,
                Ok(Ok(()))
            ),
            Err(ShareError::NotInCall) => true,
            Err(_) => false,
        };
        if !revoked && *lease == Lease::Free {
            *lease = Lease::Unknown {
                identity: identity.to_owned(),
            };
        }
    }

    /// Reconciles a leave webhook for the cached holder with the SFU.
    pub(crate) async fn participant_left(&self, room: &str, identity: &str) {
        let Some(room_state) = self.rooms.lock().unwrap().get(room).cloned() else {
            return;
        };
        let mut state = room_state.lock().await;
        let lease = &mut state.lease;
        if lease.identity() != Some(identity) {
            return;
        }

        match timeout(SFU_TIMEOUT, self.sfu.get_participant(room, identity)).await {
            Ok(Err(RoomServiceError::NotFound(_))) => {
                *lease = Lease::Free;
                debug!(room, identity, "Share arbiter: holder departure confirmed");
            }
            Ok(Ok(_)) => {}
            outcome => {
                warn!(
                    room,
                    identity,
                    ?outcome,
                    "Share arbiter: holder departure could not be confirmed"
                );
                *lease = Lease::Unknown {
                    identity: identity.to_owned(),
                };
            }
        }
    }

    async fn list(
        &self,
        room: &str,
        identity: &str,
        lease: &mut Lease,
    ) -> Result<Vec<ParticipantInfo>, ShareError> {
        let outcome = timeout(SFU_TIMEOUT, self.sfu.list_participants(room)).await;
        match outcome {
            Ok(Ok(participants)) => Ok(participants),
            // ListParticipants can report that the entire room is absent.
            Ok(Err(RoomServiceError::NotFound(_))) => Ok(Vec::new()),
            outcome => {
                warn!(
                    room,
                    ?outcome,
                    "Share arbiter: failed to list room participants"
                );
                let blocked = matches!(
                    &*lease,
                    Lease::Unknown { identity: holder } if holder.as_str() != identity
                );
                *lease = Lease::Unknown {
                    identity: lease.identity().unwrap_or(identity).to_owned(),
                };
                Err(if blocked {
                    ShareError::Unknown
                } else {
                    ShareError::SfuUnavailable
                })
            }
        }
    }

    async fn update_permission(
        &self,
        room: &str,
        identity: &str,
        permission: ParticipantPermission,
        deadline: Instant,
    ) -> Result<(), ShareError> {
        match timeout_at(
            deadline,
            self.sfu
                .update_participant_permission(room, identity, permission),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(RoomServiceError::NotFound(_))) => Err(ShareError::NotInCall),
            outcome => {
                warn!(
                    room,
                    identity,
                    ?outcome,
                    "Share arbiter: failed to update participant permissions"
                );
                Err(ShareError::SfuUnavailable)
            }
        }
    }

    async fn confirm_revocation(&self, room: &str, identity: &str) -> Result<(), RoomServiceError> {
        loop {
            match self.sfu.get_participant(room, identity).await {
                Ok(participant) if !has_screen_activity(&participant) => return Ok(()),
                Err(RoomServiceError::NotFound(_)) => return Ok(()),
                Err(err) => return Err(err),
                Ok(_) => sleep(REVOKE_POLL_INTERVAL).await,
            }
        }
    }
}

fn has_screen_activity(participant: &ParticipantInfo) -> bool {
    participant
        .tracks
        .iter()
        .any(|track| is_screen_source(track.source))
        // Missing permissions leave the participant's rights unknown.
        || participant.permission.as_ref().is_none_or(|permission| {
            // LiveKit treats an empty source list as unrestricted publish access.
            (permission.can_publish && permission.can_publish_sources.is_empty())
                || permission.can_publish_sources.iter().copied().any(is_screen_source)
        })
}

fn is_screen_source(source: i32) -> bool {
    source == TrackSource::ScreenShare as i32 || source == TrackSource::ScreenShareAudio as i32
}

/// The participant's sources other than the screen. An empty list means
/// unrestricted publishing, which covers camera and microphone.
fn non_screen_sources(permission: &ParticipantPermission) -> Vec<i32> {
    if permission.can_publish_sources.is_empty() {
        return vec![TrackSource::Camera as i32, TrackSource::Microphone as i32];
    }
    permission
        .can_publish_sources
        .iter()
        .copied()
        .filter(|source| !is_screen_source(*source))
        .collect()
}

/// Adds screen video and audio without widening anything else, so a
/// microphone-only participant does not gain the camera.
fn with_screen_sources(permission: &ParticipantPermission) -> Vec<i32> {
    let mut sources = non_screen_sources(permission);
    sources.extend([
        TrackSource::ScreenShare as i32,
        TrackSource::ScreenShareAudio as i32,
    ]);
    sources
}

/// The same permission without screen sources.
fn without_screen_sources(permission: &ParticipantPermission) -> ParticipantPermission {
    let sources = non_screen_sources(permission);
    ParticipantPermission {
        // An empty list would mean "publish anything", so a participant left
        // with no sources cannot publish at all.
        can_publish: permission.can_publish && !sources.is_empty(),
        can_publish_sources: sources,
        ..permission.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::{CreateRoomParams, RoomInfo};
    use async_trait::async_trait;
    use livekit_protocol::TrackInfo;

    const ROOM: &str = "call";
    const ALICE: &str = "alice";
    const BOB: &str = "bob";
    const A1: &str = "alice-1";
    const A2: &str = "alice-2";
    const B1: &str = "bob-1";

    fn call_sources() -> Vec<i32> {
        vec![TrackSource::Camera as i32, TrackSource::Microphone as i32]
    }

    fn share_sources() -> Vec<i32> {
        let mut sources = call_sources();
        sources.extend([
            TrackSource::ScreenShare as i32,
            TrackSource::ScreenShareAudio as i32,
        ]);
        sources
    }

    struct FakeSfu {
        participants: std::sync::Mutex<HashMap<String, ParticipantInfo>>,
        fail_list: std::sync::atomic::AtomicBool,
        ignore_update: std::sync::atomic::AtomicBool,
    }

    impl FakeSfu {
        fn new() -> Self {
            Self {
                participants: std::sync::Mutex::new(
                    [ALICE, BOB]
                        .into_iter()
                        .map(|identity| {
                            (
                                identity.to_owned(),
                                ParticipantInfo {
                                    identity: identity.to_owned(),
                                    permission: Some(ParticipantPermission {
                                        can_publish: true,
                                        can_subscribe: false,
                                        can_publish_data: true,
                                        can_update_metadata: false,
                                        can_publish_sources: call_sources(),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                },
                            )
                        })
                        .collect(),
                ),
                fail_list: false.into(),
                ignore_update: false.into(),
            }
        }

        fn set_screen_track(&self, identity: &str, source: Option<TrackSource>) {
            self.participants
                .lock()
                .unwrap()
                .get_mut(identity)
                .unwrap()
                .tracks = source
                .map(|source| TrackInfo {
                    source: source as i32,
                    ..Default::default()
                })
                .into_iter()
                .collect();
        }

        fn set_sources(&self, identity: &str, sources: Vec<i32>) {
            self.participants
                .lock()
                .unwrap()
                .get_mut(identity)
                .unwrap()
                .permission
                .as_mut()
                .unwrap()
                .can_publish_sources = sources;
        }

        fn sources(&self, identity: &str) -> Vec<i32> {
            self.participants.lock().unwrap()[identity]
                .permission
                .as_ref()
                .unwrap()
                .can_publish_sources
                .clone()
        }
    }

    #[async_trait]
    impl RoomServiceClient for FakeSfu {
        async fn create_room(&self, _: CreateRoomParams) -> Result<RoomInfo, RoomServiceError> {
            unreachable!("the arbiter never creates rooms")
        }

        async fn list_participants(
            &self,
            _: &str,
        ) -> Result<Vec<ParticipantInfo>, RoomServiceError> {
            if self.fail_list.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(RoomServiceError::Other("SFU unavailable".into()));
            }
            Ok(self
                .participants
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect())
        }

        async fn get_participant(
            &self,
            _: &str,
            identity: &str,
        ) -> Result<ParticipantInfo, RoomServiceError> {
            self.participants
                .lock()
                .unwrap()
                .get(identity)
                .cloned()
                .ok_or_else(|| RoomServiceError::NotFound(identity.into()))
        }

        async fn update_participant_permission(
            &self,
            _: &str,
            identity: &str,
            permission: ParticipantPermission,
        ) -> Result<ParticipantInfo, RoomServiceError> {
            let mut participants = self.participants.lock().unwrap();
            let participant = participants
                .get_mut(identity)
                .ok_or_else(|| RoomServiceError::NotFound(identity.into()))?;
            let mut response = participant.clone();
            response.permission = Some(permission);
            if !self
                .ignore_update
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                *participant = response.clone();
            }
            Ok(response)
        }
    }

    fn setup() -> (Arc<FakeSfu>, ShareArbiter) {
        let sfu = Arc::new(FakeSfu::new());
        let arbiter = ShareArbiter::new(sfu.clone(), Duration::from_millis(250));
        (sfu, arbiter)
    }

    async fn lease(arbiter: &ShareArbiter) -> Lease {
        arbiter.room_state(ROOM).lock().await.lease.clone()
    }

    #[tokio::test]
    async fn claim_and_release_preserve_other_permissions() {
        let (sfu, arbiter) = setup();
        let default = sfu
            .get_participant(ROOM, ALICE)
            .await
            .unwrap()
            .permission
            .unwrap();
        assert_eq!(arbiter.claim(ROOM, ALICE, A1).await, Ok(()));
        let granted = sfu
            .get_participant(ROOM, ALICE)
            .await
            .unwrap()
            .permission
            .unwrap();
        assert_eq!(
            granted,
            ParticipantPermission {
                can_publish_sources: share_sources(),
                ..default.clone()
            }
        );
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Err(ShareError::Busy));
        assert_eq!(arbiter.release(ROOM, ALICE, A1).await, Ok(()));
        assert_eq!(
            sfu.get_participant(ROOM, ALICE)
                .await
                .unwrap()
                .permission
                .unwrap(),
            default
        );
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test]
    async fn claim_and_release_only_touch_screen_sources() {
        let (sfu, arbiter) = setup();
        let microphone = vec![TrackSource::Microphone as i32];
        sfu.set_sources(ALICE, microphone.clone());
        assert_eq!(arbiter.claim(ROOM, ALICE, A1).await, Ok(()));
        assert_eq!(
            sfu.sources(ALICE),
            vec![
                TrackSource::Microphone as i32,
                TrackSource::ScreenShare as i32,
                TrackSource::ScreenShareAudio as i32,
            ]
        );
        assert_eq!(arbiter.release(ROOM, ALICE, A1).await, Ok(()));
        assert_eq!(sfu.sources(ALICE), microphone);
    }

    #[test]
    fn removing_the_last_source_disables_publishing() {
        let permission = ParticipantPermission {
            can_publish: true,
            can_publish_sources: vec![TrackSource::ScreenShare as i32],
            ..Default::default()
        };
        let revoked = without_screen_sources(&permission);
        assert!(revoked.can_publish_sources.is_empty());
        assert!(!revoked.can_publish);
    }

    #[tokio::test]
    async fn concurrent_claims_grant_only_one_participant() {
        let (_, arbiter) = setup();
        let (alice, bob) =
            tokio::join!(arbiter.claim(ROOM, ALICE, A1), arbiter.claim(ROOM, BOB, B1));
        assert!(matches!(
            (alice, bob),
            (Ok(()), Err(ShareError::Busy)) | (Err(ShareError::Busy), Ok(()))
        ));
    }

    #[tokio::test]
    async fn a_claim_after_its_release_is_refused() {
        let (sfu, arbiter) = setup();
        assert_eq!(arbiter.release(ROOM, ALICE, A1).await, Ok(()));
        assert_eq!(arbiter.claim(ROOM, ALICE, A1).await, Err(ShareError::Stale));
        assert_eq!(sfu.sources(ALICE), call_sources());
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test]
    async fn an_old_release_does_not_end_a_newer_attempt() {
        let (sfu, arbiter) = setup();
        assert_eq!(arbiter.claim(ROOM, ALICE, A1).await, Ok(()));
        assert_eq!(arbiter.claim(ROOM, ALICE, A2).await, Ok(()));
        assert_eq!(
            arbiter.release(ROOM, ALICE, A1).await,
            Err(ShareError::Stale)
        );
        assert_eq!(sfu.sources(ALICE), share_sources());
        assert_eq!(arbiter.claim(ROOM, ALICE, A1).await, Err(ShareError::Stale));
        assert_eq!(arbiter.release(ROOM, ALICE, A2).await, Ok(()));
        assert_eq!(sfu.sources(ALICE), call_sources());
    }

    #[tokio::test]
    async fn closed_attempts_are_bounded() {
        let (_, arbiter) = setup();
        for attempt in 0..=CLOSED_ATTEMPTS {
            let _ = arbiter.release(ROOM, ALICE, &attempt.to_string()).await;
        }
        let state = arbiter.room_state(ROOM);
        let state = state.lock().await;
        assert_eq!(state.closed.len(), CLOSED_ATTEMPTS);
        assert!(!state.is_closed(ALICE, "0"));
        assert!(state.is_closed(ALICE, &CLOSED_ATTEMPTS.to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn release_waits_until_the_screen_track_disappears() {
        let (sfu, arbiter) = setup();
        arbiter.claim(ROOM, ALICE, A1).await.unwrap();
        sfu.set_screen_track(ALICE, Some(TrackSource::ScreenShare));
        let remove_track = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            sfu.set_screen_track(ALICE, None);
        };
        let started = tokio::time::Instant::now();
        let (released, ()) = tokio::join!(arbiter.release(ROOM, ALICE, A1), remove_track);
        assert_eq!(released, Ok(()));
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn lingering_screen_audio_marks_unknown_until_holder_retries_release() {
        let (sfu, arbiter) = setup();
        arbiter.claim(ROOM, ALICE, A1).await.unwrap();
        sfu.set_screen_track(ALICE, Some(TrackSource::ScreenShareAudio));
        assert_eq!(
            arbiter.release(ROOM, ALICE, A1).await,
            Err(ShareError::Unknown)
        );
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Err(ShareError::Unknown));
        sfu.set_screen_track(ALICE, None);
        assert_eq!(arbiter.release(ROOM, ALICE, A1).await, Ok(()));
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn leaving_clears_unknown_only_when_the_holder_is_absent() {
        let (sfu, arbiter) = setup();
        arbiter.claim(ROOM, ALICE, A1).await.unwrap();
        sfu.set_screen_track(ALICE, Some(TrackSource::ScreenShare));
        assert_eq!(
            arbiter.release(ROOM, ALICE, A1).await,
            Err(ShareError::Unknown)
        );
        arbiter.participant_left(ROOM, ALICE).await;
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Err(ShareError::Unknown));
        sfu.participants.lock().unwrap().remove(ALICE);
        arbiter.participant_left(ROOM, ALICE).await;
        assert_eq!(lease(&arbiter).await, Lease::Free);
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_clean_sfu_reconciles_unknown_on_claim() {
        let (sfu, arbiter) = setup();
        arbiter.claim(ROOM, ALICE, A1).await.unwrap();
        sfu.set_screen_track(ALICE, Some(TrackSource::ScreenShareAudio));
        assert_eq!(
            arbiter.release(ROOM, ALICE, A1).await,
            Err(ShareError::Unknown)
        );
        sfu.set_screen_track(ALICE, None);
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test]
    async fn list_failure_returns_unavailable_without_granting() {
        let (sfu, arbiter) = setup();
        sfu.fail_list
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            arbiter.claim(ROOM, ALICE, A1).await,
            Err(ShareError::SfuUnavailable)
        );
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Err(ShareError::Unknown));
        assert_eq!(sfu.sources(ALICE), call_sources());
    }

    #[tokio::test]
    async fn a_grant_is_confirmed_by_readback() {
        let (sfu, arbiter) = setup();
        sfu.ignore_update
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            arbiter.claim(ROOM, ALICE, A1).await,
            Err(ShareError::Unknown)
        );
    }

    #[tokio::test]
    async fn restart_reconciles_screen_permissions_and_allows_holder_release() {
        let (sfu, first_arbiter) = setup();
        first_arbiter.claim(ROOM, ALICE, A1).await.unwrap();
        let arbiter = ShareArbiter::new(sfu, Duration::from_secs(1));
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Err(ShareError::Busy));
        assert_eq!(arbiter.release(ROOM, ALICE, A1).await, Ok(()));
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test]
    async fn disconnected_claimant_must_join_first() {
        let (_, arbiter) = setup();
        assert_eq!(
            arbiter.claim(ROOM, "absent", "absent-1").await,
            Err(ShareError::NotInCall)
        );
    }

    #[tokio::test]
    async fn claim_preserves_a_matrix_publish_denial() {
        let (sfu, arbiter) = setup();
        let mut participant = sfu.get_participant(ROOM, ALICE).await.unwrap();
        participant.permission.as_mut().unwrap().can_publish = false;
        sfu.participants
            .lock()
            .unwrap()
            .insert(ALICE.into(), participant);
        assert_eq!(
            arbiter.claim(ROOM, ALICE, A1).await,
            Err(ShareError::Forbidden)
        );
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn enforce_strips_screen_rights_from_a_stale_token() {
        let (sfu, arbiter) = setup();
        arbiter.claim(ROOM, BOB, B1).await.unwrap();
        // Alice rejoins with a refreshed token from an earlier share.
        sfu.set_sources(ALICE, share_sources());
        arbiter.enforce(ROOM, ALICE).await;
        assert_eq!(sfu.sources(ALICE), call_sources());
        assert_eq!(sfu.sources(BOB), share_sources());
        assert_eq!(
            lease(&arbiter).await,
            Lease::Held {
                identity: BOB.into(),
                attempt: Some(B1.into())
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn enforce_leaves_the_holder_alone() {
        let (sfu, arbiter) = setup();
        arbiter.claim(ROOM, ALICE, A1).await.unwrap();
        sfu.set_screen_track(ALICE, Some(TrackSource::ScreenShare));
        arbiter.enforce(ROOM, ALICE).await;
        assert_eq!(sfu.sources(ALICE), share_sources());
    }

    #[tokio::test(start_paused = true)]
    async fn enforce_blocks_successors_when_a_late_track_survives() {
        let (sfu, arbiter) = setup();
        sfu.set_screen_track(ALICE, Some(TrackSource::ScreenShare));
        arbiter.enforce(ROOM, ALICE).await;
        assert_eq!(sfu.sources(ALICE), call_sources());
        assert_eq!(
            lease(&arbiter).await,
            Lease::Unknown {
                identity: ALICE.into()
            }
        );
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Err(ShareError::Unknown));
        sfu.set_screen_track(ALICE, None);
        assert_eq!(arbiter.claim(ROOM, BOB, B1).await, Ok(()));
    }
}
