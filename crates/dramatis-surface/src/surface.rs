// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The endpoint a host mounts.
use std::collections::BTreeMap;

use castellan_client::quarantine::{AssignImportRequest, ReviewAction};
use chirograph::{
    AdvertisedAction, BoundsRelationship, CachePolicy, CacheRetention, ContentHash,
    EndpointDescriptor, IntentInvocation, IntentResult, PresentationBinding,
    PresentationCapability, PresentationCodec, PresentationKey, PresentationManifest,
    PresentationOffer, PresentationSemantics, ProjectionOffer, ProjectionRequest,
    ProjectionSession, ProjectionSnapshot, ProtocolVersion, ResourceRequest, ResourceResponse,
    SemanticRole,
};
use graphshell_endpoint::{IntentSink, PresentationSource, ProjectionCatalog, ProjectionSource};
use sceno::{
    Arrangement, Footprint, InstanceId, ProjectedItem, Rect, Representation, Scene, Score, Size2,
    SourceRef, Transform2, Vec2,
};
use scenotime::{Revision, SceneEpoch, SceneSnapshot};

use crate::cards::{ModelCard, Target, model};
use crate::intents::*;
use crate::state::{Reply, Request, State};

/// The projection session this surface serves.
pub const SURFACE_SESSION: &str = "native:dramatis";

/// How the surface reaches Djinn, without blocking its caller.
///
/// A request is sent and its reply comes back later through `drain`, because
/// Djinn may wait on the person at a native prompt. [`crate::Worker`] is the
/// real implementation; tests supply a recording one.
pub trait Custody {
    /// Send one request. The previous request has already been answered.
    fn send(&mut self, request: Request);
    /// Replies that arrived since the last call, each with whether it answers
    /// a request the person made (as opposed to a background reading).
    fn drain(&mut self) -> Vec<(Reply, bool)>;
}

#[derive(Debug)]
pub enum SurfaceError {
    WrongSession,
    MissingResource,
    Serialize(serde_json::Error),
    InvalidSnapshot(String),
}

impl std::fmt::Display for SurfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongSession => f.write_str("request names another projection session"),
            Self::MissingResource => f.write_str("resource was not disclosed by this session"),
            Self::Serialize(e) => write!(f, "card serialization failed: {e}"),
            Self::InvalidSnapshot(e) => write!(f, "surface snapshot is invalid: {e}"),
        }
    }
}

impl std::error::Error for SurfaceError {}

const WIDTH: f32 = 360.0;
const HEIGHT: f32 = 136.0;
const GAP: f32 = 16.0;

/// Dramatis's projection endpoint over a [`Custody`].
pub struct DramatisSurface<C: Custody> {
    custody: C,
    state: State,
    session: ProjectionSession,
    epoch: u64,
    revision: u64,
    last: Option<Vec<ModelCard>>,
    resources: BTreeMap<ContentHash, Vec<u8>>,
}

impl<C: Custody> DramatisSurface<C> {
    pub fn new(custody: C) -> Self {
        Self {
            custody,
            state: State::default(),
            session: ProjectionSession(SURFACE_SESSION.to_string()),
            epoch: 1,
            revision: 1,
            last: None,
            resources: BTreeMap::new(),
        }
    }

    pub fn session(&self) -> ProjectionSession {
        self.session.clone()
    }

    /// The request a host passes to [`ProjectionSource::snapshot`].
    pub fn request(&self) -> ProjectionRequest {
        ProjectionRequest {
            version: ProtocolVersion::V1,
            session: self.session(),
            score: Score::new(Arrangement::Spiral(Default::default())),
        }
    }

    /// The custody state the cards are built from, for hosts and tests that
    /// read it directly.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Take in what the worker has answered. Background readings do not
    /// erase an acknowledged owner action, and none replaces a request still
    /// in flight, as the application did.
    pub fn pump(&mut self) {
        for (reply, owned) in self.custody.drain() {
            if owned {
                self.state.adopt(reply);
            } else if !self.state.busy {
                self.state.adopt_refresh(reply);
            }
        }
    }

    fn observe(&mut self) -> Vec<ModelCard> {
        self.pump();
        let cards = model(&self.state);
        if self.last.as_ref().is_some_and(|last| last != &cards) {
            self.revision = self.revision.saturating_add(1);
        }
        self.last = Some(cards.clone());
        cards
    }

    fn build(&mut self) -> Result<ProjectionSnapshot, SurfaceError> {
        let cards = self.observe();
        let mut scene = Scene::new();
        let mut presentation = PresentationManifest::default();
        let mut resources = BTreeMap::new();
        for (index, model) in cards.iter().enumerate() {
            let source = scene.intern_source(SourceRef::new("dramatis", model.key.clone()));
            scene.items.push(ProjectedItem {
                source,
                space: Scene::WORLD,
                transform: Transform2::translation(0.0, index as f32 * (HEIGHT + GAP)),
                footprint: Footprint::Rect {
                    size: Size2::new(WIDTH, HEIGHT),
                },
                representation: Representation::Card,
                layer: 0,
                visible: true,
                hit: None,
                channels: Vec::new(),
            });
            let bytes = serde_json::to_vec(&model.card).map_err(SurfaceError::Serialize)?;
            let resource = ContentHash::of(&bytes);
            let key = PresentationKey(format!("dramatis:card:{index}"));
            presentation.bindings.push(PresentationBinding {
                instance: InstanceId(index as u32),
                key: key.clone(),
            });
            presentation.offers.insert(
                key,
                vec![PresentationOffer {
                    codec: PresentationCodec::PortableCardV1,
                    resource,
                    byte_size: bytes.len() as u64,
                    requires: PresentationCapability::PortableCard,
                    semantics: PresentationSemantics {
                        label: model.card.title.clone(),
                        role: SemanticRole::Article,
                        bounds: BoundsRelationship::FillFootprint,
                        actions: model.actions.clone(),
                    },
                }],
            );
            resources.insert(resource, bytes);
        }
        scene.bounds = if cards.is_empty() {
            Rect::new(Vec2::new(0.0, 0.0), Size2::new(0.0, 0.0))
        } else {
            let rows = cards.len() as f32;
            Rect::new(
                Vec2::new(0.0, 0.0),
                Size2::new(WIDTH, rows * HEIGHT + (rows - 1.0) * GAP),
            )
        };
        scene.generation = self.revision;
        let scene =
            SceneSnapshot::from_dense(SceneEpoch(self.epoch), Revision(self.revision), scene)
                .map_err(|error| SurfaceError::InvalidSnapshot(format!("{error:?}")))?;
        self.resources = resources;
        Ok(ProjectionSnapshot {
            version: ProtocolVersion::V1,
            session: self.session(),
            scene,
            presentation,
            // The public cards name stores and titles. Nothing here is worth
            // keeping past the session or exporting.
            cache_policy: CachePolicy {
                retention: CacheRetention::MemoryOnly,
                expires_at_ms: None,
                purge_on_revocation: true,
            },
        })
    }

    /// What `intent` means on the card the host acted on.
    fn request_for(
        &self,
        card: &ModelCard,
        action: &AdvertisedAction,
        payload: &[u8],
    ) -> Result<Request, String> {
        let snapshot = self.state.snapshot.as_ref();
        match (action.intent.0.as_str(), &card.target) {
            (RECONNECT_INTENT, Target::Status) => Ok(Request::Refresh),
            (UNLOCK_INTENT, Target::Vault) => Ok(Request::Unlock),
            (LOCK_INTENT, Target::Vault) => Ok(Request::Lock),
            (CHANGE_PASSPHRASE_INTENT, Target::Authentication) => Ok(Request::ChangePassphrase),
            (CHOOSE_PERSONA_INTENT, Target::Persona(id)) => Ok(Request::Select(id.clone())),
            (ACCEPT_ITEM_INTENT | DELETE_ITEM_INTENT, Target::Quarantine(index)) => {
                let entry = snapshot
                    .and_then(|s| s.cards.get(*index))
                    .ok_or("the quarantined item is no longer listed")?;
                let review = if action.intent.0 == ACCEPT_ITEM_INTENT {
                    ReviewAction::Accept
                } else {
                    ReviewAction::Delete
                };
                // `State::review` is the application's own guard: a locked
                // vault, a blocked acceptance and a card that is not listed
                // queue nothing.
                let mut probe = State {
                    snapshot: self.state.snapshot.clone(),
                    ..State::default()
                };
                probe.review(entry, review);
                probe
                    .request
                    .ok_or_else(|| "this review cannot be queued now".to_string())
            },
            (ASSIGN_IMPORT_INTENT, Target::Import(index)) => {
                let snapshot = snapshot.ok_or("Djinn is not connected")?;
                let import = snapshot
                    .unassigned
                    .get(*index)
                    .ok_or("the older import is no longer listed")?;
                let payload = action
                    .compose_payload_from(payload)
                    .map_err(|error| error.to_string())?;
                if payload.get(ASSIGN_DESTINATION_FIELD) != Some(&snapshot.roster.chosen.0) {
                    return Err("the destination is not the persona in use".into());
                }
                Ok(Request::Assign(AssignImportRequest {
                    store: import.store.clone(),
                    profile: snapshot.roster.chosen.clone(),
                    persona: import.persona,
                    revision: import.revision.clone(),
                }))
            },
            _ => Err("that action does not belong to this card".into()),
        }
    }
}

/// Read a composed payload back into its field values, refusing anything the
/// action's own form would not have composed.
trait ComposedPayload {
    fn compose_payload_from(&self, bytes: &[u8]) -> Result<BTreeMap<String, String>, String>;
}

impl ComposedPayload for AdvertisedAction {
    fn compose_payload_from(&self, bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
        let mut values: BTreeMap<String, String> = serde_json::from_slice(bytes)
            .map_err(|e| format!("payload was not understood: {e}"))?;
        if values.remove("schema").as_deref() != Some(self.payload_schema.as_str()) {
            return Err(format!(
                "payload does not name schema {}",
                self.payload_schema
            ));
        }
        // Compose again from the values: the bytes must be exactly what the
        // advertised form produces for them, so an unadvertised choice or an
        // extra field fails here.
        let recomposed = self.compose_payload(&values).map_err(|e| e.to_string())?;
        if recomposed != bytes {
            return Err("payload is not the one the advertised form composes".into());
        }
        Ok(values)
    }
}

impl<C: Custody> ProjectionCatalog for DramatisSurface<C> {
    fn describe(&self) -> EndpointDescriptor {
        EndpointDescriptor {
            label: "Dramatis".to_string(),
            projections: vec![ProjectionOffer {
                label: "Personae and quarantine review".to_string(),
                request: self.request(),
            }],
        }
    }
}

impl<C: Custody> ProjectionSource for DramatisSurface<C> {
    type Error = SurfaceError;

    fn snapshot(&mut self, request: ProjectionRequest) -> Result<ProjectionSnapshot, Self::Error> {
        if request.session != self.session || request.version.major != ProtocolVersion::V1.major {
            return Err(SurfaceError::WrongSession);
        }
        self.build()
    }
}

impl<C: Custody> PresentationSource for DramatisSurface<C> {
    type Error = SurfaceError;

    fn resource(&mut self, request: ResourceRequest) -> Result<ResourceResponse, Self::Error> {
        if request.session != self.session {
            return Err(SurfaceError::WrongSession);
        }
        let bytes = self
            .resources
            .get(&request.resource)
            .ok_or(SurfaceError::MissingResource)?
            .clone();
        Ok(ResourceResponse {
            session: request.session,
            resource: request.resource,
            bytes,
        })
    }
}

impl<C: Custody> IntentSink for DramatisSurface<C> {
    type Error = SurfaceError;

    /// Queue one request. Returns at once: Djinn may be waiting on the person,
    /// and the answer arrives in the next snapshot.
    fn invoke(&mut self, intent: IntentInvocation) -> Result<IntentResult, Self::Error> {
        if intent.session != self.session {
            return Err(SurfaceError::WrongSession);
        }
        let cards = self.observe();
        if intent.observed_epoch != SceneEpoch(self.epoch)
            || intent.observed_revision != Revision(self.revision)
        {
            return Ok(IntentResult::Stale {
                current_epoch: SceneEpoch(self.epoch),
                current_revision: Revision(self.revision),
            });
        }
        let Some(card) = cards.get(intent.target.0 as usize) else {
            return Ok(IntentResult::Rejected {
                reason: "intent target is not in the disclosed scene".into(),
            });
        };
        let Some(action) = card.actions.iter().find(|a| a.intent.0 == intent.intent) else {
            return Ok(IntentResult::Rejected {
                reason: "intent was not advertised for the selected card".into(),
            });
        };
        if action.input_form.is_none() && !intent.payload.is_empty() {
            return Ok(IntentResult::Rejected {
                reason: "this action takes no payload".into(),
            });
        }
        let request = match self.request_for(card, action, &intent.payload) {
            Ok(request) => request,
            Err(reason) => return Ok(IntentResult::Rejected { reason }),
        };
        self.state.queue(request);
        match self.state.request.take() {
            Some(request) => {
                self.custody.send(request);
                Ok(IntentResult::Accepted)
            },
            None => Ok(IntentResult::Rejected {
                reason: "another request is waiting for Djinn".into(),
            }),
        }
    }
}
