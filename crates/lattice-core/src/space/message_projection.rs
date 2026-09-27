use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use super::{
    ApplicationAction, EntityId, EventReference, Fingerprint, GraphNode, MentionTarget,
    rich_text::RichText,
};

/// Authorized message history materialized from one reducer generation.
///
/// This is an in-memory view only. Durable replay and encrypted projection
/// storage remain the caller's responsibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageHistory {
    messages: Vec<ProjectedMessage>,
}

impl MessageHistory {
    /// Returns messages in deterministic event order.
    #[must_use]
    pub fn messages(&self) -> &[ProjectedMessage] {
        &self.messages
    }
}

/// One authorized message with its immutable versions and update events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedMessage {
    /// Immutable creation event ID.
    pub event_id: EventReference,
    /// Fingerprint of the message author.
    pub author: Fingerprint,
    /// Optional immutable thread-root message ID.
    pub thread_root: Option<EventReference>,
    /// Stable identity and role references carried by this immutable message.
    pub mentions: Vec<MentionTarget>,
    versions: Vec<MessageVersion>,
    /// All authorized tombstones, including distinct moderation reasons.
    pub tombstones: Vec<MessageTombstone>,
    /// Active immutable pin-add tags.
    pub pin_tags: Vec<EventReference>,
    /// Active reaction-add tags, grouped by token.
    pub reactions: Vec<ReactionState>,
}

impl ProjectedMessage {
    /// Returns every authorized body version in deterministic event order.
    #[must_use]
    pub fn versions(&self) -> &[MessageVersion] {
        &self.versions
    }

    /// Returns the current version selected by deterministic event ordering.
    ///
    /// # Panics
    ///
    /// Never panics for a value produced by [`MessageHistory`]. Its original
    /// message event always contributes the first version.
    #[must_use]
    pub fn current_version(&self) -> &MessageVersion {
        self.versions
            .last()
            .expect("every projected message has its immutable original")
    }

    /// Whether any authorized tombstone hides this message in normal views.
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        !self.tombstones.is_empty()
    }

    /// Whether at least one authorized pin-add tag remains active.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        !self.pin_tags.is_empty()
    }
}

/// One immutable message body version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageVersion {
    /// Event that introduced this body.
    pub event_id: EventReference,
    /// Author of this version.
    pub author: Fingerprint,
    /// Plain display text with supported source markup removed.
    pub content: Arc<str>,
    /// UTF-8 byte ranges carrying semantic formatting.
    pub rich_text: RichText,
    order: MessageOrder,
}

/// One retained tombstone, including moderation provenance when present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageTombstone {
    /// Tombstone event ID.
    pub event_id: EventReference,
    /// Author of the tombstone.
    pub author: Fingerprint,
    /// Present only for a reason-bearing moderator action.
    pub moderation_reason: Option<String>,
    order: MessageOrder,
}

/// Active observed-add tags for one reaction token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactionState {
    /// Reaction token.
    pub token: String,
    /// Immutable add-event IDs not named by an authorized remove.
    pub active_tags: Vec<EventReference>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MessageOrder(u64, Fingerprint, u64, EventReference);

type MessageMap = BTreeMap<EventReference, ProjectedMessage>;
type ReactionAdds = BTreeMap<(EventReference, String), BTreeSet<EventReference>>;
type PinAdds = BTreeMap<EventReference, BTreeSet<EventReference>>;

#[derive(Default)]
struct UpdateTags {
    reaction_adds: ReactionAdds,
    reaction_removes: ReactionAdds,
    pin_adds: PinAdds,
    pin_removes: PinAdds,
}

pub(super) fn project_channel(
    graph: &BTreeMap<EventReference, GraphNode>,
    channel_id: &EntityId,
) -> MessageHistory {
    let mut messages = project_messages(graph, channel_id);
    let tags = project_updates(graph, channel_id, &mut messages);
    apply_reaction_tags(&mut messages, tags.reaction_adds, &tags.reaction_removes);
    apply_pin_tags(&mut messages, tags.pin_adds, &tags.pin_removes);

    let mut messages = messages.into_values().collect::<Vec<_>>();
    messages.sort_by_key(|message| message.versions[0].order);
    MessageHistory { messages }
}

fn project_messages(
    graph: &BTreeMap<EventReference, GraphNode>,
    channel_id: &EntityId,
) -> MessageMap {
    let mut messages = MessageMap::new();
    for (event_id, node) in graph {
        if !authorized_for_channel(node, channel_id) {
            continue;
        }
        let Some(ApplicationAction::Message {
            rich_text,
            thread_root,
            mentions,
            ..
        }) = node.application_action.as_ref()
        else {
            continue;
        };
        let order = message_order(node, *event_id);
        messages.insert(
            *event_id,
            ProjectedMessage {
                event_id: *event_id,
                author: node.author,
                thread_root: *thread_root,
                mentions: mentions.clone(),
                versions: vec![MessageVersion {
                    event_id: *event_id,
                    author: node.author,
                    content: Arc::from(rich_text.render_plain_text()),
                    rich_text: rich_text.clone(),
                    order,
                }],
                tombstones: Vec::new(),
                pin_tags: Vec::new(),
                reactions: Vec::new(),
            },
        );
    }
    messages
}

fn project_updates(
    graph: &BTreeMap<EventReference, GraphNode>,
    channel_id: &EntityId,
    messages: &mut MessageMap,
) -> UpdateTags {
    let mut tags = UpdateTags::default();
    for (event_id, node) in graph {
        if !authorized_for_channel(node, channel_id) {
            continue;
        }
        let Some(action) = node.application_action.as_ref() else {
            continue;
        };
        let order = message_order(node, *event_id);
        match action {
            ApplicationAction::Edit {
                target, rich_text, ..
            } => {
                if let Some(message) = messages.get_mut(target) {
                    message.versions.push(MessageVersion {
                        event_id: *event_id,
                        author: node.author,
                        content: Arc::from(rich_text.render_plain_text()),
                        rich_text: rich_text.clone(),
                        order,
                    });
                }
            }
            ApplicationAction::Tombstone {
                target,
                moderation_reason,
            } => {
                if let Some(message) = messages.get_mut(target) {
                    message.tombstones.push(MessageTombstone {
                        event_id: *event_id,
                        author: node.author,
                        moderation_reason: moderation_reason.clone(),
                        order,
                    });
                }
            }
            ApplicationAction::Reaction {
                target,
                token,
                add,
                tag,
            } => {
                let destination = if *add {
                    &mut tags.reaction_adds
                } else {
                    &mut tags.reaction_removes
                };
                if let Some(tag) = tag {
                    destination
                        .entry((*target, token.clone()))
                        .or_default()
                        .insert(*tag);
                } else if *add {
                    destination
                        .entry((*target, token.clone()))
                        .or_default()
                        .insert(*event_id);
                }
            }
            ApplicationAction::Pin { target, add, tag } => {
                let destination = if *add {
                    &mut tags.pin_adds
                } else {
                    &mut tags.pin_removes
                };
                if let Some(tag) = tag {
                    destination.entry(*target).or_default().insert(*tag);
                } else if *add {
                    destination.entry(*target).or_default().insert(*event_id);
                }
            }
            ApplicationAction::Message { .. } | ApplicationAction::FileManifest => {}
        }
    }
    for message in messages.values_mut() {
        message.versions.sort_by_key(|version| version.order);
        message.tombstones.sort_by_key(|tombstone| tombstone.order);
    }
    tags
}

fn apply_reaction_tags(
    messages: &mut MessageMap,
    adds: ReactionAdds,
    removed_by_key: &ReactionAdds,
) {
    for (key, tags) in adds {
        let removed_tags = removed_by_key.get(&key);
        let active_tags = tags
            .into_iter()
            .filter(|tag| removed_tags.is_none_or(|removed| !removed.contains(tag)))
            .collect::<Vec<_>>();
        if !active_tags.is_empty()
            && let Some(message) = messages.get_mut(&key.0)
        {
            message.reactions.push(ReactionState {
                token: key.1,
                active_tags,
            });
        }
    }
    for message in messages.values_mut() {
        message
            .reactions
            .sort_by(|left, right| left.token.cmp(&right.token));
    }
}

fn apply_pin_tags(messages: &mut MessageMap, adds: PinAdds, removed_by_target: &PinAdds) {
    for (target, tags) in adds {
        if let Some(message) = messages.get_mut(&target) {
            let removed_tags = removed_by_target.get(&target);
            message.pin_tags = tags
                .into_iter()
                .filter(|tag| removed_tags.is_none_or(|removed| !removed.contains(tag)))
                .collect();
        }
    }
}

fn authorized_for_channel(node: &GraphNode, channel_id: &EntityId) -> bool {
    node.application_authorized && node.channel_id.as_ref() == Some(channel_id)
}

fn message_order(node: &GraphNode, event_id: EventReference) -> MessageOrder {
    MessageOrder(node.lamport, node.author, node.author_sequence, event_id)
}
