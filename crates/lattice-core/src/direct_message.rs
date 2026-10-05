use sha2::{Digest, Sha256};

use crate::{
    Client, CoreError, DeviceCredentialInput, DirectMessageConversation, DirectMessageOutboxEntry,
    DirectMessageRecord, OutboxState, PendingDirectMessageInvitation, Store,
};
use lattice_mls::api::IncomingResult;
use lattice_protocol::{Value, decode_canonical, encode_canonical};

const DIRECT_MESSAGE_MAGIC: &[u8; 4] = b"LDMP";
const DIRECT_MESSAGE_VERSION: u8 = 1;
const DIRECT_MESSAGE_INVITATION: u8 = 1;
const DIRECT_MESSAGE_APPLICATION: u8 = 2;
const DIRECT_MESSAGE_HEADER_BYTES: usize = 4 + 1 + 1 + 32;
const DIRECT_MESSAGE_PACKET_ID_DOMAIN: &[u8] = b"lattice:direct-message-packet-id:v1\0";
const DIRECT_MESSAGE_HISTORY_DOMAIN: &[u8] = b"lattice:direct-message-history:v1\0";
const DIRECT_MESSAGE_PENDING_INVITATION_DOMAIN: &[u8] =
    b"lattice:direct-message-pending-invitation:v1\0";
/// Maximum bytes in one routed DM packet, including its routing header.
pub const MAX_DIRECT_MESSAGE_PACKET_BYTES: usize = 1024 * 1024;
/// Maximum UTF-8 bytes in a direct-message text body.
pub const MAX_DIRECT_MESSAGE_TEXT_BYTES: usize = 64 * 1024;

/// One queued invitation packet for a pinned two-device DM group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectMessagePacket {
    /// Stable packet identity used for retry and ingress deduplication.
    pub packet_id: [u8; 32],
    /// Public MLS group reference used only to route the opaque packet.
    pub group_reference: [u8; 32],
    /// Routed packet bytes; MLS content remains opaque to transports.
    pub envelope_bytes: Vec<u8>,
}

/// Result of creating a direct-message conversation and its invitation packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedDirectMessage {
    pub group_reference: [u8; 32],
    pub peer_identity: [u8; 32],
    pub invitation: DirectMessagePacket,
}

/// One decrypted direct-message history item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDirectMessage {
    pub packet_id: [u8; 32],
    pub group_reference: [u8; 32],
    pub author_identity: [u8; 32],
    pub content: String,
}

/// Metadata for an authenticated invitation awaiting explicit user consent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectMessagePendingInvitation {
    pub packet_id: [u8; 32],
    pub group_reference: [u8; 32],
    pub peer_identity: [u8; 32],
}

/// Outcome after a routed direct-message packet is authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectMessageIngressOutcome {
    Accepted {
        packet_id: [u8; 32],
        content: String,
    },
    InvitationPending {
        packet_id: [u8; 32],
        group_reference: [u8; 32],
        peer_identity: [u8; 32],
    },
    Duplicate {
        packet_id: [u8; 32],
    },
}

struct DecodedInvitationBody {
    inviter: [u8; 32],
    target: [u8; 32],
    group_id: Vec<u8>,
    welcome: Vec<u8>,
}

#[derive(Clone, Copy)]
struct RoutedDirectMessage<'a> {
    kind: u8,
    group_reference: [u8; 32],
    body: &'a [u8],
}

impl Client {
    fn direct_message_credential(
        &self,
        credential_content: Vec<u8>,
    ) -> Result<lattice_mls::api::DeviceCredentialInput, CoreError> {
        let credential = openmls::credentials::Credential::new(
            openmls::prelude::CredentialType::X509,
            credential_content,
        );
        lattice_mls::api::DeviceCredentialInput::from_x509_credential_with_policy(
            &self.identity,
            credential,
            &self.credential_trust_policy,
        )
        .map_err(|_| CoreError::SpaceCredentialInvalid)
    }

    /// Publishes a `KeyPackage` bound to a validated local X.509 credential.
    ///
    /// # Errors
    ///
    /// Returns an error if credential validation or key-package publication fails.
    pub fn publish_direct_message_key_package(
        &mut self,
        credential_content: Vec<u8>,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, CoreError> {
        let credential = self.direct_message_credential(credential_content)?;
        self.publish_key_package(&credential, now_unix_seconds)
    }

    /// Creates a routed pairwise MLS conversation from a validated credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential or peer key package is invalid, or if
    /// the conversation cannot be created and durably queued.
    pub fn create_direct_message_from_x509_credential(
        &mut self,
        credential_content: Vec<u8>,
        peer_identity: [u8; 32],
        peer_key_package: &[u8],
        next_attempt_ms: i64,
    ) -> Result<CreatedDirectMessage, CoreError> {
        let credential = self.direct_message_credential(credential_content)?;
        self.create_direct_message(
            &credential,
            peer_identity,
            peer_key_package,
            next_attempt_ms,
        )
    }

    /// Accepts an invitation only after caller consent and peer binding.
    ///
    /// # Errors
    ///
    /// Returns an error if consent is absent, the peer binding is invalid, or
    /// the invitation cannot be imported and stored.
    pub fn accept_direct_message_invitation_from_x509_credential(
        &mut self,
        credential_content: Vec<u8>,
        authenticated_peer_identity: [u8; 32],
        invitation_packet: &[u8],
        user_accepted: bool,
    ) -> Result<[u8; 32], CoreError> {
        let credential = self.direct_message_credential(credential_content)?;
        self.accept_direct_message_invitation(
            &credential,
            authenticated_peer_identity,
            invitation_packet,
            user_accepted,
        )
    }

    /// Queues one direct-message text packet under a validated credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential, conversation, or message is invalid,
    /// or if encryption and durable queueing fail.
    pub fn queue_direct_message_text_from_x509_credential(
        &mut self,
        credential_content: Vec<u8>,
        group_reference: [u8; 32],
        content: &str,
        next_attempt_ms: i64,
    ) -> Result<DirectMessagePacket, CoreError> {
        let credential = self.direct_message_credential(credential_content)?;
        self.queue_direct_message_text(&credential, group_reference, content, next_attempt_ms)
    }

    /// Creates a durable pairwise MLS conversation and queues its routed Welcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential or peer key package is invalid, or if
    /// the conversation cannot be created and durably queued.
    ///
    /// `peer_key_package` must contain an X.509 credential for `peer_identity`.
    /// The returned packet is intended for an authenticated transport addressed
    /// to that exact peer; the transport must not infer destination delivery.
    pub fn create_direct_message(
        &mut self,
        credential: &DeviceCredentialInput,
        peer_identity: [u8; 32],
        peer_key_package: &[u8],
        next_attempt_ms: i64,
    ) -> Result<CreatedDirectMessage, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        let credential = credential.clone();
        let peer_key_package = peer_key_package.to_vec();
        let local_identity = self.identity.fingerprint();
        let (conversation, packet) =
            self.with_mls_transaction(move |identity, provider, transaction| {
                if identity.fingerprint() != local_identity {
                    return Err(CoreError::DirectMessagePeerMismatch);
                }
                let (_group, invitation) = lattice_mls::api::DirectMessageGroup::create(
                    provider,
                    identity,
                    &credential,
                    peer_identity,
                    &peer_key_package,
                )?;
                let group_reference = invitation.group_reference().to_owned();
                let group_id = invitation.group_id();
                let invitation_body = encode_invitation_body(
                    &local_identity,
                    &peer_identity,
                    group_id,
                    invitation.welcome().as_bytes(),
                )?;
                let envelope_bytes = encode_routed_packet(
                    DIRECT_MESSAGE_INVITATION,
                    &group_reference,
                    &invitation_body,
                )?;
                let packet_id = packet_id(&envelope_bytes);
                let conversation = DirectMessageConversation {
                    group_reference,
                    group_id: group_id.to_vec(),
                    peer_identity,
                    closed: false,
                };
                Store::save_direct_message_conversation_in_transaction(transaction, &conversation)?;
                Store::commit_direct_message_outbox_in_transaction(
                    transaction,
                    &DirectMessageOutboxEntry {
                        packet_id,
                        group_reference,
                        envelope_bytes: envelope_bytes.clone(),
                        next_attempt_ms,
                        attempt_count: 0,
                        state: OutboxState::Queued,
                    },
                )?;
                Ok((
                    conversation,
                    DirectMessagePacket {
                        packet_id,
                        group_reference,
                        envelope_bytes,
                    },
                ))
            })?;
        drop(conversation);
        Ok(CreatedDirectMessage {
            group_reference: packet.group_reference,
            peer_identity,
            invitation: packet,
        })
    }

    /// Accepts an invitation only after caller consent and authenticated peer binding.
    ///
    /// # Errors
    ///
    /// Returns an error if consent is absent, the credential or peer binding is
    /// invalid, or the invitation cannot be imported and stored.
    pub fn accept_direct_message_invitation(
        &mut self,
        credential: &DeviceCredentialInput,
        authenticated_peer_identity: [u8; 32],
        invitation_packet: &[u8],
        user_accepted: bool,
    ) -> Result<[u8; 32], CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        if !user_accepted {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        let routed = decode_routed_packet(invitation_packet)?;
        if routed.kind != DIRECT_MESSAGE_INVITATION {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        let DecodedInvitationBody {
            inviter,
            target,
            group_id,
            welcome,
        } = decode_invitation_body(routed.body)?;
        if inviter != authenticated_peer_identity || target != self.identity.fingerprint() {
            return Err(CoreError::DirectMessagePeerMismatch);
        }
        let expected_group_reference = routed.group_reference;
        let local_credential = credential.clone();
        self.with_mls_transaction(move |identity, provider, transaction| {
            let group = lattice_mls::api::DirectMessageGroup::from_welcome(
                provider,
                &group_id,
                &local_credential,
                authenticated_peer_identity,
                &welcome,
            )?;
            if group.group_reference() != expected_group_reference {
                return Err(CoreError::DirectMessagePacketInvalid);
            }
            Store::save_direct_message_conversation_in_transaction(
                transaction,
                &DirectMessageConversation {
                    group_reference: expected_group_reference,
                    group_id,
                    peer_identity: authenticated_peer_identity,
                    closed: false,
                },
            )?;
            if identity.fingerprint() != target {
                return Err(CoreError::DirectMessagePeerMismatch);
            }
            Ok(expected_group_reference)
        })
    }

    /// Encrypts, retains, and queues one immutable direct-message text packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential, conversation, or message is invalid,
    /// or if encryption and durable queueing fail.
    pub fn queue_direct_message_text(
        &mut self,
        credential: &DeviceCredentialInput,
        group_reference: [u8; 32],
        content: &str,
        next_attempt_ms: i64,
    ) -> Result<DirectMessagePacket, CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        if content.is_empty() || content.len() > MAX_DIRECT_MESSAGE_TEXT_BYTES {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        let conversation = self
            .store
            .load_direct_message_conversation(&group_reference)?
            .filter(|conversation| !conversation.closed)
            .ok_or(CoreError::DirectMessageConversationUnavailable)?;
        let local_credential = credential.clone();
        let content = content.to_owned();
        let local_identity = self.identity.fingerprint();
        self.with_mls_transaction(move |identity, provider, transaction| {
            if identity.fingerprint() != local_identity {
                return Err(CoreError::DirectMessagePeerMismatch);
            }
            let mut group = lattice_mls::api::DirectMessageGroup::load_with_trust_policy(
                provider,
                &conversation.group_id,
                local_identity,
                conversation.peer_identity,
                &local_credential.trust_policy().clone(),
            )?;
            let plaintext = encode_text_body(&content)?;
            let wire = group
                .encrypt_application(provider, identity, &local_credential, &plaintext)?
                .as_bytes()
                .to_vec();
            let envelope_bytes =
                encode_routed_packet(DIRECT_MESSAGE_APPLICATION, &group_reference, &wire)?;
            let packet_id = packet_id(&envelope_bytes);
            let encrypted_content = lattice_mls::protect_local_record(
                &history_context(&group_reference, &packet_id),
                content.as_bytes(),
            )?;
            Store::save_direct_message_record_in_transaction(
                transaction,
                &DirectMessageRecord {
                    packet_id,
                    group_reference,
                    author_identity: local_identity,
                    encrypted_content,
                },
            )?;
            Store::commit_direct_message_outbox_in_transaction(
                transaction,
                &DirectMessageOutboxEntry {
                    packet_id,
                    group_reference,
                    envelope_bytes: envelope_bytes.clone(),
                    next_attempt_ms,
                    attempt_count: 0,
                    state: OutboxState::Queued,
                },
            )?;
            Ok(DirectMessagePacket {
                packet_id,
                group_reference,
                envelope_bytes,
            })
        })
    }

    fn ingest_direct_message_invitation(
        &mut self,
        authenticated_peer_identity: [u8; 32],
        packet_id: [u8; 32],
        routed: RoutedDirectMessage<'_>,
        envelope_bytes: &[u8],
    ) -> Result<DirectMessageIngressOutcome, CoreError> {
        let invitation = decode_invitation_body(routed.body)?;
        let local_identity = self.identity.fingerprint();
        if invitation.inviter != authenticated_peer_identity || invitation.target != local_identity
        {
            return Err(CoreError::DirectMessagePeerMismatch);
        }
        if self
            .store
            .load_direct_message_conversation(&routed.group_reference)?
            .is_some_and(|conversation| {
                !conversation.closed && conversation.peer_identity == authenticated_peer_identity
            })
        {
            return Ok(DirectMessageIngressOutcome::Duplicate { packet_id });
        }
        let Some(pending) = self
            .store
            .load_pending_direct_message_invitation(&packet_id)?
        else {
            let group_reference = routed.group_reference;
            let invitation_envelope = envelope_bytes.to_vec();
            return self.with_mls_transaction(move |identity, _, transaction| {
                if identity.fingerprint() != local_identity {
                    return Err(CoreError::DirectMessagePeerMismatch);
                }
                let encrypted_envelope = lattice_mls::protect_local_record(
                    &pending_invitation_context(&packet_id),
                    &invitation_envelope,
                )?;
                let pending = PendingDirectMessageInvitation {
                    packet_id,
                    group_reference,
                    peer_identity: authenticated_peer_identity,
                    encrypted_envelope,
                };
                Store::save_pending_direct_message_invitation_in_transaction(
                    transaction,
                    &pending,
                )?;
                Ok(DirectMessageIngressOutcome::InvitationPending {
                    packet_id,
                    group_reference,
                    peer_identity: authenticated_peer_identity,
                })
            });
        };
        if pending.group_reference != routed.group_reference
            || pending.peer_identity != authenticated_peer_identity
        {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        Ok(DirectMessageIngressOutcome::Duplicate { packet_id })
    }

    fn ingest_direct_message_application(
        &mut self,
        authenticated_peer_identity: [u8; 32],
        packet_id: [u8; 32],
        routed: RoutedDirectMessage<'_>,
    ) -> Result<DirectMessageIngressOutcome, CoreError> {
        let group_reference = routed.group_reference;
        let conversation = self
            .store
            .load_direct_message_conversation(&group_reference)?
            .filter(|conversation| !conversation.closed)
            .ok_or(CoreError::DirectMessageConversationUnavailable)?;
        if conversation.peer_identity != authenticated_peer_identity {
            return Err(CoreError::DirectMessagePeerMismatch);
        }
        let group_id = conversation.group_id;
        let trust_policy = self.credential_trust_policy.clone();
        let wire = routed.body.to_vec();
        self.with_mls_transaction(move |identity, provider, transaction| {
            if identity.fingerprint() == authenticated_peer_identity {
                return Err(CoreError::DirectMessagePeerMismatch);
            }
            if Store::direct_message_history_contains_in_transaction(transaction, &packet_id)? {
                return Ok(DirectMessageIngressOutcome::Duplicate { packet_id });
            }
            let mut group = lattice_mls::api::DirectMessageGroup::load_with_trust_policy(
                provider,
                &group_id,
                identity.fingerprint(),
                authenticated_peer_identity,
                &trust_policy,
            )?;
            let IncomingResult::Application(application) =
                group.process_incoming(provider, &wire)?
            else {
                return Err(CoreError::DirectMessagePacketInvalid);
            };
            if application.member_identity_fingerprint() != Some(&authenticated_peer_identity) {
                return Err(CoreError::DirectMessagePeerMismatch);
            }
            let content = decode_text_body(application.plaintext())?;
            let encrypted_content = lattice_mls::protect_local_record(
                &history_context(&group_reference, &packet_id),
                content.as_bytes(),
            )?;
            Store::save_direct_message_record_in_transaction(
                transaction,
                &DirectMessageRecord {
                    packet_id,
                    group_reference,
                    author_identity: authenticated_peer_identity,
                    encrypted_content,
                },
            )?;
            Ok(DirectMessageIngressOutcome::Accepted { packet_id, content })
        })
    }

    /// Authenticates and stores one incoming DM application packet from its pinned peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed, is not from the pinned peer,
    /// or cannot be authenticated and stored.
    pub fn ingest_direct_message_packet(
        &mut self,
        authenticated_peer_identity: [u8; 32],
        envelope_bytes: &[u8],
    ) -> Result<DirectMessageIngressOutcome, CoreError> {
        let routed = decode_routed_packet(envelope_bytes)?;
        let packet_id = packet_id(envelope_bytes);
        if routed.kind == DIRECT_MESSAGE_INVITATION {
            return self.ingest_direct_message_invitation(
                authenticated_peer_identity,
                packet_id,
                routed,
                envelope_bytes,
            );
        }
        if routed.kind != DIRECT_MESSAGE_APPLICATION {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        self.ingest_direct_message_application(authenticated_peer_identity, packet_id, routed)
    }

    /// Returns recent direct-message conversations in stable order.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the conversation store fails.
    pub fn direct_message_conversations(
        &self,
        limit: usize,
    ) -> Result<Vec<DirectMessageConversation>, CoreError> {
        Ok(self.store.list_direct_message_conversations(limit)?)
    }

    /// Checks whether an open local conversation is bound to one peer identity.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the conversation store fails.
    pub fn direct_message_is_for_peer(
        &self,
        group_reference: [u8; 32],
        peer_identity: [u8; 32],
    ) -> Result<bool, CoreError> {
        Ok(self
            .store
            .load_direct_message_conversation(&group_reference)?
            .is_some_and(|conversation| {
                !conversation.closed && conversation.peer_identity == peer_identity
            }))
    }

    /// Returns one bounded page of encrypted direct-message retry packets.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the outbox fails.
    pub fn direct_message_outbox_page(
        &self,
        after_packet_id: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<DirectMessageOutboxEntry>, CoreError> {
        Ok(self
            .store
            .list_direct_message_outbox_page(after_packet_id, limit)?)
    }

    /// Records a forwarding attempt before a DM packet is placed on transport.
    ///
    /// # Errors
    ///
    /// Returns an error if updating the outbox fails.
    pub fn mark_direct_message_attempt(
        &mut self,
        packet_id: [u8; 32],
        next_attempt_ms: i64,
    ) -> Result<(), CoreError> {
        self.store
            .mark_direct_message_forwarding_attempt(packet_id, next_attempt_ms)?;
        Ok(())
    }

    /// Records only authenticated peer-ingress acceptance, never delivery.
    ///
    /// # Errors
    ///
    /// Returns an error if updating the outbox fails.
    pub fn record_direct_message_peer_ingress_accepted(
        &mut self,
        packet_id: [u8; 32],
    ) -> Result<(), CoreError> {
        self.store
            .record_direct_message_peer_ingress_accepted(packet_id)?;
        Ok(())
    }

    /// Returns local decrypted DM history after authenticating its at-rest records.
    ///
    /// # Errors
    ///
    /// Returns an error if history cannot be read or its protected records fail
    /// authentication or validation.
    pub fn direct_message_history(
        &mut self,
        group_reference: [u8; 32],
        limit: usize,
    ) -> Result<Vec<LocalDirectMessage>, CoreError> {
        let records = self
            .store
            .list_direct_message_history(&group_reference, limit)?;
        self.with_mls_transaction(move |_, _, _| {
            records
                .into_iter()
                .map(|record| {
                    let plaintext = lattice_mls::unprotect_local_record(
                        &history_context(&group_reference, &record.packet_id),
                        &record.encrypted_content,
                    )?;
                    let content = String::from_utf8(plaintext)
                        .map_err(|_| CoreError::DirectMessagePacketInvalid)?;
                    if content.is_empty() || content.len() > MAX_DIRECT_MESSAGE_TEXT_BYTES {
                        return Err(CoreError::DirectMessagePacketInvalid);
                    }
                    Ok(LocalDirectMessage {
                        packet_id: record.packet_id,
                        group_reference: record.group_reference,
                        author_identity: record.author_identity,
                        content,
                    })
                })
                .collect()
        })
    }

    /// Lists invitations persisted from authenticated transport ingress.
    ///
    /// # Errors
    ///
    /// Returns an error if reading pending invitations fails.
    pub fn pending_direct_message_invitations(
        &self,
        limit: usize,
    ) -> Result<Vec<DirectMessagePendingInvitation>, CoreError> {
        Ok(self
            .store
            .list_pending_direct_message_invitations(limit)?
            .into_iter()
            .map(|invitation| DirectMessagePendingInvitation {
                packet_id: invitation.packet_id,
                group_reference: invitation.group_reference,
                peer_identity: invitation.peer_identity,
            })
            .collect())
    }

    /// Accepts a persisted invitation only after explicit user consent.
    ///
    /// # Errors
    ///
    /// Returns an error if consent is absent, the peer binding is invalid, or
    /// the persisted invitation cannot be opened and accepted.
    pub fn accept_pending_direct_message_invitation_from_x509_credential(
        &mut self,
        credential_content: Vec<u8>,
        authenticated_peer_identity: [u8; 32],
        expected_packet_id: [u8; 32],
        user_accepted: bool,
    ) -> Result<[u8; 32], CoreError> {
        if !user_accepted {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        let credential = self.direct_message_credential(credential_content)?;
        self.accept_pending_direct_message_invitation(
            &credential,
            authenticated_peer_identity,
            expected_packet_id,
            true,
        )
    }

    /// Accepts a persisted invitation only after explicit user consent.
    ///
    /// # Errors
    ///
    /// Returns an error if consent is absent, the credential or peer binding is
    /// invalid, or the persisted invitation cannot be opened and accepted.
    pub fn accept_pending_direct_message_invitation(
        &mut self,
        credential: &lattice_mls::api::DeviceCredentialInput,
        authenticated_peer_identity: [u8; 32],
        expected_packet_id: [u8; 32],
        user_accepted: bool,
    ) -> Result<[u8; 32], CoreError> {
        self.ensure_credential_trust_policy(credential)?;
        if !user_accepted {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        let pending = self
            .store
            .load_pending_direct_message_invitation(&expected_packet_id)?
            .ok_or(CoreError::DirectMessageConversationUnavailable)?;
        if pending.peer_identity != authenticated_peer_identity {
            return Err(CoreError::DirectMessagePeerMismatch);
        }
        let encrypted_envelope = pending.encrypted_envelope;
        let invitation_packet = self.with_mls_transaction(move |_, _, _| {
            lattice_mls::unprotect_local_record(
                &pending_invitation_context(&expected_packet_id),
                &encrypted_envelope,
            )
            .map_err(CoreError::from)
        })?;
        if packet_id(&invitation_packet) != expected_packet_id {
            return Err(CoreError::DirectMessagePacketInvalid);
        }
        let existing = self
            .store
            .load_direct_message_conversation(&pending.group_reference)?
            .filter(|conversation| {
                !conversation.closed && conversation.peer_identity == authenticated_peer_identity
            });
        let group_reference = match existing {
            Some(conversation) => conversation.group_reference,
            None => self.accept_direct_message_invitation(
                credential,
                authenticated_peer_identity,
                &invitation_packet,
                true,
            )?,
        };
        self.store
            .remove_pending_direct_message_invitation(&expected_packet_id)?;
        Ok(group_reference)
    }

    /// Declines one persisted invitation without importing its MLS Welcome.
    ///
    /// # Errors
    ///
    /// Returns an error if removing the pending invitation fails.
    pub fn decline_pending_direct_message_invitation(
        &mut self,
        packet_id: [u8; 32],
    ) -> Result<bool, CoreError> {
        Ok(self
            .store
            .remove_pending_direct_message_invitation(&packet_id)?)
    }
}

fn encode_routed_packet(
    kind: u8,
    group_reference: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if !matches!(kind, DIRECT_MESSAGE_INVITATION | DIRECT_MESSAGE_APPLICATION)
        || body.is_empty()
        || body.len() > MAX_DIRECT_MESSAGE_PACKET_BYTES - DIRECT_MESSAGE_HEADER_BYTES
    {
        return Err(CoreError::DirectMessagePacketInvalid);
    }
    let mut bytes = Vec::with_capacity(DIRECT_MESSAGE_HEADER_BYTES + body.len());
    bytes.extend_from_slice(DIRECT_MESSAGE_MAGIC);
    bytes.push(DIRECT_MESSAGE_VERSION);
    bytes.push(kind);
    bytes.extend_from_slice(group_reference);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn decode_routed_packet(bytes: &[u8]) -> Result<RoutedDirectMessage<'_>, CoreError> {
    if bytes.len() <= DIRECT_MESSAGE_HEADER_BYTES
        || bytes.len() > MAX_DIRECT_MESSAGE_PACKET_BYTES
        || &bytes[..4] != DIRECT_MESSAGE_MAGIC
        || bytes[4] != DIRECT_MESSAGE_VERSION
        || !matches!(
            bytes[5],
            DIRECT_MESSAGE_INVITATION | DIRECT_MESSAGE_APPLICATION
        )
    {
        return Err(CoreError::DirectMessagePacketInvalid);
    }
    Ok(RoutedDirectMessage {
        kind: bytes[5],
        group_reference: bytes[6..DIRECT_MESSAGE_HEADER_BYTES]
            .try_into()
            .map_err(|_| CoreError::DirectMessagePacketInvalid)?,
        body: &bytes[DIRECT_MESSAGE_HEADER_BYTES..],
    })
}

fn encode_invitation_body(
    inviter: &[u8; 32],
    target: &[u8; 32],
    group_id: &[u8],
    welcome: &[u8],
) -> Result<Vec<u8>, CoreError> {
    encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Bytes(inviter.to_vec())),
        (2, Value::Bytes(target.to_vec())),
        (3, Value::Bytes(group_id.to_vec())),
        (4, Value::Bytes(welcome.to_vec())),
    ]))
    .map_err(CoreError::from)
}

fn decode_invitation_body(bytes: &[u8]) -> Result<DecodedInvitationBody, CoreError> {
    let value = decode_canonical(bytes).map_err(|_| CoreError::DirectMessagePacketInvalid)?;
    let Value::Map(fields) = value else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    if fields.len() != 5
        || fields
            .iter()
            .enumerate()
            .any(|(index, (key, _))| *key != index as u64)
    {
        return Err(CoreError::DirectMessagePacketInvalid);
    }
    let Value::Unsigned(1) = fields[0].1 else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    let Value::Bytes(inviter) = &fields[1].1 else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    let Value::Bytes(target) = &fields[2].1 else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    let Value::Bytes(group_id) = &fields[3].1 else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    let Value::Bytes(welcome) = &fields[4].1 else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    if group_id.is_empty()
        || group_id.len() > 256
        || welcome.is_empty()
        || inviter.len() != 32
        || target.len() != 32
    {
        return Err(CoreError::DirectMessagePacketInvalid);
    }
    Ok(DecodedInvitationBody {
        inviter: inviter
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::DirectMessagePacketInvalid)?,
        target: target
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::DirectMessagePacketInvalid)?,
        group_id: group_id.clone(),
        welcome: welcome.clone(),
    })
}

fn encode_text_body(content: &str) -> Result<Vec<u8>, CoreError> {
    if content.is_empty() || content.len() > MAX_DIRECT_MESSAGE_TEXT_BYTES {
        return Err(CoreError::DirectMessagePacketInvalid);
    }
    encode_canonical(&Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Text(content.to_owned())),
    ]))
    .map_err(CoreError::from)
}

fn decode_text_body(bytes: &[u8]) -> Result<String, CoreError> {
    let value = decode_canonical(bytes).map_err(|_| CoreError::DirectMessagePacketInvalid)?;
    let Value::Map(fields) = value else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    if fields.len() != 2 || fields[0].0 != 0 || fields[1].0 != 1 {
        return Err(CoreError::DirectMessagePacketInvalid);
    }
    let Value::Unsigned(1) = fields[0].1 else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    let Value::Text(content) = &fields[1].1 else {
        return Err(CoreError::DirectMessagePacketInvalid);
    };
    if content.is_empty() || content.len() > MAX_DIRECT_MESSAGE_TEXT_BYTES {
        return Err(CoreError::DirectMessagePacketInvalid);
    }
    Ok(content.clone())
}

fn packet_id(envelope_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIRECT_MESSAGE_PACKET_ID_DOMAIN);
    hasher.update(envelope_bytes);
    hasher.finalize().into()
}

fn history_context(group_reference: &[u8; 32], packet_id: &[u8; 32]) -> Vec<u8> {
    let mut context = Vec::with_capacity(DIRECT_MESSAGE_HISTORY_DOMAIN.len() + 64);
    context.extend_from_slice(DIRECT_MESSAGE_HISTORY_DOMAIN);
    context.extend_from_slice(group_reference);
    context.extend_from_slice(packet_id);
    context
}

fn pending_invitation_context(packet_id: &[u8; 32]) -> Vec<u8> {
    let mut context = Vec::with_capacity(DIRECT_MESSAGE_PENDING_INVITATION_DOMAIN.len() + 32);
    context.extend_from_slice(DIRECT_MESSAGE_PENDING_INVITATION_DOMAIN);
    context.extend_from_slice(packet_id);
    context
}
