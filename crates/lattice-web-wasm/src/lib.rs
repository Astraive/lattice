use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use lattice_identity::{PrivateKeyProtectionError, PrivateKeyProtector};
use zeroize::Zeroizing;

const WRAP_FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const WRAP_AAD: &[u8] = b"lattice.web.private-key-wrap.v1\0";

/// Protects Core's persisted identity and MLS keys with the unlocked profile key.
///
/// The browser worker obtains this key by unwrapping a profile key using the
/// origin-scoped, non-extractable Web Crypto key. The key is held only for the
/// lifetime of the unlocked profile and is zeroized when its worker closes it.
pub struct SessionKeyProtector {
    key: Zeroizing<[u8; 32]>,
}

impl SessionKeyProtector {
    /// Creates a session protector from exactly 32 bytes of unwrapped key data.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateKeyProtectionError`] if `key` is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, PrivateKeyProtectionError> {
        let key: [u8; 32] = key.try_into().map_err(|_| PrivateKeyProtectionError)?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }
}

impl std::fmt::Debug for SessionKeyProtector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionKeyProtector([REDACTED])")
    }
}

impl PrivateKeyProtector for SessionKeyProtector {
    fn wrap(&self, private_material: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| PrivateKeyProtectionError)?;
        let cipher =
            Aes256Gcm::new_from_slice(&self.key[..]).map_err(|_| PrivateKeyProtectionError)?;
        let ciphertext = cipher
            .encrypt(
                TryFrom::try_from(&nonce).map_err(|_| PrivateKeyProtectionError)?,
                Payload {
                    msg: private_material,
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| PrivateKeyProtectionError)?;
        let mut protected = Vec::with_capacity(1 + NONCE_BYTES + ciphertext.len());
        protected.push(WRAP_FORMAT_VERSION);
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&ciphertext);
        Ok(protected)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PrivateKeyProtectionError> {
        if ciphertext.len() < 1 + NONCE_BYTES + TAG_BYTES || ciphertext[0] != WRAP_FORMAT_VERSION {
            return Err(PrivateKeyProtectionError);
        }
        let nonce_end = 1 + NONCE_BYTES;
        let nonce =
            TryFrom::try_from(&ciphertext[1..nonce_end]).map_err(|_| PrivateKeyProtectionError)?;
        let cipher =
            Aes256Gcm::new_from_slice(&self.key[..]).map_err(|_| PrivateKeyProtectionError)?;
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext[nonce_end..],
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| PrivateKeyProtectionError)
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod browser {
    use super::SessionKeyProtector;
    use js_sys::{Array, Uint8Array};
    use lattice_core::space::ChannelType;
    use lattice_core::{
        Client, CreatedSpace, InitialChannel, MAX_OUTBOX_PAGE_SIZE, OutboxApplicationEventPage,
    };
    use lattice_mls::api::{CredentialTrustPolicy, install_browser_opfs_vfs_for_profile};
    use openmls::prelude::tls_codec::{Serialize as TlsSerialize, VLBytes};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use wasm_bindgen::prelude::*;
    use zeroize::Zeroizing;

    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    #[derive(serde::Serialize)]
    struct PublicIdentityView {
        public_bundle: Vec<u8>,
        fingerprint: Vec<u8>,
    }

    #[derive(Serialize)]
    struct SpaceView {
        space_id: Vec<u8>,
        group_reference: Vec<u8>,
        channels: Vec<ChannelView>,
    }

    #[derive(Serialize)]
    struct ChannelView {
        id: Vec<u8>,
        name: String,
        channel_type: &'static str,
    }

    #[derive(Serialize)]
    struct MessageView {
        event_id: Vec<u8>,
        author_id: Vec<u8>,
        content: String,
    }

    #[derive(Serialize)]
    struct InviteView {
        target_fingerprint: Vec<u8>,
        welcome_bootstrap: Vec<u8>,
    }

    fn certificate_credential(certificate_der: &[u8]) -> Result<Vec<u8>, JsValue> {
        if certificate_der.is_empty() || certificate_der.len() > 16 * 1024 {
            return Err(JsValue::from_str(
                "device certificate must contain 1 to 16384 DER bytes",
            ));
        }
        vec![VLBytes::new(certificate_der.to_vec())]
            .tls_serialize_detached()
            .map_err(|_| JsValue::from_str("device certificate could not be encoded"))
    }

    fn fixed_bytes<const N: usize>(bytes: &Uint8Array, label: &str) -> Result<[u8; N], JsValue> {
        if bytes.length() as usize != N {
            return Err(JsValue::from_str(&format!("{label} must be {N} bytes")));
        }
        let mut fixed = [0_u8; N];
        bytes.copy_to(&mut fixed);
        Ok(fixed)
    }

    fn space_view(created: &CreatedSpace) -> Result<SpaceView, JsValue> {
        let policy = created
            .reducer()
            .policy()
            .ok_or_else(|| JsValue::from_str("Space has no active policy"))?;
        Ok(SpaceView {
            space_id: created.space_id().to_vec(),
            group_reference: created.group_reference().to_vec(),
            channels: policy
                .channels
                .iter()
                .filter(|channel| !channel.archived)
                .map(|channel| ChannelView {
                    id: channel.id.to_vec(),
                    name: channel.name.clone(),
                    channel_type: match channel.channel_type {
                        ChannelType::Text => "text",
                        ChannelType::Announcement => "announcement",
                        ChannelType::Voice => "voice",
                    },
                })
                .collect(),
        })
    }

    fn space_json(created: &CreatedSpace) -> Result<String, JsValue> {
        serde_json::to_string(&space_view(created)?)
            .map_err(|_| JsValue::from_str("could not encode Space details"))
    }

    #[wasm_bindgen]
    pub struct WebProfile {
        client: Option<Client>,
        _protector: Option<SessionKeyProtector>,
        _opfs_pool: Option<lattice_mls::api::BrowserOpfsPool>,
    }

    #[wasm_bindgen]
    impl WebProfile {
        /// Returns the non-secret identity bundle and fingerprint as JSON.
        #[wasm_bindgen(js_name = identityInfoJson)]
        pub fn identity_info_json(&self) -> Result<String, JsValue> {
            let client = self
                .client
                .as_ref()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?;
            let identity = client.identity_info();
            serde_json::to_string(&PublicIdentityView {
                public_bundle: identity.public_bundle.to_vec(),
                fingerprint: identity.fingerprint.to_vec(),
            })
            .map_err(|_| JsValue::from_str("could not encode public identity"))
        }

        /// Creates a DER PKCS#10 request without exporting the identity key.
        #[wasm_bindgen(js_name = certificateSigningRequest)]
        pub fn certificate_signing_request(&self) -> Result<Vec<u8>, JsValue> {
            self.client
                .as_ref()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .certificate_signing_request()
                .map_err(|error| JsValue::from_str(&error.to_string()))
        }

        /// Lists integrity-checked local Spaces and their active channels.
        #[wasm_bindgen(js_name = spacesJson)]
        pub fn spaces_json(&mut self) -> Result<String, JsValue> {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?;
            let mut spaces = Vec::new();
            let mut cursor = None;
            loop {
                let page = client
                    .restore_space_page(cursor)
                    .map_err(|error| JsValue::from_str(&error.to_string()))?;
                for created in page.spaces() {
                    spaces.push(space_view(created)?);
                }
                cursor = page.next_cursor();
                if cursor.is_none() {
                    break;
                }
            }
            serde_json::to_string(&spaces)
                .map_err(|_| JsValue::from_str("could not encode browser Space list"))
        }
        /// Closes Core and releases the worker-owned OPFS connection.
        pub fn close(&mut self) {
            self.client.take();
            self._protector.take();
            self._opfs_pool.take();
        }
        /// Creates the starter Space using the locally issued device certificate.
        #[wasm_bindgen(js_name = createSpace)]
        pub fn create_space(&mut self, certificate_der: Uint8Array) -> Result<String, JsValue> {
            let credential = certificate_credential(&certificate_der.to_vec())?;
            let created = self
                .client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .create_space_from_x509_credential(
                    credential,
                    vec![InitialChannel {
                        channel_type: ChannelType::Text,
                        name: "general".to_owned(),
                        default_allow: 0,
                        default_deny: 0,
                        role_overrides: Vec::new(),
                    }],
                )
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            space_json(&created)
        }

        /// Publishes one tracked X.509 KeyPackage for offline profile invites.
        #[wasm_bindgen(js_name = publishKeyPackage)]
        pub fn publish_key_package(
            &mut self,
            certificate_der: Uint8Array,
        ) -> Result<Vec<u8>, JsValue> {
            let credential = certificate_credential(&certificate_der.to_vec())?;
            let now = (js_sys::Date::now() / 1000.0).max(0.0) as u64;
            self.client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .publish_x509_key_package(credential, now)
                .map_err(|error| JsValue::from_str(&error.to_string()))
        }

        /// Invites one device by committing a policy Invite and MLS Add.
        #[wasm_bindgen(js_name = createInvite)]
        pub fn create_invite(
            &mut self,
            space_id: Uint8Array,
            group_reference: Uint8Array,
            certificate_der: Uint8Array,
            key_package: Uint8Array,
        ) -> Result<String, JsValue> {
            let space_id = fixed_bytes::<16>(&space_id, "Space ID")?;
            let group_reference = fixed_bytes::<32>(&group_reference, "group reference")?;
            let credential = certificate_credential(&certificate_der.to_vec())?;
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?;
            let mut created = client
                .restore_space(&space_id, &group_reference)
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            let now = (js_sys::Date::now() / 1000.0).max(0.0) as u64;
            let invite = client
                .create_space_invite_from_x509_credential(
                    &mut created,
                    credential,
                    &key_package.to_vec(),
                    None,
                    now.saturating_add(86_400),
                    Some(1),
                )
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            serde_json::to_string(&InviteView {
                target_fingerprint: invite.target_fingerprint().to_vec(),
                welcome_bootstrap: invite.welcome_bootstrap().to_vec(),
            })
            .map_err(|_| JsValue::from_str("could not encode Space invitation"))
        }

        /// Joins a Space from its signed offline Welcome bootstrap.
        #[wasm_bindgen(js_name = joinSpace)]
        pub fn join_space(
            &mut self,
            welcome_bootstrap: Uint8Array,
            inviter_fingerprint: Uint8Array,
            certificate_der: Uint8Array,
        ) -> Result<String, JsValue> {
            let inviter = fixed_bytes::<32>(&inviter_fingerprint, "inviter fingerprint")?;
            let credential = certificate_credential(&certificate_der.to_vec())?;
            let created = self
                .client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .join_space_from_welcome_bootstrap_from_x509_credential(
                    &welcome_bootstrap.to_vec(),
                    inviter,
                    credential,
                )
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            space_json(&created)
        }

        /// Encrypts and queues one text message for the selected channel.
        #[wasm_bindgen(js_name = sendTextMessage)]
        pub fn send_text_message(
            &mut self,
            space_id: Uint8Array,
            group_reference: Uint8Array,
            channel_id: Uint8Array,
            certificate_der: Uint8Array,
            content: String,
        ) -> Result<(), JsValue> {
            let space_id = fixed_bytes::<16>(&space_id, "Space ID")?;
            let group_reference = fixed_bytes::<32>(&group_reference, "group reference")?;
            let channel_id = fixed_bytes::<16>(&channel_id, "channel ID")?;
            let credential = certificate_credential(&certificate_der.to_vec())?;
            self.client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .queue_text_message_from_x509_credential(
                    &space_id,
                    &group_reference,
                    credential,
                    channel_id,
                    &content,
                )
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            Ok(())
        }

        /// Returns the locally decrypted bounded message history as JSON.
        #[wasm_bindgen(js_name = textMessageHistoryJson)]
        pub fn text_message_history_json(
            &mut self,
            space_id: Uint8Array,
            group_reference: Uint8Array,
            channel_id: Uint8Array,
        ) -> Result<String, JsValue> {
            let space_id = fixed_bytes::<16>(&space_id, "Space ID")?;
            let group_reference = fixed_bytes::<32>(&group_reference, "group reference")?;
            let channel_id = fixed_bytes::<16>(&channel_id, "channel ID")?;
            let messages = self
                .client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .local_text_message_history(&space_id, &group_reference, &channel_id)
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            let view: Vec<MessageView> = messages
                .into_iter()
                .map(|message| MessageView {
                    event_id: message.event_id.to_vec(),
                    author_id: message.author_id.to_vec(),
                    content: message.content,
                })
                .collect();
            serde_json::to_string(&view)
                .map_err(|_| JsValue::from_str("could not encode local message history"))
        }

        /// Returns a bounded batch of verified signed messages for local sync.
        #[wasm_bindgen(js_name = outboxMessagePage)]
        pub fn outbox_message_page(
            &self,
            space_id: Uint8Array,
            group_reference: Uint8Array,
            after_event_id: Option<Uint8Array>,
        ) -> Result<Array, JsValue> {
            let space_id = fixed_bytes::<16>(&space_id, "Space ID")?;
            let group_reference = fixed_bytes::<32>(&group_reference, "group reference")?;
            let cursor = after_event_id
                .as_ref()
                .map(|bytes| fixed_bytes::<32>(bytes, "outbox cursor"))
                .transpose()?;
            let page: OutboxApplicationEventPage = self
                .client
                .as_ref()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .outbox_application_event_page(
                    &space_id,
                    &group_reference,
                    cursor,
                    MAX_OUTBOX_PAGE_SIZE,
                )
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            let result = Array::new();
            let events = Array::new();
            for event in page.events() {
                events.push(&Uint8Array::from(event.as_slice()));
            }
            result.push(&events);
            match page.next_cursor() {
                Some(cursor) => result.push(&Uint8Array::from(cursor.as_slice())),
                None => result.push(&JsValue::NULL),
            };
            Ok(result)
        }

        /// Authenticates a signed application event received from another peer.
        #[wasm_bindgen(js_name = acceptSyncedEvent)]
        pub fn accept_synced_event(&mut self, canonical_event: Uint8Array) -> Result<(), JsValue> {
            self.client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .accept_synced_application_event_for_local_generation(&canonical_event.to_vec())
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            Ok(())
        }
        /// Pins a peer identity only when its bundle matches an out-of-band fingerprint.
        #[wasm_bindgen(js_name = pinIdentity)]
        pub fn pin_identity(
            &mut self,
            public_bundle: Uint8Array,
            fingerprint: Uint8Array,
        ) -> Result<(), JsValue> {
            let fingerprint = fixed_bytes::<32>(&fingerprint, "identity fingerprint")?;
            self.client
                .as_mut()
                .ok_or_else(|| JsValue::from_str("profile is closed"))?
                .pin_identity(&public_bundle.to_vec(), fingerprint)
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            Ok(())
        }
    }

    /// Installs OPFS and opens one origin-local profile under its confirmed root pin.
    ///
    /// `wrapping_key` is the 32-byte value unwrapped by the worker using the
    /// profile's non-extractable Web Crypto key. The key is never returned to UI code.
    #[wasm_bindgen]
    pub async fn open_profile(
        profile_id: String,
        root_der: js_sys::Uint8Array,
        root_sha256: js_sys::Uint8Array,
        wrapping_key: js_sys::Uint8Array,
    ) -> Result<WebProfile, JsValue> {
        if profile_id.is_empty() || profile_id.len() > 128 {
            return Err(JsValue::from_str("profile ID must contain 1 to 128 bytes"));
        }
        let root_der = root_der.to_vec();
        if root_sha256.length() != 32 {
            return Err(JsValue::from_str("root pin must be 32 bytes"));
        }
        let mut root_pin = [0_u8; 32];
        root_sha256.copy_to(&mut root_pin);
        let trust_policy = CredentialTrustPolicy::pinned_root_der(&root_der, &root_pin)
            .map_err(|_| JsValue::from_str("pinned issuer root is invalid"))?;
        if wrapping_key.length() != 32 {
            return Err(JsValue::from_str("profile wrapping key must be 32 bytes"));
        }
        let mut session_key = Zeroizing::new([0_u8; 32]);
        wrapping_key.copy_to(&mut session_key[..]);
        let protector = SessionKeyProtector::new(&session_key[..])
            .map_err(|_| JsValue::from_str("profile wrapping key must be 32 bytes"))?;
        let opfs_pool = install_browser_opfs_vfs_for_profile(&profile_id)
            .await
            .map_err(|error| {
                JsValue::from_str(&format!("browser OPFS storage is unavailable: {error:?}"))
            })?;
        let digest = Sha256::digest(profile_id.as_bytes());
        let mut database_name = String::with_capacity("lattice-profile-".len() + 64 + 7);
        database_name.push_str("lattice-profile-");
        for byte in digest {
            database_name.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            database_name.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        database_name.push_str(".sqlite");
        let client =
            Client::open_or_create_with_trust_policy(database_name, &protector, trust_policy)
                .map_err(|_| JsValue::from_str("Core could not open the browser profile"))?;
        Ok(WebProfile {
            client: Some(client),
            _protector: Some(protector),
            _opfs_pool: Some(opfs_pool),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SessionKeyProtector;
    use lattice_identity::PrivateKeyProtector;

    #[test]
    fn session_protection_round_trips_and_rejects_modified_ciphertext() {
        let protector = SessionKeyProtector::new(&[0x3a; 32]).expect("valid key length");
        let plaintext = b"persisted protected identity";
        let mut ciphertext = protector.wrap(plaintext).expect("wrap succeeds");
        assert_ne!(ciphertext, plaintext);
        assert_eq!(
            protector.unwrap(&ciphertext).expect("unwrap succeeds"),
            plaintext
        );
        *ciphertext.last_mut().expect("ciphertext is non-empty") ^= 1;
        assert!(protector.unwrap(&ciphertext).is_err());
    }

    #[test]
    fn session_protection_rejects_wrong_key_and_malformed_version() {
        let protector = SessionKeyProtector::new(&[0x3a; 32]).expect("valid key length");
        let wrong_key = SessionKeyProtector::new(&[0x4b; 32]).expect("valid key length");
        let ciphertext = protector.wrap(b"secret").expect("wrap succeeds");
        assert!(wrong_key.unwrap(&ciphertext).is_err());
        assert!(protector.unwrap(&[0; 1 + 12 + 16]).is_err());
    }

    #[test]
    fn session_protector_redacts_debug_output() {
        let protector = SessionKeyProtector::new(&[0x3a; 32]).expect("valid key length");
        assert_eq!(format!("{protector:?}"), "SessionKeyProtector([REDACTED])");
    }
}
