//! Authenticated Public Key Encryption using `XChaChaPoly20Poly1305` with an
//! `X25519` key exchange.
//!
//! # Warning
//!
//! This crate is written by someone who is *not* a cryptographer. And, while
//! the dependencies of this crate are excellent crates, most of the code that
//! this crate is built upon has not been audited. Use at your own risk.
//!
//! # Public Key Encryption
//!
//! This crate uses [`X25519`](x25519) for public key encryption between two
//! parties. Each party has their own [`StaticSecret`]. A [`PublicKey`] can be
//! derived from each secret and can be freely exchanged. Using
//! [`PublicKeyEncryption`], payloads can be encrypted and decrypted by either
//! party as long as both parties know each other's public keys.
//!
//! ```rust
//! use x25519_xchacha20poly1305::{PublicKeyEncryption, x25519::{PublicKey, StaticSecret}};
//! use rand::{thread_rng, Rng};
//!
//! # fn main() {
//! let bob_private_key = StaticSecret::new(thread_rng());
//! let bob_public_key = PublicKey::from(&bob_private_key);
//!
//! let mary_private_key = StaticSecret::new(thread_rng());
//! let mary_public_key = PublicKey::from(&mary_private_key);
//!
//! // Mary and Bob can exchange public keys, which will allow them to encrypt and decrypt
//! // messages for each other.
//! let bob = PublicKeyEncryption::new(&bob_private_key, &mary_public_key);
//! let mary = PublicKeyEncryption::new(&mary_private_key, &bob_public_key);
//!
//! // Bob sends a message to Mary with a random nonce.
//! let nonce: [u8; 24] = thread_rng().gen();
//! let bobs_message = bob.encrypt(b"hello", b"associated data", &nonce).unwrap();
//!
//! // Bob can decrypt this message.
//! assert_eq!(
//!     bob.decrypt(&bobs_message, b"associated data", &nonce).unwrap(),
//!     b"hello"
//! );
//!
//! // And, so can Mary.
//! assert_eq!(
//!     mary.decrypt(&bobs_message, b"associated data", &nonce).unwrap(),
//!     b"hello"
//! );
//! # }

#![forbid(unsafe_code)]
#![warn(
    clippy::cargo,
    missing_docs,
    clippy::pedantic,
    future_incompatible,
    rust_2018_idioms
)]
#![cfg_attr(doc, deny(rustdoc::all))]
#![allow(clippy::missing_errors_doc)]

use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace, NewAead},
    Tag, XNonce,
};
pub use x25519_dalek as x25519;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

const POLY1305_LEN: usize = 16;

pub mod ephemeral;

/// A public key encryption context.
pub struct PublicKeyEncryption {
    shared_secret: SharedSecret,
}

/// A secret that can be used with `PublicKeyEncryption`.
pub trait Secret {
    /// Establish a shared secret using the
    /// [Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellan)
    /// protocol.
    fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret;
}

impl<'a> Secret for &'a StaticSecret {
    fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        self.diffie_hellman(their_public)
    }
}

impl Secret for EphemeralSecret {
    fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        EphemeralSecret::diffie_hellman(self, their_public)
    }
}

impl PublicKeyEncryption {
    /// Returns a new shared encryption context between `secret` and
    /// `their_public`.
    pub fn new<S: Secret>(secret: S, their_public: &PublicKey) -> Self {
        Self {
            shared_secret: secret.diffie_hellman(their_public),
        }
    }

    fn encrypt_in_place(
        &self,
        nonce: &XNonce,
        buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<Tag, chacha20poly1305::aead::Error> {
        chacha20poly1305::XChaCha20Poly1305::new(GenericArray::from_slice(
            self.shared_secret.as_bytes(),
        ))
        .encrypt_in_place_detached(nonce, associated_data, buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &XNonce,
        buffer: &mut [u8],
        associated_data: &[u8],
        tag: &Tag,
    ) -> Result<(), chacha20poly1305::aead::Error> {
        chacha20poly1305::XChaCha20Poly1305::new(GenericArray::from_slice(
            self.shared_secret.as_bytes(),
        ))
        .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
    }

    /// Performs an `AEAD` encryption session with the shared secret.
    pub fn encrypt(
        &self,
        message: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        // Allocate 16 extra bytes for the Poly1305
        let mut encrypted = Vec::with_capacity(message.len() + POLY1305_LEN);
        encrypted.extend_from_slice(message);
        let tag = self.encrypt_in_place(
            XNonce::from_slice(nonce),
            &mut encrypted[..message.len()],
            associated_data,
        )?;
        // Copy the Poly1305 to the end of the buffer.
        encrypted.extend_from_slice(&tag);
        Ok(encrypted)
    }

    /// Performs an `AEAD` decryption session with the shared secret.
    pub fn decrypt(
        &self,
        message: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let mut buffer = message[..message.len() - POLY1305_LEN].to_vec();
        let tag = Tag::from_slice(&message[message.len() - POLY1305_LEN..]);

        self.decrypt_in_place(XNonce::from_slice(nonce), &mut buffer, associated_data, tag)?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::ephemeral::{PublicKeyExt, StaticSecretExt};

    #[test]
    fn public_key_encryption_tests() {
        let local_private_key = StaticSecret::new(thread_rng());
        let local_public_key = PublicKey::from(&local_private_key);

        let remote_private_key = StaticSecret::new(thread_rng());
        let remote_public_key = PublicKey::from(&remote_private_key);

        let nonce: [u8; 24] = thread_rng().gen();

        let local_encryption = PublicKeyEncryption::new(&local_private_key, &remote_public_key);
        let local_encrypted = local_encryption.encrypt(b"hello", b"", &nonce).unwrap();
        let local_decrypted = local_encryption
            .decrypt(&local_encrypted, b"", &nonce)
            .unwrap();
        assert_eq!(local_decrypted, b"hello");

        let remote_encryption = PublicKeyEncryption::new(&remote_private_key, &local_public_key);
        let remote_encrypted = remote_encryption.encrypt(b"hello", b"", &nonce).unwrap();
        let remote_decrypted = remote_encryption
            .decrypt(&remote_encrypted, b"", &nonce)
            .unwrap();
        assert_eq!(remote_decrypted, b"hello");

        assert_eq!(local_encrypted, remote_encrypted);
    }

    #[test]
    fn ecies_like_tests() {
        let private_key = StaticSecret::new(thread_rng());
        let public_key = PublicKey::from(&private_key);

        let nonce: [u8; 24] = thread_rng().gen();
        let nonce = XNonce::from_slice(&nonce);

        let encrypted = public_key.encrypt(b"hello", b"", nonce).unwrap();
        let decrypted = private_key.decrypt(&encrypted, b"", nonce).unwrap();

        assert_eq!(decrypted, b"hello");
    }
}
