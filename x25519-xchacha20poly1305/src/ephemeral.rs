//! Encrypts messages for a [`StaticSecret`] using only the [`PublicKey`].
//!
//! This is accomplished by generating an [`EphemeralSecret`]. The ephemeral
//! secret key + the known public key are used to encrypt the payload. The
//! ephemeral public key is embedded in the resulting payload. The ephemeral
//! secret key is forgotten after encrypting the payload.
//!
//! The order of the produced payload is:
//!
//! * Ephemeral X25519 Public Key: 32 bytes
//! * Poly1305 MAC: 16 bytes
//! * Remainder: ciphertext
//!
//! This is an example showing how to encrypt a message using a public key and
//! decrypt it using the private key:
//!
//! ```rust
//! # fn main() {
//! use x25519_xchacha20poly1305::{
//!     ephemeral::{PublicKeyExt as _, StaticSecretExt as _},
//!     x25519::{PublicKey, StaticSecret},
//! };
//! use rand::{thread_rng, Rng};
//!
//! let private_key = StaticSecret::new(thread_rng());
//! let public_key = PublicKey::from(&private_key);
//!
//! let nonce: [u8; 24] = thread_rng().gen();
//! let encrypted = public_key.encrypt(b"hello", b"associated data", &nonce).unwrap();
//! let decrypted = private_key.decrypt(&encrypted, b"associated data", &nonce).unwrap();
//! assert_eq!(decrypted, b"hello");
//! # }

use chacha20poly1305::{Tag, XNonce};
use rand::thread_rng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{PublicKeyEncryption, POLY1305_LEN};

const X25519_KEY_LEN: usize = x25519_dalek::X25519_BASEPOINT_BYTES.len();
const ECIES_HEADER_LEN: usize = POLY1305_LEN + X25519_KEY_LEN;

/// Extension trait for [`PublicKey`]. Encrypts plaintext using
/// `XChaCha20Poly1305` that only the owner of the private key of `self` can
/// decrypt. For more information on how this is accomplished, see the
/// [`ephemeral` module](crate::ephemeral).
pub trait PublicKeyExt {
    /// Encrypts plaintext using `XChaCha20Poly1305` that only the owner of the
    /// private key of `self` can decrypt. For more information on how this is
    /// accomplished, see the [`ephemeral` module](crate::ephemeral).
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error>;
}

/// Extension trait for [`StaticSecret`]. Decrypts paylods produced by
/// [`PublicKeyExt::encrypt()`]. For more information on how this is
/// accomplished, see the [`ephemeral` module](crate::ephemeral).
pub trait StaticSecretExt {
    /// Decrypts a payload that was previously encrypted with [`PublicKeyExt`].
    /// For more information on how this is accomplished, see the [`ephemeral`
    /// module](crate::ephemeral).
    fn decrypt(
        &self,
        payload: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error>;
}

impl PublicKeyExt for PublicKey {
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let ephemeral_secret = EphemeralSecret::new(thread_rng());
        let ephemeral_public_key = PublicKey::from(&ephemeral_secret);

        let mut buffer = Vec::with_capacity(plaintext.len() + ECIES_HEADER_LEN);

        // Copy the ephemeral public key to the output buffer
        buffer.extend_from_slice(ephemeral_public_key.as_bytes());

        // Allocate space for the Poly1305 tag. This doesn't actually realloacte
        // the vector, since the capacity is large enough.
        buffer.resize_with(ECIES_HEADER_LEN, || 0);

        // Copy the plaintext into the buffer.
        buffer.extend_from_slice(plaintext);

        // Encrypt the plaintext in-place
        let tag = PublicKeyEncryption::new(ephemeral_secret, self).encrypt_in_place(
            XNonce::from_slice(nonce),
            &mut buffer[ECIES_HEADER_LEN..],
            associated_data,
        )?;

        // Copy the Poly1305 tag into the location we allocated earlier.
        buffer[X25519_KEY_LEN..ECIES_HEADER_LEN].copy_from_slice(&tag);

        Ok(buffer)
    }
}

impl PublicKeyExt for StaticSecret {
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        PublicKey::from(self).encrypt(plaintext, associated_data, nonce)
    }
}

impl StaticSecretExt for StaticSecret {
    fn decrypt(
        &self,
        payload: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let mut decrypted = Vec::with_capacity(payload.len() - ECIES_HEADER_LEN);
        decrypted.extend_from_slice(&payload[ECIES_HEADER_LEN..]);

        let mut ephemeral_public_key = [0_u8; X25519_KEY_LEN];
        ephemeral_public_key.copy_from_slice(&payload[0..X25519_KEY_LEN]);
        let ephemeral_public_key = PublicKey::from(ephemeral_public_key);

        let tag = Tag::from_slice(&payload[X25519_KEY_LEN..ECIES_HEADER_LEN]);
        PublicKeyEncryption::new(self, &ephemeral_public_key).decrypt_in_place(
            XNonce::from_slice(nonce),
            &mut decrypted,
            associated_data,
            tag,
        )?;

        Ok(decrypted)
    }
}
