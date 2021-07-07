# x25519-xchacha20poly1305

Authenticated Encryption using XChaCha20Poly1305 with an X25519 key exchange.

![x25519-xchacha20poly1305 is considered experimental and unsupported](https://img.shields.io/badge/status-experimental-blueviolet)
[![crate version](https://img.shields.io/crates/v/x25519_xchacha20poly1305.svg)](https://crates.io/crates/x25519_xchacha20poly1305)
[![Live Build Status](https://img.shields.io/github/workflow/status/khonsulabs/x25519-xchacha20poly1305/Tests/main)](https://github.com/khonsulabs/x25519-xchacha20poly1305/actions?query=workflow:Tests)
[![HTML Coverage Report for `main` branch](https://khonsulabs.github.io/x25519-xchacha20poly1305/coverage/badge.svg)](https://khonsulabs.github.io/x25519-xchacha20poly1305/coverage/)
[![Documentation for `main` branch](https://img.shields.io/badge/docs-main-informational)](https://khonsulabs.github.io/x25519-xchacha20poly1305/main/x25519_xchacha20poly1305/)

## WARNING / DISCLAIMER

This crate is written by someone who is *not* a cryptographer. And, while the dependencies of this crate are excellent crates, most of the code that this crate is built upon has not been audited. Use at your own risk.

## About x25519-xchacha20poly1305

This crate provides convenience wrappers around [`x25519-dalek`](https://github.com/dalek-cryptography/x25519-dalek) and [`chacha20poly1305`](https://github.com/RustCrypto/AEADs) to provide payload encryption using [XChaCha20](https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20), message authentication using [Poly1305](https://en.wikipedia.org/wiki/Poly1305), and key agreement using [X25519](https://en.wikipedia.org/wiki/Curve25519).

There are two goals served by this crate:

* Public Key Encryption: The ability for two parties with their own private keys to encrypt and decrypt payloads that each other can read using only the other party's public key and their own private key.

* [ECIES](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption)-like Encryption: The ability to encrypt a payload using the public key of the recipient such that only the recipients private key can decrypt the payload. **NOTE**: This is not ECIES, because ECIES by the current standard doesn't support Poly1305 as a MAC type. This library's authors made no attempt to verify that the MAC calculation matches the standard expected by ECIES's spec. By using the same MAC calculation type used by the [`AEAD`](https://github.com/RustCrypto/AEADs) implementation of XChaCha20Poly1305, this library has less overall code to review. However, if the ECIES standard requires the MAC to be calculated differently than how the AEAD implementation does it, this crate would need to be updated to comply with the spec.

  If someone more knowledgable wants to submit pull requests to move this towards an actual standard implementation or provide any clarifying details via Issues, all help is greatly appreciated.

### Public Key Encryption

```rust
use x25519_xchacha20poly1305::{PublicKeyEncryption, x25519::{PublicKey, StaticSecret}};
use rand::{thread_rng, Rng};

let bob_private_key = StaticSecret::new(thread_rng());
let bob_public_key = PublicKey::from(&bob_private_key);

let mary_private_key = StaticSecret::new(thread_rng());
let mary_public_key = PublicKey::from(&mary_private_key);

// Mary and Bob can exchange public keys, which will allow them to encrypt and decrypt
// messages for each other.
let bob = PublicKeyEncryption::new(&bob_private_key, &mary_public_key);
let mary = PublicKeyEncryption::new(&mary_private_key, &bob_public_key);

// Bob sends a message to Mary with a random nonce.
let nonce: [u8; 24] = thread_rng().gen();
let bobs_message = bob.encrypt(b"hello", b"", &nonce).unwrap();

// Bob can decrypt this message.
assert_eq!(
    bob.decrypt(&bobs_message, b"", &nonce).unwrap(),
    b"hello"
);

// And, so can Mary.
assert_eq!(
    mary.decrypt(&bobs_message, b"", &nonce).unwrap(),
    b"hello"
);
```

### `ECIES`-like Encryption

Provided as extension traits:

```rust
use crate::{
    ephemeral::{PublicKeyExt as _, StaticSecretExt as _},
    x25519::{PublicKey, StaticSecret},
};
use rand::{thread_rng, Rng};

let private_key = StaticSecret::new(thread_rng());
let public_key = PublicKey::from(&private_key);

let nonce: [u8; 24] = thread_rng().gen();
let encrypted = public_key.encrypt(b"hello", b"", &nonce).unwrap();
let decrypted = private_key.decrypt(&encrypted, b"", &nonce).unwrap();
assert_eq!(decrypted, b"hello");
```

## What does this crate actually do?

![office space "what would you say you do here"](https://media.giphy.com/media/b7MdMkkFCyCWI/giphy.gif)

This crate has barely any code. The heavy lifting is done by
[`x25519-dalek`](https://github.com/dalek-cryptography/x25519-dalek) and
[`chacha20poly1305`](https://github.com/RustCrypto/AEADs). This crate only
simplifies the process, and adds `ECIES`-standard cryptogram output when using
that method.

## Why these algorithms?

* XChaCha20: ChaCha20 is a wonderful algorithm, and XChaCha20 extends the nonce
  from 12 bytes to 24 bytes. This wider space allows for randomly generated
  nonces.
* X25519: This
  [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
  key agreement algorithm is one of the gold-standards of today's algorithms.
* Poly1305: This is the MAC algorithm is a common pairing with XChaCha20 and is
  part of the TLS standard.
