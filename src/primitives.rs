//! Abstractions for the choices of underlying cryptographic primitives.
//!
//! The main export here is [`Primitives`], which represents all needed types and operations that
//! EROR needs.
//!
//! A basic implementation with classical primitives is available as [`EcPrimitives`].
use std::fmt::Debug;

use aez::Aez;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, EdwardsPoint, Scalar};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512};

/// Role that a key will take.
///
/// This is used to derive multiple keys from a single shared secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// The key is used to symetrically encrypt something (the payload or the header)
    SymEnc,
    /// The key is used to calculate the MAC.
    Mac,
    /// The key is used for the authenticated encryption of the backwards payload.
    AuthEnc,
    /// The key is used as the end-to-end key.
    ///
    /// This is the key that is shared between the sender and the recipient, and from which further
    /// keys can be derived.
    End2End,
    /// The key is used to seed the pseudorandom number generator.
    Prng,
    /// The key is used to encrypt the forward payload.
    ///
    /// The number is the number of the hop on the path.
    Forward(u32),
    /// The key is used to encrypt the backward payload.
    ///
    /// The number is the number of the hop on the path.
    Backward(u32),
    /// They key is used to hash the backward payload.
    Uhf,
}

impl KeyRole {
    /// Converts the enum representation of the [`KeyRole`] to something that can put into a
    /// cryptographically secure hash function.
    ///
    /// Note that all discriminants are non-overlapping to prevent any collisions.
    pub fn discriminant(&self) -> [u8; 5] {
        match self {
            KeyRole::SymEnc => [1, 0, 0, 0, 0],
            KeyRole::Mac => [2, 0, 0, 0, 0],
            KeyRole::AuthEnc => [3, 0, 0, 0, 0],
            KeyRole::End2End => [4, 0, 0, 0, 0],
            KeyRole::Prng => [5, 0, 0, 0, 0],
            KeyRole::Forward(i) => {
                let mut result = [6, 0, 0, 0, 0];
                result[1..5].copy_from_slice(&i.to_le_bytes());
                result
            }
            KeyRole::Backward(i) => {
                let mut result = [7, 0, 0, 0, 0];
                result[1..5].copy_from_slice(&i.to_le_bytes());
                result
            }
            KeyRole::Uhf => [8, 0, 0, 0, 0],
        }
    }
}

/// A combination of all traits that the types of the keys must satisfy in order to be usable.
pub trait RequiredTraits = Serialize + DeserializeOwned + Clone + Debug + Default;

/// Generalization over the chosen cryptographic primitives and their parameters.
///
/// For the sake of consistency, all methods (except for [`Primitives::prng`]) take as an input a
/// randomness source, regardless of whether they use it or not. This is so that any primitives can
/// be used, not just those who happen to be deterministic.
pub trait Primitives: Debug {
    /// Type of the tag that the MAC outputs.
    type Tag: RequiredTraits + PartialEq + Eq;
    /// Type of a public key.
    type PublicKey: RequiredTraits;
    /// Type of a private key.
    type PrivateKey: RequiredTraits;
    /// Type of a symmetric encryption key (also used for authenticated encryption and the MAC).
    type SymmetricKey: RequiredTraits;

    const SYMMETRIC_KEY_LENGTH: usize;

    /// Generates a random key using the cryptographically secure randomness source.
    fn random_key<R: Rng + CryptoRng>(&self, rng: R) -> Self::SymmetricKey;

    /// Generates a random tag using the cryptographically secure randomness source.
    fn random_tag<R: Rng + CryptoRng>(&self, rng: R) -> Self::Tag;

    /// Compute a MAC for the given data.
    fn tag<R: Rng + CryptoRng>(&self, rng: R, key: &Self::SymmetricKey, data: &[u8]) -> Self::Tag;

    /// XOR two tags into one (used for the authenticated encryption).
    fn xor_tag(&self, tag_a: &Self::Tag, tag_b: &Self::Tag) -> Self::Tag;

    /// Encrypt the given data using a PKE.
    ///
    /// The output might be longer than the input, therefore this method does not operate in-place,
    /// but rather allocates a new buffer.
    fn asymmetric_encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &Self::PublicKey,
        data: &[u8],
    ) -> Vec<u8>;

    /// Decrypt the given data using a PKE.
    ///
    /// The output might be shorter than the input, therefore this method does not operate in-place,
    /// but rather allocates a new buffer.
    fn asymmetric_decrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &Self::PrivateKey,
        data: &[u8],
    ) -> Vec<u8>;

    /// Derive a new key for the given role from the source key.
    fn derive_key<R: Rng + CryptoRng>(
        &self,
        rng: R,
        role: KeyRole,
        key: &Self::SymmetricKey,
    ) -> Self::SymmetricKey;

    /// Encrypt the given data in-place.
    ///
    /// Choosing a different nonce should produce different output, even if the key is the same.
    fn symmetric_encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &Self::SymmetricKey,
        nonce: u32,
        data: &mut [u8],
    );

    /// Decrypt the given data in-place.
    ///
    /// This is the inverse to [`Primitives::symmetric_encrypt`].
    fn symmetric_decrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        key: &Self::SymmetricKey,
        nonce: u32,
        data: &mut [u8],
    );

    /// Fill the given buffer with pseudorandom output, generated from the given seed.
    ///
    /// Note that this should be cryptographically secure.
    fn prng(&self, seed: &Self::SymmetricKey, output: &mut [u8]);
}

/// A primitive collection that provides security against non-quantum attackers.
///
/// The chosen primitives are:
/// * ElGamal on Curve25519 for asymmetric encryption (not quantum secure!). We use an IND-CCA
/// secure implementation ([Compact CCA-Secure Encryption for Messages of Arbitrary Length](https://www.iacr.org/archive/pkc2009/54430381/54430381.pdf))
/// * AES 128 bit for symmetric encryption
/// * AES-GCM for the authenticated encryption
/// * SHA3 as the basis for key derivation and MACs
/// * HMAC (using SHA3) for the actual MACs
/// * ChaCha20 for the PRNG
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcPrimitives;

impl EcPrimitives {
    /// Generate a fresh key pair consisting of a private key and the corresponding public key.
    pub fn generate_keypair<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
    ) -> (
        <Self as Primitives>::PrivateKey,
        <Self as Primitives>::PublicKey,
    ) {
        let private_key = Scalar::random(&mut rng);
        (private_key, ED25519_BASEPOINT_TABLE * &private_key)
    }
}

impl Primitives for EcPrimitives {
    // Enough to hold a HMAC with SHA3
    type Tag = [u8; 16];
    type PublicKey = EdwardsPoint;
    type PrivateKey = Scalar;
    type SymmetricKey = [u8; 16];

    const SYMMETRIC_KEY_LENGTH: usize = 16;

    fn random_key<R: Rng + CryptoRng>(&self, mut rng: R) -> Self::SymmetricKey {
        rng.gen()
    }

    fn random_tag<R: Rng + CryptoRng>(&self, mut rng: R) -> Self::Tag {
        rng.gen()
    }

    fn tag<R: Rng + CryptoRng>(&self, _: R, key: &Self::SymmetricKey, data: &[u8]) -> Self::Tag {
        let mut mac = <Hmac<Sha3_256> as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes()[..16].try_into().unwrap()
    }

    fn xor_tag(&self, tag_a: &Self::Tag, tag_b: &Self::Tag) -> Self::Tag {
        tag_a
            .iter()
            .zip(tag_b.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn asymmetric_encrypt<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        key: &Self::PublicKey,
        data: &[u8],
    ) -> Vec<u8> {
        let r = Scalar::random(&mut rng);
        let symmetric_key = hash_edwards(ED25519_BASEPOINT_TABLE * &r);
        let mut data = data.to_vec();
        self.symmetric_encrypt(&mut rng, &symmetric_key, 0, &mut data);
        let u = (ED25519_BASEPOINT_TABLE * &hash_to_scalar(&data) + key) * r;
        bincode::serialize(&(u, data)).unwrap()
    }

    fn asymmetric_decrypt<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        key: &Self::PrivateKey,
        data: &[u8],
    ) -> Vec<u8> {
        // IF we get bytes that do not represent a valid EdwardsPoint, we do not want to crash.
        // Instead, we assume that the ciphertext has been mauled and return garbage.
        if let Ok((u, mut payload)) = bincode::deserialize::<(EdwardsPoint, Vec<u8>)>(data) {
            let point = u * (hash_to_scalar(&payload) + key).invert();
            let symmetric_key = hash_edwards(point);
            self.symmetric_decrypt(&mut rng, &symmetric_key, 0, &mut payload);
            payload
        } else {
            let point_bytes = &data[..32];
            let mut data_bytes = Vec::from(&data[40..]);
            let hash: [u8; 32] = Sha3_256::digest(point_bytes).into();
            self.symmetric_decrypt(&mut rng, hash[..16].try_into().unwrap(), 0, &mut data_bytes);
            data_bytes
        }
    }

    fn derive_key<R: Rng + CryptoRng>(
        &self,
        _: R,
        role: KeyRole,
        key: &Self::SymmetricKey,
    ) -> Self::SymmetricKey {
        let mut result = [0u8; 16];
        let mut hasher = Sha3_256::new();
        hasher.update(role.discriminant());
        hasher.update(key);
        result.copy_from_slice(&hasher.finalize()[..16]);
        result
    }

    fn symmetric_encrypt<R: Rng + CryptoRng>(
        &self,
        _: R,
        key: &Self::SymmetricKey,
        nonce: u32,
        data: &mut [u8],
    ) {
        // The AEZ implementation actually segfaults if we give it a slice with length 0, so we
        // catch that early (which also saves us a bit of work)
        if data.is_empty() {
            return;
        }

        let mut iv = [0u8; 16];
        let mut hasher = Sha3_256::new();
        hasher.update(nonce.to_le_bytes());
        iv.copy_from_slice(&hasher.finalize()[..16]);
        let cipher = Aez::new(key);
        let mut ciphertext = vec![0u8; data.len()];
        cipher.encrypt(&iv, None, data, &mut ciphertext);
        data.copy_from_slice(&ciphertext);
    }

    fn symmetric_decrypt<R: Rng + CryptoRng>(
        &self,
        _: R,
        key: &Self::SymmetricKey,
        nonce: u32,
        data: &mut [u8],
    ) {
        // The AEZ implementation actually segfaults if we give it a slice with length 0, so we
        // catch that early (which also saves us a bit of work)
        if data.is_empty() {
            return;
        }
        let mut iv = [0u8; 16];
        let mut hasher = Sha3_256::new();
        hasher.update(nonce.to_le_bytes());
        iv.copy_from_slice(&hasher.finalize()[..16]);
        let cipher = Aez::new(key);
        let mut plaintext = vec![0u8; data.len()];
        cipher
            .decrypt(&iv, None, data, &mut plaintext)
            .expect("we don't use AD so we should always get a good decryption");
        data.copy_from_slice(&plaintext);
    }

    fn prng(&self, seed: &Self::SymmetricKey, output: &mut [u8]) {
        let mut new_seed = [0u8; 32];
        new_seed[0..16].copy_from_slice(seed);
        let mut rng = ChaCha20Rng::from_seed(new_seed);
        rng.fill_bytes(output);
    }
}

fn hash_edwards(point: EdwardsPoint) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut hasher = Sha3_256::new();
    hasher.update(point.compress().as_bytes());
    result.copy_from_slice(&hasher.finalize()[..16]);
    result
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    Scalar::hash_from_bytes::<Sha3_512>(data)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_asymmetric_encrypt_decrypt() {
        let mut rng = rand::thread_rng();
        let primitives = EcPrimitives;

        let message = b"Hello, world!".to_vec();
        let (privkey, pubkey) = primitives.generate_keypair(&mut rng);

        let encrypted = primitives.asymmetric_encrypt(&mut rng, &pubkey, &message);
        let decrypted = primitives.asymmetric_decrypt(&mut rng, &privkey, &encrypted);

        assert_eq!(decrypted, b"Hello, world!");
    }

    #[test]
    fn test_asymmetric_ciphertext_mauled() {
        let mut rng = rand::thread_rng();
        let primitives = EcPrimitives;

        let message = b"Hello, world!".to_vec();
        let (privkey, pubkey) = primitives.generate_keypair(&mut rng);

        let mut encrypted = primitives.asymmetric_encrypt(&mut rng, &pubkey, &message);
        encrypted[0] ^= 0xFF;
        let decrypted = primitives.asymmetric_decrypt(&mut rng, &privkey, &encrypted);

        assert_ne!(decrypted, b"Hello, world!");
    }

    #[test]
    fn test_mac() {
        let mut rng = rand::thread_rng();
        let primitives = EcPrimitives;

        let message = b"Hello, world!";
        let key: <EcPrimitives as Primitives>::SymmetricKey = rng.gen();

        let tag1 = primitives.tag(&mut rng, &key, message);
        let tag2 = primitives.tag(&mut rng, &key, message);

        assert_eq!(tag1, tag2);

        let tag3 = primitives.tag(&mut rng, &key, b"Hello, w0rld!");

        assert_ne!(tag1, tag3);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = rand::thread_rng();
        let primitives = EcPrimitives;

        let mut message = b"Hello, world!".to_vec();
        let key: <EcPrimitives as Primitives>::SymmetricKey = rng.gen();

        primitives.symmetric_encrypt(&mut rng, &key, 42, &mut message);
        primitives.symmetric_decrypt(&mut rng, &key, 42, &mut message);

        assert_eq!(message, b"Hello, world!");

        primitives.symmetric_encrypt(&mut rng, &key, 42, &mut message);
        primitives.symmetric_decrypt(&mut rng, &key, 43, &mut message);

        assert_ne!(message, b"Hello, world!");
    }
}
