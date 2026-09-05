#![feature(trait_alias)]
//! This crate contains an implementation of the *EROR: Efficient Repliable Onion Routing with
//! Strong Provably Privacy* scheme.
//!
//! **WARNING:** This code is a prototype for benchmarks in the paper. It is *not* audited or meant
//! for production use. Tread carefully!
use std::iter;

use num_derive::FromPrimitive;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

pub mod error;
pub mod pki;
pub mod primitives;

use error::Error;
use pki::Pki;
use primitives::{KeyRole, Primitives};

fn pack<T: Serialize>(value: T) -> Vec<u8> {
    bincode::serialize(&value).unwrap()
}

/// Address of mix nodes and recipients.
///
/// 32 bytes is what Nym uses to address nodes, so we stay consistent. We can use the 32 bytes e.g.
/// to store a 16 byte IPv6 address and a 2 byte port easily, or to store a domain name, or other
/// types of addresses.
pub type Address = [u8; 32];
const ADDRESS_LENGTH: usize = 32;

/// Nonce that is used when encrypting the forward payload.
pub const NONCE_BWD: u32 = 0xFFAAFFAA;
/// Nonce that is used when encrypting the backward payload.
pub const NONCE_FWD: u32 = 0xAAFFAAFF;
/// Nonce that is used when encrypting the header data.
pub const NONCE_HDR: u32 = 0xAFAFAFAF;
/// Nonce that is used when using symmetric encryption for authenticated encryption.
pub const NONCE_AE: u32 = 0xFAFAFAFA;

/// Meta-flag for the role that the current mix node should have in the path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, FromPrimitive)]
#[repr(u8)]
pub enum Role {
    /// The hop is the original sender of the onion.
    Sender,
    /// The hop is the receiver of the onion.
    Receiver,
    /// The hop is a mix node along the path.
    Hop,
}

/// Meta-Information that is contained in a header block
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Meta {
    role: Role,
    next: Address,
}

/// A single block of the header.
///
/// This contains the data available per hop, i.e. the tag, key and address of the next hop.
#[derive(Debug, Serialize, Deserialize)]
pub struct HeaderBlock<P: Primitives> {
    /// MAC tag to verify the integrity of the remaining onion.
    pub tag: P::Tag,
    pub data: Vec<u8>,
}

impl<P: Primitives> HeaderBlock<P> {
    /// Pack (serialize) this header block into a stream of bytes.
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        Ok(bincode::serialize(&self)?)
    }

    /// Unpack (deserialize) a header block from the given bytes.
    pub fn unpack(data: &[u8]) -> Result<Self, Error> {
        Ok(bincode::deserialize(data)?)
    }
}

impl<P: Primitives> Clone for HeaderBlock<P> {
    fn clone(&self) -> Self {
        Self { tag: self.tag.clone(), data: self.data.clone() }
    }
}

/// A single header element.
///
/// This is a small wrapper around [`HeaderBlock`] which  allows us to treat a header block either
/// opaquely as a sequence of bytes (e.g. if it is still encrypted), or transparently as a parsed
/// [`HeaderBlock`] (e.g. if the header block for the current mix node has been decrypted).
#[derive(Debug)]
pub enum Header<P: Primitives> {
    /// The header is opaque and only accessible as a sequence of bytes.
    Raw(Vec<u8>),
    /// The header is transparent and accessible as a struct.
    Parsed(Box<HeaderBlock<P>>),
}

impl<P: Primitives> Header<P> {
    pub fn structured(tag: P::Tag, data: Vec<u8>) -> Self {
        Header::Parsed(Box::new(HeaderBlock { tag, data }))
    }

    /// Converts the header block into its byte form.
    pub fn into_bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            Header::Raw(v) => Ok(v.clone()),
            Header::Parsed(block) => block.pack(),
        }
    }

    /// Converts the header block into its parsed form.
    pub fn into_parsed(&self) -> Result<HeaderBlock<P>, Error> {
        match self {
            Header::Raw(v) => HeaderBlock::unpack(v),
            // Cheap man's clone() due to trait bounds (can be fixed)
            Header::Parsed(p) => HeaderBlock::unpack(&p.pack()?),
        }
    }

    /// Ensures that the header block is in its raw form, and returns mutable access to the
    /// underlying byte sequence.
    pub fn force_pack(&mut self) -> Result<&mut Vec<u8>, Error> {
        match self {
            Header::Raw(v) => Ok(v),
            Header::Parsed(block) => {
                *self = Header::Raw(block.pack()?);
                self.force_pack()
            }
        }
    }
}

impl<P: Primitives> Serialize for Header<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        self.into_bytes().unwrap().serialize(serializer)
    }
}

impl<'de, P: Primitives> Deserialize<'de> for Header<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Ok(Header::Raw(bytes))
    }
}

impl<P: Primitives> Clone for Header<P> {
    fn clone(&self) -> Self {
        match self {
            Self::Raw(arg0) => Self::Raw(arg0.clone()),
            Self::Parsed(arg0) => Self::Parsed(arg0.clone()),
        }
    }
}

impl<P: Primitives> PartialEq for Header<P> {
    fn eq(&self, other: &Self) -> bool {
        self.into_bytes().ok() == other.into_bytes().ok()
    }
}

impl<P: Primitives> Eq for Header<P> {}

/// Struct representing an assembled onion.
#[derive(Debug)]
pub struct Onion<P: Primitives> {
    /// The complete header for the onion (one block per hop).
    pub header: Vec<Header<P>>,
    /// The forward payload.
    pub forward: Vec<u8>,
    /// The backward payload.
    pub backward: (Vec<u8>, P::Tag),
}

impl<P: Primitives> Clone for Onion<P> {
    fn clone(&self) -> Self {
        Self { header: self.header.clone(), forward: self.forward.clone(), backward: self.backward.clone() }
    }
}

impl<P: Primitives> Serialize for Onion<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let packed_headers = self
            .header
            .iter()
            .map(|h| h.into_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        (packed_headers, &self.forward, &self.backward).serialize(serializer)
    }
}

impl<'de, P: Primitives> Deserialize<'de> for Onion<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (packed_headers, forward, backward) =
            <(Vec<Vec<u8>>, Vec<u8>, (Vec<u8>, P::Tag))>::deserialize(deserializer)?;
        let header = packed_headers.into_iter().map(Header::Raw).collect();
        Ok(Onion {
            header,
            forward,
            backward,
        })
    }
}

impl<P: Primitives> PartialEq for Onion<P> {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.forward == other.forward && self.backward == other.backward
    }
}

impl<P: Primitives> Eq for Onion<P> {}

impl<P: Primitives> Onion<P> {
    /// Pack (serialize) all header blocks into a single stream of bytes.
    pub fn packed_header(&self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        for part in &self.header {
            result.extend(part.into_bytes()?);
        }
        Ok(result)
    }
}

/// An element of what is called `dbinfo` in the pseudocode.
///
/// This is saved by the sender to later check if the recipient has received an untagged onion.
#[derive(Debug, Clone)]
pub struct ExpectedResponse<P: Primitives> {
    /// The key (usually the onion's header bytes) that are used to identify the reply in `dbinfo`.
    ///
    /// This is the header of the backwards onion, not the forward onion (which is saved in
    /// `onion`).
    pub identifier: Vec<u8>,
    /// The full forward onion, just makes it easier to debug.
    pub onion: Onion<P>,
    /// The tag of the forward onion, as it is expected to be received.
    pub tag: P::Tag,
}

/// Main struct to generate new [`Onion`]s.
///
/// The [`OnionFormat`] encapsulates all parametrizations. That is, it is specific to a selected
/// set of primitives in the `P` type parameter, as well as the maximum path length.
///
/// The main functions to interact with the format are [`OnionFormat::form_onion`] to create new
/// onions, and [`OnionFormat::proc_onion`] to process onions. The other methods are lower-level.
#[derive(Debug, Clone)]
pub struct OnionFormat<P: Primitives> {
    /// The maximum allowed path length.
    pub max_path_length: u32,
    /// The public key infrastructure that the format uses to retrieve public keys for hops.
    pub pki: Pki<P>,
    /// The chosen primitives.
    pub primitives: P,
}

/// Payload for the new onion.
///
/// Depending on whether this is [`Payload::Forward`] or [`Payload::Backward`], the
/// [`OnionFormat::onionize`] method will prepare the payload differently:
///
/// If [`Payload::Forward`] is chosen, the payload is treated such that it arrives at the recipient
/// in the specified form. In particular, the payload is onion encrypted, such that each hop along
/// the path removes a layer and the payload appears in plain at the last hop.
///
/// If [`Payload::Backward`] is chosen, the payload is treated such that the sender puts in the
/// given bytes. In particular, the payload is *not* onion encrypted, as we assume that the sender
/// copies it verbatim into the onion.
#[derive(Debug, Clone, Copy)]
pub enum Payload<'a> {
    /// The payload is for a forward onion.
    Forward(&'a [u8]),
    /// The payload is for a backward onion.
    Backward(&'a [u8]),
}

impl<P: Primitives> OnionFormat<P> {
    /// Create a new onion format with the given primitives, public key infrastructure and maximum
    /// path length.
    pub fn new(primitives: P, pki: Pki<P>, max_path_length: u32) -> Self {
        Self {
            // We need to account for the dummy recipient
            max_path_length,
            pki,
            primitives,
        }
    }

    fn single_header_length(&self) -> usize {
        16 + // Tag
            P::SYMMETRIC_KEY_LENGTH + // Symmetric Key
            ADDRESS_LENGTH +
            4 + // Role
            32 + // Montgomery point from the KEM
            8 + // Vector length inside the encryption
            8 // Vector length in Meta
    }

    fn total_header_length(&self) -> usize {
        8 + (self.max_path_length as usize) * (8 + self.single_header_length())
    }

    fn zero_header(&self) -> Header<P> {
        Header::Raw(vec![0; self.single_header_length()])
    }

    fn random_header<R: Rng + CryptoRng>(&self, mut rng: R) -> Header<P> {
        Header::Raw((0..self.single_header_length()).map(|_| rng.gen()).collect())
    }

    pub fn ae_enc<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        key: &P::SymmetricKey,
        ad: &P::Tag,
        payload: &[u8],
    ) -> (Vec<u8>, P::Tag) {
        let key_symmetric = self.primitives.derive_key(&mut rng, KeyRole::SymEnc, key);
        let key_mac = self.primitives.derive_key(&mut rng, KeyRole::Mac, key);
        let mut ciphertext = Vec::from(payload);
        self.primitives.symmetric_encrypt(&mut rng, &key_symmetric, NONCE_AE, &mut ciphertext);
        let mac = self.primitives.tag(&mut rng, &key_mac, &ciphertext);
        (ciphertext, self.primitives.xor_tag(&mac, &ad))
    }

    pub fn ae_dec<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        key: &P::SymmetricKey,
        ad: &P::Tag,
        mut bwd: (Vec<u8>, P::Tag),
    ) -> Option<Vec<u8>> {
        let key_symmetric = self.primitives.derive_key(&mut rng, KeyRole::SymEnc, key);
        let key_mac = self.primitives.derive_key(&mut rng, KeyRole::Mac, key);
        let tag = self.primitives.xor_tag(&self.primitives.tag(&mut rng, &key_mac, &bwd.0), ad);
        if tag != bwd.1 {
            return None;
        }
        self.primitives.symmetric_decrypt(&mut rng, &key_symmetric, NONCE_AE, &mut bwd.0);
        Some(bwd.0)
    }

    pub fn ae_unwrap<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        key: &P::SymmetricKey,
        bwd: (Vec<u8>, P::Tag),
    ) -> (Vec<u8>, P::Tag) {
        let key_symmetric = self.primitives.derive_key(&mut rng, KeyRole::SymEnc, key);
        let mut buffer = pack(&bwd.1);
        let tag_len = buffer.len();
        buffer.extend(bwd.0);
        self.primitives.symmetric_decrypt(&mut rng, &key_symmetric, NONCE_BWD, &mut buffer);
        (buffer[tag_len..].into(), bincode::deserialize(&buffer[..tag_len]).unwrap())
    }

    pub fn ae_wrap<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        key: &P::SymmetricKey,
        bwd: (Vec<u8>, P::Tag),
    ) -> (Vec<u8>, P::Tag) {
        let key_symmetric = self.primitives.derive_key(&mut rng, KeyRole::SymEnc, key);
        let mut buffer = pack(&bwd.1);
        let tag_len = buffer.len();
        buffer.extend(bwd.0);
        self.primitives.symmetric_encrypt(&mut rng, &key_symmetric, NONCE_BWD, &mut buffer);
        (buffer[tag_len..].into(), bincode::deserialize(&buffer[..tag_len]).unwrap())
    }

    pub fn wrap<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        key: &P::SymmetricKey,
        ciphertext: &[u8],
        headers: &[Header<P>],
        payload: &[u8],
    ) -> Result<(Vec<Header<P>>, Vec<u8>), Error> {
        let key_symmetric = self.primitives.derive_key(&mut rng, KeyRole::SymEnc, key);
        let key_mac = self.primitives.derive_key(&mut rng, KeyRole::Mac, key);
        let mut new_headers = headers.iter()
            .enumerate()
            .map(|(i, h)| {
                let mut packed = h.into_bytes()?;
                self.primitives.symmetric_encrypt(&mut rng, &key_symmetric, i as u32 + 2, &mut packed);
                Ok(Header::<P>::Raw(packed))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let data = ciphertext.to_vec();
        let mut payload = Vec::from(payload);
        self.primitives.symmetric_encrypt(&mut rng, &key_symmetric, NONCE_FWD, &mut payload);
        let tag = self.primitives.tag(&mut rng, &key_mac, &pack((&data, &new_headers[..], &payload)));
        let first_block = HeaderBlock {
            tag,
            data,
        };
        new_headers.insert(0, Header::Parsed(Box::new(first_block)));
        Ok((new_headers, payload))
    }

    /// Generates an onion for the given path.
    ///
    /// Note that this function does not ensure that the payload has a uniform size, this is left
    /// for the caller to do.
    ///
    /// Returns both the created onion for the first hop, as well as the onion as it will arrive at
    /// the last hop, as well as the expected tag for the final hop (for backwards integrity).
    pub fn onionize<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        keys: &[P::SymmetricKey],
        hops: &[Address],
        meta: Meta,
        payload: Payload,
        backward_payload_length: usize,
    ) -> Result<(Onion<P>, Onion<P>, P::Tag), Error> {
        assert_eq!(keys.len(), hops.len());
        if hops.len() > self.max_path_length as usize {
            return Err(Error::PathTooLong);
        }
        let n = keys.len();

        let keys_symmetric = keys
            .iter()
            .map(|k| self.primitives.derive_key(&mut rng, KeyRole::SymEnc, k))
            .collect::<Vec<_>>();
        let keys_mac = keys
            .iter()
            .map(|k| self.primitives.derive_key(&mut rng, KeyRole::Mac, k))
            .collect::<Vec<_>>();

        // Precompute all PKE ciphertexts of meta^i
        let mut meta_ciphers = Vec::new();
        for ((key, address), next_address) in keys.iter().zip(hops.iter()).zip(hops.iter().skip(1)) {
            let pubkey = self.pki.get(address).ok_or(Error::KeyNotFound)?;
            let block_data = pack((key, Meta { role: Role::Hop, next: *next_address }));
            let encrypted = self.primitives.asymmetric_encrypt(&mut rng, pubkey, &block_data);
            meta_ciphers.push(encrypted);
        }
        {
            let pubkey = self.pki.get(hops.last().unwrap()).ok_or(Error::KeyNotFound)?;
            let block_data = pack((keys.last().unwrap(), meta));
            let encrypted = self.primitives.asymmetric_encrypt(&mut rng, pubkey, &block_data);
            meta_ciphers.push(encrypted);
        }

        // Precompute all deterministic (garbage) values
        let mut header_blocks = vec![vec![Header::Raw(Vec::new()); self.max_path_length as usize]; self.max_path_length as usize];
        for i in 0..n - 1 {
            for j in self.max_path_length as usize - i - 1 .. self.max_path_length as usize - 1 {
                let mut data = header_blocks[i][j + 1].into_bytes()?;
                self.primitives.symmetric_decrypt(&mut rng, &keys_symmetric[i], j as u32 + 2, &mut data);
                header_blocks[i + 1][j] = Header::Raw(data);
            }
            let mut data = self.zero_header();
            self.primitives.symmetric_decrypt(&mut rng, &keys_symmetric[i], self.max_path_length + 1, data.force_pack()?);
            header_blocks[i + 1][self.max_path_length as usize - 1] = data;
        }


        // Fill remaining garbage terms arbirarily
        for j in 1..self.max_path_length as usize - n + 1 {
            header_blocks[n - 1][j] = self.random_header(&mut rng);
        }

        // Compute fwd^n and bwd^{n+1}
        let (fwd_n, bwd, bwd_n, expected_tag) = match payload {
            Payload::Forward(data) => {
                let mut data = Vec::from(data);
                self.primitives.symmetric_encrypt(&mut rng, &keys_symmetric[n - 1], NONCE_FWD, &mut data);

                // Generate garbage backward payload bwd^1
                let bwd_1 = ((0..backward_payload_length).map(|_| rng.gen()).collect(), self.primitives.random_tag(&mut rng));
                let mut bwd_n = bwd_1.clone();
                for key in &keys[..keys.len() - 1] {
                    bwd_n = self.ae_unwrap(&mut rng, key, bwd_n);
                }
                // In ReplyOnion we take the MAC after unwrapping the onion a final time, so we
                // need to take that as the expected MAC:
                let expected_tag = self.ae_unwrap(&mut rng, keys.last().unwrap(), bwd_n.clone()).1;
                (data, bwd_1, bwd_n, expected_tag)
            },
            Payload::Backward(data) => {
                let mut data = Vec::from(data);
                for key in &keys_symmetric[..n - 1] {
                    self.primitives.symmetric_decrypt(&mut rng, key, NONCE_FWD, &mut data);
                }

                // Backward payload won't be used
                let bwd_1 = (Vec::new(), Default::default());
                let bwd_n = (Vec::new(), Default::default());
                (data, bwd_1, bwd_n, Default::default())
            },
        };

        let tag = self.primitives.tag(&mut rng, &keys_mac[n - 1], &pack((&meta_ciphers[n - 1], &header_blocks[n - 1][1..], &fwd_n)));

        let first_block = Header::structured(tag, meta_ciphers[n - 1].clone());

        // Wrap up the onion
        let mut fwd = fwd_n.clone();
        let mut headers = vec![first_block];
        headers.extend_from_slice(&header_blocks[n - 1][1..]);
        let headers_n = headers.clone();
        for i in (0..n - 1).rev() {
            headers.pop();
            (headers, fwd) = self.wrap(&mut rng, &keys[i], &meta_ciphers[i], &headers, &fwd)?;
        }

        let onion_1 = Onion {
            header: headers,
            forward: fwd,
            backward: bwd,
        };

        let onion_n = Onion {
            header: headers_n,
            forward: fwd_n,
            backward: bwd_n,
        };

        Ok((onion_1, onion_n, expected_tag))
    }

    /// Unwraps a single onion layer.
    ///
    /// This takes the private key of the mix node, and returns the onion with a layer removed.
    ///
    /// The extracted (and decrypted) hop data is also returned.
    pub fn unwrap<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        private_key: &P::PrivateKey,
        mut onion: Onion<P>,
    ) -> Result<(P::SymmetricKey, Meta, Onion<P>), Error> {
        let header = onion.header[0].into_parsed()?;
        let decrypted_meta = self.primitives.asymmetric_decrypt(&mut rng, private_key, &header.data);
        let (key, meta): (P::SymmetricKey, Meta) = bincode::deserialize(&decrypted_meta).or(Err(Error::MacMismatch))?;
        let key_symmetric = self.primitives.derive_key(&mut rng, KeyRole::SymEnc, &key);
        let key_mac = self.primitives.derive_key(&mut rng, KeyRole::Mac, &key);
        let tag = self.primitives.tag(&mut rng, &key_mac, &pack((header.data, &onion.header[1..], &onion.forward)));
        if tag != header.tag {
            return Err(Error::MacMismatch);
        }
        for i in 0usize..self.max_path_length as usize - 1 {
            let mut data = onion.header[i + 1].into_bytes()?;
            self.primitives.symmetric_decrypt(&mut rng, &key_symmetric, i as u32 + 2, &mut data);
            onion.header[i] = Header::Raw(data);
        }
        {
            let mut data = self.zero_header();
            self.primitives.symmetric_decrypt(&mut rng, &key_symmetric, self.max_path_length + 1, data.force_pack()?);
            *onion.header.last_mut().unwrap() = data;
        }

        self.primitives.symmetric_decrypt(&mut rng, &key_symmetric, NONCE_FWD, &mut onion.forward);
        onion.backward = self.ae_unwrap(&mut rng, &key, onion.backward);

        Ok((key, meta, onion))
    }

    /// Forms a reply onion for the given input onion.
    ///
    /// This takes the extracted (and decrypted) hop data (as returned by [`OnionFormat::unwrap`],
    /// and the onion. It will split the reply-header off the payload, fill the forward section
    /// with pseudorandom data, and fill the backward section with the encrypted `payload`.
    pub fn reply_onion<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        private_key: &P::PrivateKey,
        onion: Onion<P>,
        payload: &[u8],
    ) -> Result<(Onion<P>, Address), Error> {
        let payload_length = onion.forward.len();

        let (key, meta, next_onion) = self.unwrap(&mut rng, private_key, onion)?;

        if meta.role != Role::Receiver {
            return Err(Error::NotTheReceiver);
        }

        let (header, _) = self.split_reply_header(&next_onion.forward)?;

        let mut new_message = vec![0; payload_length];
        self.primitives.prng(&self.primitives.derive_key(&mut rng, KeyRole::Prng, &key), &mut new_message);

        let mu = next_onion.backward.1;

        let onion = Onion {
            header,
            forward: new_message,
            backward: self.ae_enc(&mut rng, &key, &mu, &payload),
        };

        Ok((onion, meta.next))
    }

    /// Main function to create a new onion.
    ///
    /// This takes the forward path, backward path and the payload, and returns a fresh repliable
    /// onion.
    ///
    /// The backward section of the resulting onion is filled with random data in the same length
    /// as the given `payload`.
    ///
    /// This function internally uses [`OnionFormat::onionize`] and returns the same two onions
    /// (first hop and final hop).
    pub fn form_onion<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        hops_forward: &[Address],
        hops_backward: &[Address],
        payload: &[u8],
    ) -> Result<(Onion<P>, ExpectedResponse<P>), Error> {
        if hops_forward.len() > self.max_path_length as usize || hops_backward.len() > self.max_path_length as usize {
            return Err(Error::PathTooLong);
        }

        let master_key = self.primitives.random_key(&mut rng);

        let keys_forward = (0..hops_forward.len())
            .map(|i| self.primitives.derive_key(&mut rng, KeyRole::Forward(i as u32), &master_key))
            .collect::<Vec<_>>();

        let keys_backward = (0..hops_backward.len() - 1)
            .map(|i| self.primitives.derive_key(&mut rng, KeyRole::Backward(i as u32), &master_key))
            .chain(iter::once(master_key.clone()))
            .collect::<Vec<_>>();

        let key_prng = self.primitives.derive_key(&mut rng, KeyRole::Prng, keys_forward.last().unwrap());

        let mut random_payload = vec![0; self.total_header_length() + 8 + payload.len()];
        self.primitives.prng(&key_prng, &mut random_payload);

        let mut meta_backward = Meta {
            role: Role::Sender,
            next: Default::default(),
        };
        meta_backward.next[0..16].copy_from_slice(&pack((hops_forward.len() as u64, hops_backward.len() as u64)));
        let (onion_backward_1, onion_backward_n, _) = self.onionize(
            &mut rng,
            &keys_backward,
            hops_backward,
            meta_backward,
            Payload::Backward(&random_payload),
            0,
        )?;

        let meta_forward = Meta {
            role: Role::Receiver,
            next: *hops_backward.first().unwrap(),
        };
        let (onion_forward_1, onion_forward_n, expected_tag) = self.onionize(
            &mut rng,
            &keys_forward,
            hops_forward,
            meta_forward,
            Payload::Forward(&pack((onion_backward_1.header, payload))),
            payload.len(),
        )?;

        let expected_response = ExpectedResponse {
            identifier: onion_backward_n.packed_header()?,
            onion: onion_forward_n,
            tag: expected_tag,
        };

        Ok((onion_forward_1, expected_response))
    }

    /// Splits off the reply header from the actual payload.
    pub fn split_reply_header<'b>(
        &self,
        data: &'b [u8],
    ) -> Result<(Vec<Header<P>>, &'b [u8]), Error> {
        Ok(bincode::deserialize(data)?)
    }

    /// Processes the onion.
    ///
    /// Depending on the role of the mix node, returns the right [`ProcessedOnion`] variant.
    pub fn proc_onion<R: Rng + CryptoRng, F: Fn(&[u8]) -> Option<P::Tag>>(
        &self,
        mut rng: R,
        private_key: &P::PrivateKey,
        expected_tag: F,
        onion: Onion<P>,
    ) -> Result<ProcessedOnion<P>, Error> {
        let (master_key, meta, next_onion) = self.unwrap(&mut rng, private_key, onion.clone())?;

        match meta.role {
            Role::Hop => {
                Ok(ProcessedOnion::Hop { next_address: meta.next, next_onion })
            },
            Role::Receiver => {
                let (_, message) = self.split_reply_header(&next_onion.forward)?;
                Ok(ProcessedOnion::Receiver { payload: message.to_vec() })
            },
            Role::Sender => {
                let (n_forward, n_backward): (u64, u64) = bincode::deserialize(&meta.next[..16])?;
                let identifier = onion.packed_header()?;
                let mut bwd = onion.backward;

                //bwd = self.ae_wrap(&mut rng, &master_key, bwd);
                for i in (0..n_backward - 1).rev() {
                    let key_backward = self.primitives.derive_key(&mut rng, KeyRole::Backward(i as u32), &master_key);
                    bwd = self.ae_wrap(&mut rng, &key_backward, bwd);
                }
                let key_forward = self.primitives.derive_key(&mut rng, KeyRole::Forward(n_forward as u32 - 1), &master_key);
                let Some(ex_tag) = expected_tag(&identifier) else {
                    return Err(Error::UnexpectedReply);
                };

                let payload = self.ae_dec(&mut rng, &key_forward, &ex_tag, bwd).ok_or(Error::AeError)?;

                Ok(ProcessedOnion::Sender {
                    payload,
                })
            },
        }
    }

    /// Shorthand for [`proc_onion`] when no replies are expected.
    pub fn proc_onion_without_reply<R: Rng + CryptoRng>(
        &self,
        rng: R,
        private_key: &P::PrivateKey,
        onion: Onion<P>,
    ) -> Result<ProcessedOnion<P>, Error> {
        self.proc_onion(rng, private_key, |_| None, onion)
    }
}

/// An onion as you will get it from `ProcOnion`.
#[derive(Debug, Clone)]
pub enum ProcessedOnion<P: Primitives> {
    /// We're simply a hop in the onion path.
    Hop {
        /// Address of the next hop in the path.
        next_address: Address,
        /// Prepared onion to send to `next_address`.
        next_onion: Onion<P>,
    },

    /// We are the receiver of an onion. We have the chance to reply.
    Receiver {
        /// "Forward" payload of the onion.
        payload: Vec<u8>,
    },
    /// This hop was the original sender of the onion.
    Sender {
        /// "Backward" payload of the onion
        payload: Vec<u8>,
    },
}

#[cfg(test)]
mod test {
    use std::{assert_matches, collections::HashMap};

    use super::*;
    use super::{
        pki::Pki,
        primitives::{EcPrimitives, Primitives},
    };

    type TestFormat = OnionFormat<EcPrimitives>;
    const PAYLOAD: &[u8] = b"foo bar";
    const REPLY_PAYLOAD: &[u8] = b"rab oof";

    fn keysetup() -> (
        Pki<EcPrimitives>,
        HashMap<Address, <EcPrimitives as Primitives>::PrivateKey>,
    ) {
        let mut pki = Pki::<EcPrimitives>::new();
        let mut private_keys = HashMap::new();
        for _ in 0..20 {
            let address: Address = rand::thread_rng().gen();
            let (sk, pk) = EcPrimitives.generate_keypair(rand::thread_rng());
            pki.insert(address, pk);
            private_keys.insert(address, sk);
        }
        (pki, private_keys)
    }

    fn konst<A: ?Sized, B: Clone>(value: B) -> impl for<'a> Fn(&'a A) -> B {
        move |_| value.clone()
    }

    #[test]
    fn test_direct() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 1);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, expected_response) = format
            .form_onion(&mut rng, &addresses[..1], &addresses[1..2], PAYLOAD)
            .unwrap();

        assert_ne!(current_onion.forward, PAYLOAD);

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[0]], current_onion.clone())
            .unwrap();

        if let ProcessedOnion::Receiver {
            payload,
        } = proc
        {
            assert_eq!(payload, PAYLOAD);
            let next_hop;
            (current_onion, next_hop) = format
                .reply_onion(&mut rng, &private_keys[&addresses[0]], current_onion, REPLY_PAYLOAD)
                .unwrap();
            assert_eq!(next_hop, addresses[1]);
        } else {
            panic!("Expected the receiver as layer 1");
        }

        let proc = format
            .proc_onion(&mut rng, &private_keys[&addresses[1]], |_| Some(expected_response.tag), current_onion)
            .unwrap();

        if let ProcessedOnion::Sender { payload, .. } = proc {
            assert_eq!(payload, REPLY_PAYLOAD);
        } else {
            panic!("Expected the original sender as layer 2");
        }
    }

    #[test]
    fn test_single_between() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 2);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, expected_reply) = format
            .form_onion(&mut rng, &addresses[..2], &addresses[2..4], PAYLOAD)
            .unwrap();

        assert_ne!(current_onion.forward, PAYLOAD);

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[0]], current_onion)
            .unwrap();

        if let ProcessedOnion::Hop {
            next_address,
            next_onion,
        } = proc
        {
            current_onion = next_onion;
            assert_eq!(next_address, addresses[1]);
        } else {
            panic!("Expected a hop as layer 1");
        }

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[1]], current_onion.clone())
            .unwrap();

        if let ProcessedOnion::Receiver {
            payload,
        } = proc
        {
            assert_eq!(payload, PAYLOAD);
            let next_hop;
            (current_onion, next_hop) = format
                .reply_onion(&mut rng, &private_keys[&addresses[1]], current_onion, REPLY_PAYLOAD)
                .unwrap();
            assert_eq!(next_hop, addresses[2]);
        } else {
            panic!("Expected the receiver as layer 2");
        }

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[2]], current_onion)
            .unwrap();

        if let ProcessedOnion::Hop {
            next_address,
            next_onion,
        } = proc
        {
            current_onion = next_onion;
            assert_eq!(next_address, addresses[3]);
        } else {
            panic!("Expected a hop as layer 3");
        }

        let proc = format
            .proc_onion(&mut rng, &private_keys[&addresses[3]], |_| Some(expected_reply.tag), current_onion)
            .unwrap();

        if let ProcessedOnion::Sender { payload } = proc {
            assert_eq!(payload, REPLY_PAYLOAD);
        } else {
            panic!("Expected the original sender as layer 4");
        }
    }

    #[test]
    fn test_long_path_between() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 10);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, expected_reply) = format
            .form_onion(&mut rng, &addresses[..10], &addresses[10..20], PAYLOAD)
            .unwrap();
        let mut current_address = addresses[0];

        loop {
            let private_key = private_keys.get(&current_address).unwrap();

            let proc = format
                .proc_onion(
                    &mut rng,
                    private_key,
                    |identifier| if identifier == expected_reply.identifier {
                        Some(expected_reply.tag)
                    } else {
                        None
                    },
                    current_onion.clone(),
                )
                .unwrap();

            match proc {
                ProcessedOnion::Hop {
                    next_address,
                    next_onion,
                } => {
                    current_onion = next_onion;
                    current_address = next_address;
                }
                ProcessedOnion::Sender { payload } => {
                    assert_eq!(payload, REPLY_PAYLOAD);
                    break;
                }
                ProcessedOnion::Receiver {
                    payload,
                } => {
                    assert_eq!(payload, PAYLOAD);

                    (current_onion, current_address) = format
                        .reply_onion(&mut rng, private_key, current_onion, REPLY_PAYLOAD)
                        .unwrap();
                }
            }
        }
    }

    #[test]
    fn test_final_onion_as_expected() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 10);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, final_expectation) = format
            .form_onion(&mut rng, &addresses[..10], &addresses[10..20], PAYLOAD)
            .unwrap();
        let mut current_address = addresses[0];

        let final_expectation = final_expectation.onion;

        loop {
            let private_key = private_keys.get(&current_address).unwrap();

            let proc = format
                .proc_onion_without_reply(&mut rng, private_key, current_onion.clone())
                .unwrap();

            match proc {
                ProcessedOnion::Hop {
                    next_address,
                    next_onion,
                } => {
                    current_onion = next_onion;
                    current_address = next_address;
                }
                ProcessedOnion::Sender { .. } => {
                    panic!("We don't create a reply, should never reach here");
                }
                ProcessedOnion::Receiver { .. } => {
                    assert_eq!(current_onion.header, final_expectation.header);
                    assert_eq!(current_onion.forward, final_expectation.forward);
                    assert_eq!(current_onion.backward, final_expectation.backward);
                    break;
                }
            }
        }
    }

    #[test]
    fn test_wrong_key() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 2);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (current_onion, _) = format
            .form_onion(&mut rng, &addresses[..2], &addresses[2..4], PAYLOAD)
            .unwrap();

        // Note that we use the wrong key here:
        let result = format.proc_onion_without_reply(&mut rng, &private_keys[&addresses[1]], current_onion);
        assert_matches!(result, Err(Error::MacMismatch));
    }

    #[test]
    fn test_header_tagging_foiled() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 2);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, _) = format
            .form_onion(&mut rng, &addresses[..2], &addresses[2..4], PAYLOAD)
            .unwrap();

        // Evil bitflip by the attacker
        current_onion.header[1].force_pack().unwrap()[0] ^= 1;

        let result = format.proc_onion_without_reply(&mut rng, &private_keys[&addresses[0]], current_onion);
        assert_matches!(result, Err(Error::MacMismatch));
    }

    #[test]
    fn test_forward_payload_tagging_foiled() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 2);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, _) = format
            .form_onion(&mut rng, &addresses[..2], &addresses[2..4], PAYLOAD)
            .unwrap();

        // The attacker strikes again with a bitflip
        current_onion.forward[0] ^= 1;

        let result = format.proc_onion_without_reply(&mut rng, &private_keys[&addresses[0]], current_onion);
        assert_matches!(result, Err(Error::MacMismatch));
    }

    #[test]
    fn test_backward_payload_tagging() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 2);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, expected_reply) = format
            .form_onion(&mut rng, &addresses[..2], &addresses[2..4], PAYLOAD)
            .unwrap();

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[0]], current_onion)
            .unwrap();

        if let ProcessedOnion::Hop {
            next_address: _,
            next_onion,
        } = proc
        {
            current_onion = next_onion;
        } else {
            panic!("Expected a hop as layer 1");
        }

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[1]], current_onion.clone())
            .unwrap();

        if let ProcessedOnion::Receiver {
            payload: _,
        } = proc
        {
            (current_onion, _) = format
                .reply_onion(&mut rng, &private_keys[&addresses[1]], current_onion, REPLY_PAYLOAD)
                .unwrap();
        } else {
            panic!("Expected the receiver as layer 2");
        }

        // The attacker flips the bit
        current_onion.backward.0[0] ^= 1;

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[2]], current_onion)
            .unwrap();

        // The next hop does not notice it, that is intended - only the original sender will notice
        // the bitflip.
        if let ProcessedOnion::Hop {
            next_address: _,
            next_onion,
        } = proc
        {
            current_onion = next_onion;
        } else {
            panic!("Expected a hop as layer 3");
        }

        // The original sender realizes that the payload has been tagged.
        let proc = format.proc_onion(&mut rng, &private_keys[&addresses[3]], konst(Some(expected_reply.tag)), current_onion);
        assert_matches!(proc, Err(Error::AeError));
    }

    #[test]
    fn test_size_independent_of_path() {
        fn len(onion: &Onion<EcPrimitives>) -> usize {
            bincode::serialize(onion).unwrap().len()
        }

        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 10);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let onion_1_1 = format
            .form_onion(&mut rng, &addresses[..1], &addresses[1..2], PAYLOAD)
            .unwrap()
            .0;
        let onion_5_5 = format
            .form_onion(&mut rng, &addresses[0..5], &addresses[5..10], PAYLOAD)
            .unwrap()
            .0;
        let onion_1_5 = format
            .form_onion(&mut rng, &addresses[..1], &addresses[2..7], PAYLOAD)
            .unwrap()
            .0;
        let onion_5_1 = format
            .form_onion(&mut rng, &addresses[..5], &addresses[5..6], PAYLOAD)
            .unwrap()
            .0;

        assert_eq!(len(&onion_1_1), len(&onion_5_5));
        assert_eq!(len(&onion_1_1), len(&onion_1_5));
        assert_eq!(len(&onion_1_1), len(&onion_5_1));
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 1);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let (mut current_onion, expected_reply) = format
            .form_onion(&mut rng, &addresses[..1], &addresses[1..2], PAYLOAD)
            .unwrap();

        // Transport onion over the wire by serializing and deserializing it.
        let old_onion = current_onion.clone();
        current_onion = bincode::deserialize(&bincode::serialize(&current_onion).unwrap()).unwrap();
        assert_eq!(current_onion, old_onion);

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[0]], current_onion.clone())
            .unwrap();

        if let ProcessedOnion::Receiver {
            payload,
        } = proc
        {
            assert_eq!(payload, PAYLOAD);
            let next_hop;
            (current_onion, next_hop) = format
                .reply_onion(&mut rng, &private_keys[&addresses[0]], current_onion, REPLY_PAYLOAD)
                .unwrap();
            assert_eq!(next_hop, addresses[1]);
        } else {
            panic!("Expected the receiver as layer 1");
        }

        // Again, simulated wire transport.
        current_onion = bincode::deserialize(&bincode::serialize(&current_onion).unwrap()).unwrap();

        let proc = format
            .proc_onion(&mut rng, &private_keys[&addresses[1]], konst(Some(expected_reply.tag)), current_onion)
            .unwrap();

        if let ProcessedOnion::Sender { payload, .. } = proc {
            assert_eq!(payload, REPLY_PAYLOAD);
        } else {
            panic!("Expected the original sender as layer 2");
        }
    }

    fn onion_size<P: Primitives>(onion: &Onion<P>) -> usize {
        bincode::serialize(onion).unwrap().len()
    }

    #[test]
    fn test_reply_same_size() {
        let mut rng = rand::thread_rng();
        let (pki, private_keys) = keysetup();

        let format = TestFormat::new(EcPrimitives, pki, 2);

        let addresses = private_keys.keys().cloned().collect::<Vec<_>>();

        let mut current_onion = format
            .form_onion(&mut rng, &addresses[..2], &addresses[2..4], PAYLOAD)
            .unwrap()
            .0;

        let first_size = onion_size(&current_onion);

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[0]], current_onion)
            .unwrap();

        if let ProcessedOnion::Hop {
            next_address: _,
            next_onion,
        } = proc
        {
            current_onion = next_onion;
        } else {
            panic!("Expected a hop as layer 1");
        }

        assert_eq!(onion_size(&current_onion), first_size);

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[1]], current_onion.clone())
            .unwrap();

        if let ProcessedOnion::Receiver { .. } = proc
        {
            (current_onion, _) = format
                .reply_onion(&mut rng, &private_keys[&addresses[1]], current_onion, REPLY_PAYLOAD)
                .unwrap();
        } else {
            panic!("Expected the receiver as layer 2");
        }

        assert_eq!(onion_size(&current_onion), first_size);

        let proc = format
            .proc_onion_without_reply(&mut rng, &private_keys[&addresses[2]], current_onion)
            .unwrap();

        if let ProcessedOnion::Hop {
            next_onion, ..
        } = proc
        {
            current_onion = next_onion;
        } else {
            panic!("Expected a hop as layer 3");
        }

        assert_eq!(onion_size(&current_onion), first_size);
    }
}
