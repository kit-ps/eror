//! Mock implementation of a public key infrastructure.
//!
//! In real usages, this might be replaced with code that reads keys from a local key store (like
//! GPG), or retrieves keys from a key server.
//!
//! For our prototype, we build a simple PKI that stores all available keys as a hashmap.
use std::collections::HashMap;

use super::{primitives::Primitives, Address};

/// Struct that simulates a public key infrastructure.
///
/// This is a small shim over a hashmap with the correct types for the given primitives.
#[derive(Debug, Clone)]
pub struct Pki<P: Primitives> {
    keys: HashMap<Address, P::PublicKey>,
}

impl<P: Primitives> Default for Pki<P> {
    fn default() -> Self {
        Self {
            keys: Default::default(),
        }
    }
}

impl<P: Primitives> Pki<P> {
    /// Creates a new, empty key store.
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns a reference to the underlying storage.
    pub fn keys(&self) -> &HashMap<Address, P::PublicKey> {
        &self.keys
    }

    /// Insert a key into the PKI.
    ///
    /// If the key did not exist yet, ``None`` is returned. If the key did already exist, the old
    /// key is returned.
    pub fn insert(&mut self, address: Address, key: P::PublicKey) -> Option<P::PublicKey> {
        self.keys.insert(address, key)
    }

    /// Retrieve a key from the store.
    ///
    /// Returns ``None`` if no key is found for the given address.
    pub fn get(&self, address: &Address) -> Option<&P::PublicKey> {
        self.keys.get(address)
    }
}
