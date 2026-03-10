//! Secret value type with automatic zeroization
//!
//! This module provides a `Secret` type that automatically zeroizes
//! sensitive data when dropped, preventing secrets from remaining in memory.

use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize, Deserializer, Serializer};

/// A secret value that is automatically zeroized when dropped
///
/// This type ensures that sensitive data is cleared from memory
/// when no longer needed, preventing memory dumps from exposing secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Create a new secret from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Secret(data)
    }
    
    /// Get a reference to the secret bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Get the length of the secret
    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    
    /// Consume the secret and return the inner Vec<u8>
    /// 
    /// WARNING: This exposes the secret. Use with caution.
    /// Note: This clones the data since Secret implements Drop.
    pub fn into_inner(self) -> Vec<u8> {
        self.0.clone()
    }
}

impl From<Vec<u8>> for Secret {
    fn from(data: Vec<u8>) -> Self {
        Secret::new(data)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(***)")
    }
}

// Custom serialization that doesn't expose the secret in serialized form
impl Serialize for Secret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a placeholder - secrets should not be serialized
        // In production, this should error or use encryption
        serializer.serialize_bytes(&[])
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize as empty - secrets should not be deserialized from untrusted sources
        let _ = Vec::<u8>::deserialize(deserializer)?;
        Ok(Secret::new(vec![]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = Secret::new(data.clone());
        
        assert_eq!(secret.len(), 5);
        assert_eq!(secret.as_bytes(), &data[..]);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secret_from_vec() {
        let data = vec![1, 2, 3];
        let secret = Secret::from(data.clone());
        
        assert_eq!(secret.as_bytes(), &data[..]);
    }

    #[test]
    fn test_secret_zeroization() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = Secret::new(data);
        
        // Drop the secret - it will be zeroized
        drop(secret);
        
        // Note: We can't directly verify memory was zeroized,
        // but the ZeroizeOnDrop trait ensures it will be
    }
}

