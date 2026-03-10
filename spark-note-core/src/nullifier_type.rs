//! Nullifier type for efficient HashSet operations
//!
//! This module provides a fixed-size Nullifier type that is more efficient
//! than using Vec<u8> as HashSet keys.

use std::fmt;
use crate::error::{SparkError, SparkResult};
use crate::validation::validate_nullifier;

/// A 32-byte nullifier value
///
/// This type uses a fixed-size array for efficient HashSet operations
/// and prevents accidental use of wrong-sized data.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier([u8; 32]);

impl Nullifier {
    /// Create a new nullifier from a 32-byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Nullifier(bytes)
    }
    
    /// Get the nullifier as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Create a nullifier from a byte slice
    ///
    /// # Returns
    /// * `Ok(Nullifier)` if the slice is exactly 32 bytes
    /// * `Err(SparkError)` if the slice has wrong length
    pub fn from_slice(slice: &[u8]) -> SparkResult<Self> {
        validate_nullifier(slice)?;
        
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        Ok(Nullifier(arr))
    }
    
    /// Convert to a Vec<u8> (for compatibility with existing code)
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<[u8; 32]> for Nullifier {
    fn from(bytes: [u8; 32]) -> Self {
        Nullifier::new(bytes)
    }
}

impl TryFrom<Vec<u8>> for Nullifier {
    type Error = SparkError;
    
    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Nullifier::from_slice(&v)
    }
}

impl fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nullifier({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_from_slice() {
        let bytes = vec![1u8; 32];
        let nullifier = Nullifier::from_slice(&bytes).unwrap();
        assert_eq!(nullifier.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_nullifier_wrong_length() {
        let bytes = vec![1u8; 31];
        assert!(Nullifier::from_slice(&bytes).is_err());
    }

    #[test]
    fn test_nullifier_hash() {
        use std::collections::HashSet;
        
        let n1 = Nullifier::new([1; 32]);
        let n2 = Nullifier::new([2; 32]);
        let n3 = Nullifier::new([1; 32]);
        
        let mut set = HashSet::new();
        set.insert(n1);
        set.insert(n2);
        set.insert(n3); // Duplicate of n1
        
        assert_eq!(set.len(), 2);
    }
}

