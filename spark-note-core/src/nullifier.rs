//! Nullifier generation and spent tracking
//!
//! This module provides functions for generating nullifiers from notes
//! and checking if nullifiers have been spent, with batch operations support.

use std::collections::HashSet;
use serde::{Deserialize, Serialize};

use crate::error::{NullifierErrorCode, SparkError, SparkResult};
use crate::note::SparkNote;
use crate::secret::Secret;
use crate::validation::validate_nullifier;
pub use crate::nullifier_type::Nullifier;

/// Generates a nullifier for a given note
///
/// The nullifier is computed as BLAKE3(commitment || secret), which creates
/// a unique identifier that can be used to prevent double-spending without
/// revealing the note's contents.
pub fn generate_nullifier(note: &SparkNote, secret: &Secret) -> Nullifier {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&note.commitment);
    hasher.update(secret.as_bytes());
    let hash = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_bytes());
    Nullifier::new(bytes)
}

/// Generates a nullifier and returns it as Vec<u8> (for compatibility)
pub fn generate_nullifier_vec(note: &SparkNote, secret: &Secret) -> Vec<u8> {
    generate_nullifier(note, secret).to_vec()
}

/// Efficient nullifier set using fixed-size keys
#[derive(Debug, Clone)]
pub struct NullifierSet {
    spent_set: HashSet<Nullifier>,
}

impl NullifierSet {
    /// Create a new empty nullifier set
    pub fn new() -> Self {
        NullifierSet {
            spent_set: HashSet::new(),
        }
    }
    
    /// Add a nullifier to the set
    pub fn add(&mut self, nullifier: Nullifier) -> bool {
        self.spent_set.insert(nullifier)
    }
    
    /// Check if a nullifier is in the set
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.spent_set.contains(nullifier)
    }
    
    /// Check if a nullifier slice is in the set
    pub fn contains_slice(&self, nullifier: &[u8]) -> bool {
        match Nullifier::from_slice(nullifier) {
            Ok(n) => self.contains(&n),
            Err(_) => false,
        }
    }
    
    /// Get the size of the set
    pub fn len(&self) -> usize {
        self.spent_set.len()
    }
    
    /// Export all nullifiers as Vec<u8> (for compatibility)
    pub fn export(&self) -> Vec<Vec<u8>> {
        self.spent_set.iter().map(|n| n.to_vec()).collect()
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if a nullifier has been spent (legacy API using Vec<u8>)
///
/// This function is kept for backward compatibility but uses
/// the efficient NullifierSet internally when possible.
pub fn is_nullifier_spent(nullifier: &[u8], spent_set: &HashSet<Vec<u8>>) -> bool {
    // Convert to Nullifier for efficient lookup
    if let Ok(_n) = Nullifier::from_slice(nullifier) {
        // Convert HashSet<Vec<u8>> to HashSet<Nullifier> for lookup
        // This is not ideal but maintains backward compatibility
        spent_set.contains(nullifier)
    } else {
        false
    }
}

/// Checks multiple nullifiers at once
///
/// # Arguments
/// * `nullifiers` - Vector of nullifiers to check
/// * `spent_set` - A set of already spent nullifiers
///
/// # Returns
/// Vector of booleans indicating whether each nullifier is spent
///
/// # Example
/// ```
/// use std::collections::HashSet;
/// use spark_note_core::nullifier::check_multiple_nullifiers;
///
/// let nullifiers = vec![vec![1u8; 32], vec![2u8; 32]];
/// let mut spent_set = HashSet::new();
/// spent_set.insert(vec![1u8; 32]);
///
/// let results = check_multiple_nullifiers(&nullifiers, &spent_set);
/// assert_eq!(results, vec![true, false]);
/// ```
pub fn check_multiple_nullifiers(
    nullifiers: &[Vec<u8>],
    spent_set: &HashSet<Vec<u8>>,
) -> Vec<bool> {
    nullifiers
        .iter()
        .map(|n| is_nullifier_spent(n, spent_set))
        .collect()
}

/// Marks multiple nullifiers as spent
///
/// # Arguments
/// * `nullifiers` - Vector of nullifiers to mark as spent
/// * `spent_set` - Mutable reference to the set of spent nullifiers
///
/// # Returns
/// * `Ok(())` if all nullifiers were successfully marked
/// * `Err(SparkError)` if any nullifier is invalid or already spent
///
/// # Example
/// ```
/// use std::collections::HashSet;
/// use spark_note_core::nullifier::mark_multiple_as_spent;
///
/// let mut spent_set = HashSet::new();
/// let nullifiers = vec![vec![1; 32], vec![2; 32]];
///
/// mark_multiple_as_spent(&nullifiers, &mut spent_set).unwrap();
/// assert_eq!(spent_set.len(), 2);
/// ```
pub fn mark_multiple_as_spent(
    nullifiers: &[Vec<u8>],
    spent_set: &mut HashSet<Vec<u8>>,
) -> SparkResult<()> {
    for nullifier in nullifiers {
        validate_nullifier(nullifier)?;
        
        if spent_set.contains(nullifier) {
            return Err(SparkError::nullifier_error(
                NullifierErrorCode::AlreadySpent,
                "One or more nullifiers are already spent",
            ));
        }
        
        spent_set.insert(nullifier.clone());
    }
    
    Ok(())
}

/// Marks a nullifier as spent with validation
///
/// # Arguments
/// * `nullifier` - The nullifier to mark as spent
/// * `spent_set` - Mutable reference to the set of spent nullifiers
///
/// # Returns
/// * `Ok(())` if successfully marked
/// * `Err(SparkError)` if nullifier is invalid or already spent
pub fn mark_as_spent(
    nullifier: &[u8],
    spent_set: &mut HashSet<Vec<u8>>,
) -> SparkResult<()> {
    validate_nullifier(nullifier)?;
    
    if spent_set.contains(nullifier) {
        return Err(SparkError::nullifier_error(
            NullifierErrorCode::AlreadySpent,
            "Nullifier is already spent",
        ));
    }
    
    spent_set.insert(nullifier.to_vec());
    Ok(())
}

/// Gets the size of the nullifier set
///
/// # Arguments
/// * `spent_set` - The set of spent nullifiers
///
/// # Returns
/// The number of nullifiers in the set
pub fn get_nullifier_set_size(spent_set: &HashSet<Vec<u8>>) -> usize {
    spent_set.len()
}

/// Statistics about a nullifier set
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct NullifierSetStats {
    /// Number of nullifiers in the set
    pub count: u64,
    /// Estimated memory usage in bytes
    pub memory_usage_bytes: u64,
}

/// Gets statistics about a nullifier set
///
/// # Arguments
/// * `spent_set` - The set of spent nullifiers
///
/// # Returns
/// Statistics about the set
pub fn get_nullifier_set_stats(spent_set: &HashSet<Vec<u8>>) -> NullifierSetStats {
    let count = spent_set.len() as u64;
    // Estimate: each nullifier is 32 bytes + overhead
    // HashSet overhead is roughly 8 bytes per entry
    let memory_usage_bytes = count * (32 + 8);
    
    NullifierSetStats {
        count,
        memory_usage_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::create_note;

    #[test]
    fn test_generate_nullifier() {
        use crate::secret::Secret;
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let note = create_note(1000, secret.clone()).unwrap();

        let nullifier = generate_nullifier(&note, &secret);

        // BLAKE3 produces 32 bytes
        assert_eq!(nullifier.as_bytes().len(), 32);
    }

    #[test]
    fn test_nullifier_consistency() {
        use crate::secret::Secret;
        let secret = Secret::new(vec![42, 43, 44, 45, 46, 47, 48, 49]);
        let note = create_note(5000, secret.clone()).unwrap();

        let nullifier1 = generate_nullifier(&note, &secret);
        let nullifier2 = generate_nullifier(&note, &secret);

        // Same inputs should produce same nullifier
        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_different_secrets_different_nullifiers() {
        use crate::secret::Secret;
        let secret1 = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let secret2 = Secret::new(vec![5, 6, 7, 8, 9, 10, 11, 12]);
        let note = create_note(1000, secret1.clone()).unwrap();

        let nullifier1 = generate_nullifier(&note, &secret1);
        let nullifier2 = generate_nullifier(&note, &secret2);

        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_is_nullifier_spent_not_in_set() {
        let nullifier = vec![1; 32]; // Must be 32 bytes
        let spent_set: HashSet<Vec<u8>> = HashSet::new();

        assert!(!is_nullifier_spent(&nullifier, &spent_set));
    }

    #[test]
    fn test_is_nullifier_spent_in_set() {
        let nullifier = vec![1; 32]; // Must be 32 bytes
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        spent_set.insert(nullifier.clone());

        assert!(is_nullifier_spent(&nullifier, &spent_set));
    }

    #[test]
    fn test_check_multiple_nullifiers() {
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        let nullifier1 = vec![1; 32];
        let nullifier2 = vec![2; 32];
        let nullifier3 = vec![3; 32];
        
        spent_set.insert(nullifier1.clone());
        spent_set.insert(nullifier2.clone());
        
        let nullifiers = vec![nullifier1, nullifier2, nullifier3];
        let results = check_multiple_nullifiers(&nullifiers, &spent_set);
        
        assert_eq!(results, vec![true, true, false]);
    }

    #[test]
    fn test_mark_multiple_as_spent() {
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        let nullifiers = vec![vec![1; 32], vec![2; 32], vec![3; 32]];
        
        mark_multiple_as_spent(&nullifiers, &mut spent_set).unwrap();
        assert_eq!(spent_set.len(), 3);
    }

    #[test]
    fn test_mark_multiple_as_spent_already_spent() {
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        let nullifier = vec![1; 32];
        spent_set.insert(nullifier.clone());
        
        let nullifiers = vec![nullifier];
        let result = mark_multiple_as_spent(&nullifiers, &mut spent_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_as_spent() {
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        let nullifier = vec![1; 32];
        
        mark_as_spent(&nullifier, &mut spent_set).unwrap();
        assert!(is_nullifier_spent(&nullifier, &spent_set));
    }

    #[test]
    fn test_mark_as_spent_already_spent() {
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        let nullifier = vec![1; 32];
        spent_set.insert(nullifier.clone());
        
        let result = mark_as_spent(&nullifier, &mut spent_set);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_nullifier_set_size() {
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        assert_eq!(get_nullifier_set_size(&spent_set), 0);
        
        spent_set.insert(vec![1; 32]);
        spent_set.insert(vec![2; 32]);
        assert_eq!(get_nullifier_set_size(&spent_set), 2);
    }

    #[test]
    fn test_get_nullifier_set_stats() {
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        spent_set.insert(vec![1; 32]);
        spent_set.insert(vec![2; 32]);
        
        let stats = get_nullifier_set_stats(&spent_set);
        assert_eq!(stats.count, 2);
        assert!(stats.memory_usage_bytes > 0);
    }

    #[test]
    fn test_full_workflow() {
        use crate::secret::Secret;
        // Create a note
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let note = create_note(1000, secret.clone()).unwrap();

        // Generate nullifier
        let nullifier = generate_nullifier(&note, &secret);

        // Initially not spent
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();
        assert!(!is_nullifier_spent(nullifier.as_bytes(), &spent_set));

        // After spending
        mark_as_spent(nullifier.as_bytes(), &mut spent_set).unwrap();
        assert!(is_nullifier_spent(nullifier.as_bytes(), &spent_set));
    }
    
    #[test]
    fn test_nullifier_set() {
        use crate::secret::Secret;
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let note = create_note(1000, secret.clone()).unwrap();
        
        let nullifier = generate_nullifier(&note, &secret);
        let mut set = NullifierSet::new();
        
        assert!(!set.contains(&nullifier));
        set.add(nullifier);
        assert!(set.contains(&nullifier));
        assert_eq!(set.len(), 1);
    }
}
