//! Note Manager for state management
//!
//! This module provides a NoteManager struct for managing multiple notes,
//! tracking nullifier sets, and providing query methods.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::error::{SparkError, SparkResult};
use crate::note::SparkNote;
use crate::nullifier::{generate_nullifier, NullifierSet, Nullifier};

/// Note state tracking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum NoteState {
    /// Note has not been spent
    Unspent,
    /// Note has been spent
    Spent,
}

/// Public note type for UniFFI (without secret)
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct PublicNote {
    pub value: u64,
    pub commitment: Vec<u8>,
}

impl From<&SparkNote> for PublicNote {
    fn from(note: &SparkNote) -> Self {
        PublicNote {
            value: note.value,
            commitment: note.commitment.clone(),
        }
    }
}

/// Entry in the note manager
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct NoteEntry {
    /// The note itself (public fields only)
    pub note: PublicNote,
    /// Current state of the note
    pub state: NoteState,
    /// Nullifier for this note (if generated)
    pub nullifier: Option<Vec<u8>>,
}

/// Internal note storage with secret
#[derive(Debug, Clone)]
struct InternalNoteEntry {
    note: SparkNote,
    state: NoteState,
    nullifier: Option<Vec<u8>>,
}

/// Manager for Spark notes and nullifiers
///
/// Note: This struct is not directly exposed via UniFFI due to HashSet limitations.
/// Use the provided methods to interact with the manager.
#[derive(Debug, Clone)]
pub struct NoteManager {
    /// Map of note IDs to note entries (with secrets)
    notes: HashMap<String, InternalNoteEntry>,
    /// Global set of spent nullifiers (efficient fixed-size keys)
    spent_nullifiers: NullifierSet,
    /// Optional Tezos client for on-chain synchronization
    pub tezos_client: Option<std::sync::Arc<crate::tezos::TezosClient>>,
}

impl NoteManager {
    /// Creates a new NoteManager
    pub fn new() -> Self {
        NoteManager {
            notes: HashMap::new(),
            spent_nullifiers: NullifierSet::new(),
            tezos_client: None,
        }
    }
    
    /// Sets the Tezos client
    pub fn with_tezos_client(mut self, client: crate::tezos::TezosClient) -> Self {
        self.tezos_client = Some(std::sync::Arc::new(client));
        self
    }
    
    /// Adds a note to the manager
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the note
    /// * `note` - The SparkNote to add
    ///
    /// # Returns
    /// * `Ok(())` if successfully added
    /// * `Err(SparkError)` if ID already exists
    pub fn add_note(&mut self, id: String, note: SparkNote) -> SparkResult<()> {
        if self.notes.contains_key(&id) {
            return Err(SparkError::OperationError {
                message: format!("Note with ID '{}' already exists", id),
            });
        }
        
        self.notes.insert(id, InternalNoteEntry {
            note,
            state: NoteState::Unspent,
            nullifier: None,
        });
        
        Ok(())
    }
    
    /// Gets a note by ID (public fields only)
    ///
    /// # Arguments
    /// * `id` - The note ID
    ///
    /// # Returns
    /// * `Some(NoteEntry)` if found
    /// * `None` if not found
    pub fn get_note(&self, id: &str) -> Option<NoteEntry> {
        self.notes.get(id).map(|entry| NoteEntry {
            note: PublicNote::from(&entry.note),
            state: entry.state.clone(),
            nullifier: entry.nullifier.clone(),
        })
    }
    
    /// Gets a mutable reference to internal note entry

    
    /// Lists all note IDs
    pub fn list_note_ids(&self) -> Vec<String> {
        self.notes.keys().cloned().collect()
    }
    
    /// Lists all notes (public fields only)
    pub fn list_notes(&self) -> Vec<(String, NoteEntry)> {
        self.notes.iter().map(|(k, v)| {
            (k.clone(), NoteEntry {
                note: PublicNote::from(&v.note),
                state: v.state.clone(),
                nullifier: v.nullifier.clone(),
            })
        }).collect()
    }
    
    /// Removes a note by ID
    ///
    /// # Arguments
    /// * `id` - The note ID to remove
    ///
    /// # Returns
    /// * `Ok(Option<NoteEntry>)` - The removed note if it existed
    pub fn remove_note(&mut self, id: &str) -> Option<NoteEntry> {
        self.notes.remove(id).map(|entry| NoteEntry {
            note: PublicNote::from(&entry.note),
            state: entry.state,
            nullifier: entry.nullifier,
        })
    }
    
    /// Generates a nullifier for a note
    ///
    /// # Arguments
    /// * `id` - The note ID
    /// * `secret` - The spending secret
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The generated nullifier
    /// * `Err(SparkError)` if note not found
    pub fn generate_nullifier_for_note(&mut self, id: &str, secret: Vec<u8>) -> SparkResult<Vec<u8>> {
        use crate::secret::Secret;
        let note_entry = self.notes.get_mut(id)
            .ok_or_else(|| SparkError::OperationError {
                message: format!("Note with ID '{}' not found", id),
            })?;
        
        let secret = Secret::from(secret);
        let nullifier = generate_nullifier(&note_entry.note, &secret);
        note_entry.nullifier = Some(nullifier.to_vec());
        
        Ok(nullifier.to_vec())
    }
    
    /// Marks a note as spent by its nullifier
    ///
    /// # Arguments
    /// * `id` - The note ID
    ///
    /// # Returns
    /// * `Ok(())` if successfully marked
    /// * `Err(SparkError)` if note not found, nullifier not generated, or already spent
    pub fn mark_note_as_spent(&mut self, id: &str) -> SparkResult<()> {
        let note_entry = self.notes.get_mut(id)
            .ok_or_else(|| SparkError::OperationError {
                message: format!("Note with ID '{}' not found", id),
            })?;
        
        let nullifier_bytes = note_entry.nullifier.as_ref()
            .ok_or_else(|| SparkError::OperationError {
                message: format!("Nullifier not generated for note '{}'", id),
            })?;
        
        // Convert to Nullifier type for efficient storage
        let nullifier = Nullifier::from_slice(nullifier_bytes)?;
        
        // Check if already spent
        if self.spent_nullifiers.contains(&nullifier) {
            return Err(SparkError::nullifier_error(
                crate::error::NullifierErrorCode::AlreadySpent,
                format!("Nullifier for note '{}' is already spent", id),
            ));
        }
        
        // Add to spent set
        self.spent_nullifiers.add(nullifier);
        note_entry.state = NoteState::Spent;
        
        Ok(())
    }
    
    /// Add a spent nullifier directly
    ///
    /// # Arguments
    /// * `nullifier` - The nullifier bytes to mark as spent
    ///
    /// # Returns
    /// * `Ok(())` if successfully added
    /// * `Err(SparkError)` if nullifier is invalid or already spent
    pub fn add_spent_nullifier(&mut self, nullifier: &[u8]) -> SparkResult<()> {
        let n = Nullifier::from_slice(nullifier)?;
        
        if self.spent_nullifiers.contains(&n) {
            return Err(SparkError::nullifier_error(
                crate::error::NullifierErrorCode::AlreadySpent,
                "Nullifier is already spent".to_string(),
            ));
        }
        
        self.spent_nullifiers.add(n);
        Ok(())
    }
    
    /// Check if a nullifier has been spent
    ///
    /// # Arguments
    /// * `nullifier` - The nullifier bytes to check
    ///
    /// # Returns
    /// `true` if the nullifier is in the spent set, `false` otherwise
    pub fn is_nullifier_spent(&self, nullifier: &[u8]) -> bool {
        self.spent_nullifiers.contains_slice(nullifier)
    }
    
    /// Gets statistics about the nullifier set
    pub fn get_nullifier_stats(&self) -> crate::nullifier::NullifierSetStats {
        use crate::nullifier::NullifierSetStats;
        let count = self.spent_nullifiers.len() as u64;
        // Estimate: each nullifier is 32 bytes + overhead
        // HashSet overhead is roughly 8 bytes per entry
        let memory_usage_bytes = count * (32 + 8);
        
        NullifierSetStats {
            count,
            memory_usage_bytes,
        }
    }
    
    /// Gets the number of notes
    pub fn note_count(&self) -> usize {
        self.notes.len()
    }
    
    /// Gets the number of spent nullifiers
    pub fn spent_nullifier_count(&self) -> usize {
        self.spent_nullifiers.len()
    }
    
    /// Export spent nullifiers as Vec<Vec<u8>> (for compatibility)
    ///
    /// # Deprecated
    /// This method is kept for backward compatibility. Consider using
    /// `NullifierSet` directly for better performance.
    #[deprecated(note = "Use NullifierSet directly. This method will be removed in v2.0")]
    pub fn get_spent_nullifiers(&self) -> Vec<Vec<u8>> {
        self.spent_nullifiers.export()
    }

    /// Sync a deposit to Tezos
    pub async fn sync_deposit_to_tezos(&self, id: &str, secret_key: &str) -> SparkResult<crate::tezos::TezosOperationResult> {
        let entry = self.get_note(id).ok_or_else(|| SparkError::OperationError {
            message: format!("Note with ID '{}' not found", id),
        })?;
        
        // This would require a real ZK proof attached to the note
        // For POC, we use a dummy proof
        let dummy_proof = vec![0u8; 128];
        
        let client = self.tezos_client.as_ref().ok_or_else(|| SparkError::tezos_error("Tezos client not configured"))?;
        client.deposit(&entry.note, &dummy_proof, secret_key).await
    }

    /// Sync a spend to Tezos
    pub async fn sync_spend_to_tezos(&self, id: &str, secret_key: &str) -> SparkResult<crate::tezos::TezosOperationResult> {
         let entry = self.get_note(id).ok_or_else(|| SparkError::OperationError {
            message: format!("Note with ID '{}' not found", id),
        })?;
        
        let nullifier = entry.nullifier.as_ref().ok_or_else(|| SparkError::OperationError {
            message: "Nullifier not generated for note".to_string(),
        })?;
        
        let dummy_proof = vec![0u8; 128];
        
        let client = self.tezos_client.as_ref().ok_or_else(|| SparkError::tezos_error("Tezos client not configured"))?;
        client.spend(nullifier, &dummy_proof, secret_key).await
    }
}

impl Default for NoteManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::create_note;
    
    #[test]
    fn test_note_manager_new() {
        let manager = NoteManager::new();
        assert_eq!(manager.note_count(), 0);
        assert_eq!(manager.spent_nullifier_count(), 0);
    }
    
    #[test]
    fn test_add_note() {
        use crate::secret::Secret;
        let mut manager = NoteManager::new();
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let note = create_note(1000, secret).unwrap();
        
        manager.add_note("note1".to_string(), note).unwrap();
        assert_eq!(manager.note_count(), 1);
    }
    
    #[test]
    fn test_add_note_duplicate_id() {
        use crate::secret::Secret;
        let mut manager = NoteManager::new();
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let note = create_note(1000, secret.clone()).unwrap();
        
        manager.add_note("note1".to_string(), note.clone()).unwrap();
        let result = manager.add_note("note1".to_string(), note);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_get_note() {
        use crate::secret::Secret;
        let mut manager = NoteManager::new();
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let note = create_note(1000, secret).unwrap();
        
        manager.add_note("note1".to_string(), note).unwrap();
        let entry = manager.get_note("note1").unwrap();
        assert_eq!(entry.note.value, 1000);
        assert_eq!(entry.state, NoteState::Unspent);
    }
    
    #[test]
    fn test_generate_nullifier_for_note() {
        use crate::secret::Secret;
        let mut manager = NoteManager::new();
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let note = create_note(1000, secret.clone()).unwrap();
        
        manager.add_note("note1".to_string(), note).unwrap();
        let nullifier = manager.generate_nullifier_for_note("note1", secret.into_inner()).unwrap();
        assert_eq!(nullifier.len(), 32);
        
        let entry = manager.get_note("note1").unwrap();
        assert!(entry.nullifier.is_some());
    }
    
    #[test]
    fn test_mark_note_as_spent() {
        use crate::secret::Secret;
        let mut manager = NoteManager::new();
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let note = create_note(1000, secret.clone()).unwrap();
        
        manager.add_note("note1".to_string(), note).unwrap();
        manager.generate_nullifier_for_note("note1", secret.into_inner()).unwrap();
        manager.mark_note_as_spent("note1").unwrap();
        
        let entry = manager.get_note("note1").unwrap();
        assert_eq!(entry.state, NoteState::Spent);
        assert_eq!(manager.spent_nullifier_count(), 1);
    }
    
    #[test]
    fn test_list_notes() {
        use crate::secret::Secret;
        let mut manager = NoteManager::new();
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        
        for i in 0..3 {
            let note = create_note(100 * (i + 1) as u64, secret.clone()).unwrap();
            manager.add_note(format!("note{}", i), note).unwrap();
        }
        
        let ids = manager.list_note_ids();
        assert_eq!(ids.len(), 3);
    }
}

