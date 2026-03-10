//! Spark Note Core Library
//!
//! This crate provides the core functionality for the Spark note management SDK,
//! including note creation, commitment generation, and nullifier operations.
//!
//! # Overview
//!
//! The library implements a simplified proof-of-concept demonstrating:
//! - Note creation with cryptographic commitments
//! - Nullifier generation for spent tracking
//! - Commitment verification
//!
//! # Example
//!
//! ```rust
//! use spark_note_core::note::{create_note, note_commitment};
//! use spark_note_core::nullifier::{generate_nullifier, is_nullifier_spent};
//! use spark_note_core::secret::Secret;
//! use std::collections::HashSet;
//!
//! // Create a new note
//! let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
//! let note = create_note(1000, secret.clone()).unwrap();
//!
//! // Get the Pedersen commitment (48-byte compressed BLS12-381 G1 point)
//! let commitment = note_commitment(&note);
//!
//! // Generate a nullifier for spending
//! let nullifier = generate_nullifier(&note, &secret);
//!
//! // Check if spent
//! let spent_set: HashSet<Vec<u8>> = HashSet::new();
//! assert!(!is_nullifier_spent(nullifier.as_bytes(), &spent_set));
//! ```
//!
//! # Modules
//!
//! - [`note`] - Spark note structure and creation
//! - [`nullifier`] - Nullifier generation and spent tracking

pub mod error;
pub mod manager;
pub mod note;
pub mod nullifier;
pub mod nullifier_type;
pub mod secret;
pub mod serialization;
pub mod validation;
pub mod rng;
pub mod crypto;
pub mod tezos;

// WASM bindings (enabled with --features wasm)
#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export commonly used types for convenience
pub use error::{SparkError, SparkResult};
pub use manager::{NoteEntry, NoteManager, NoteState, PublicNote};
pub use note::{create_note, note_commitment, SparkNote};
pub use nullifier::{
    check_multiple_nullifiers, generate_nullifier, get_nullifier_set_size,
    get_nullifier_set_stats, is_nullifier_spent, mark_as_spent, mark_multiple_as_spent,
    NullifierSetStats,
};
pub use serialization::{export_nullifier_set, import_nullifier_set, NullifierSetExport};
pub use validation::{validate_nullifier, validate_secret, validate_value};
pub use tezos::{TezosClient, TezosOperationResult};

// UniFFI setup for native bindings
uniffi::setup_scaffolding!();

use crate::secret::Secret;

/// UniFFI-exported function to create a PublicNote (without secret)
#[uniffi::export]
pub fn uniffi_create_note(value: u64, secret: Vec<u8>) -> Result<PublicNote, SparkError> {
    let note = create_note(value, Secret::from(secret))?;
    Ok(PublicNote::from(&note))
}

/// UniFFI-exported function to get note commitment  
#[uniffi::export]
pub fn uniffi_note_commitment(note: &PublicNote) -> Vec<u8> {
    note.commitment.clone()
}

/// UniFFI-exported function to generate nullifier
/// Note: This requires the original secret, which should be provided separately
#[uniffi::export]
pub fn uniffi_generate_nullifier(note: &PublicNote, secret: Vec<u8>) -> Result<Vec<u8>, SparkError> {
    // Reconstruct note temporarily for nullifier generation
    let secret = Secret::from(secret);
    let temp_note = create_note(note.value, secret.clone())?;
    
    // Verify commitment matches
    if !crate::crypto::constant_time_eq(&temp_note.commitment, &note.commitment) {
        return Err(SparkError::OperationError {
            message: "Commitment mismatch - invalid secret".to_string(),
        });
    }
    
    Ok(generate_nullifier(&temp_note, &secret).to_vec())
}


/// UniFFI-exported function to verify a spending proof.
/// Returns true if the proof is valid for the given root and nullifier.
#[uniffi::export]
pub fn uniffi_verify_spending_proof(
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    merkle_root: Vec<u8>,
    nullifier: Vec<u8>,
) -> Result<bool, SparkError> {
    use crate::crypto::{SpendingProof, Groth16VerifyingKey};
    use ark_serialize::CanonicalDeserialize;
    
    let vk = Groth16VerifyingKey::deserialize_compressed(&vk_bytes[..])
        .map_err(|e| SparkError::invalid_proof(format!("Invalid VK: {}", e)))?;
    let proof = SpendingProof::from_bytes(&proof_bytes)?;
    
    crate::crypto::verify_spending_proof(&vk, &proof, &merkle_root, &nullifier)
}

/// UniFFI-exported function to get the default verifying key for the spending circuit.
/// In a production system, this would be a fixed value from a trusted setup.
#[uniffi::export]
pub fn uniffi_get_spending_vk() -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let (_pk, vk) = crate::crypto::setup_spending_snark();
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf).unwrap();
    buf
}


#[cfg(test)]
#[path = "note_prop_test.rs"]
mod note_prop_test;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use std::collections::HashSet;

    #[test]
    fn test_integration_workflow() {
        use crate::secret::Secret;
        // Create a note with some value
        let secret = Secret::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let value = 1000u64;

        let note = create_note(value, secret.clone()).expect("Failed to create note");

        // Verify the note was created correctly
        assert_eq!(note.value, value);
        assert_eq!(note.secret_bytes(), secret.as_bytes());
        assert!(!note.commitment.is_empty());

        // Get the commitment
        let commitment = note_commitment(&note);
        assert_eq!(commitment, note.commitment);

        // Generate nullifier for spending
        let nullifier = generate_nullifier(&note, &secret);
        assert_eq!(nullifier.as_bytes().len(), 32);

        // Track spent nullifiers
        let mut spent_set: HashSet<Vec<u8>> = HashSet::new();

        // Initially not spent
        assert!(!is_nullifier_spent(nullifier.as_bytes(), &spent_set));

        // Mark as spent
        spent_set.insert(nullifier.to_vec());

        // Now it should be marked as spent
        assert!(is_nullifier_spent(nullifier.as_bytes(), &spent_set));
    }

    #[test]
    fn test_multiple_notes_unique_nullifiers() {
        use crate::secret::Secret;
        let notes: Vec<_> = (0..5)
            .map(|i| {
                let secret = Secret::new(vec![i as u8; 16]);
                create_note(100 * (i + 1) as u64, secret).unwrap()
            })
            .collect();

        let nullifiers: Vec<_> = notes
            .iter()
            .enumerate()
            .map(|(i, note)| {
                let secret = Secret::new(vec![i as u8; 16]);
                generate_nullifier(note, &secret).to_vec()
            })
            .collect();

        // All nullifiers should be unique
        let unique_nullifiers: HashSet<_> = nullifiers.iter().collect();
        assert_eq!(unique_nullifiers.len(), nullifiers.len());
    }

    #[test]
    fn test_uniffi_exports() {
        let secret = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let note = uniffi_create_note(1000, secret.clone()).unwrap();
        let commitment = uniffi_note_commitment(&note);
        let nullifier = uniffi_generate_nullifier(&note, secret).unwrap();

        assert_eq!(commitment.len(), 48);
        assert_eq!(nullifier.len(), 32);
    }
}
