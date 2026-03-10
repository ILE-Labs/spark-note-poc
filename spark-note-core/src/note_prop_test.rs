#![cfg(not(target_arch = "wasm32"))]

//! Property-based tests for Spark Note operations
//!
//! These tests use proptest to verify cryptographic properties
//! across a wide range of inputs, catching edge cases that
//! unit tests might miss.

use proptest::prelude::*;
use crate::note::{SparkNote, create_note};
use crate::secret::Secret;
use crate::crypto::constant_time_eq;
use crate::nullifier::generate_nullifier;

proptest! {
    #[test]
    fn test_commitment_deterministic(
        value in 1u64..=1000000u64,
        secret_bytes in prop::collection::vec(8u8..=255u8, 16..=256)
    ) {
        let secret = Secret::new(secret_bytes.clone());
        
        // Same inputs should produce same commitment
        let note1 = create_note(value, secret.clone()).unwrap();
        let note2 = create_note(value, secret).unwrap();
        
        prop_assert!(constant_time_eq(&note1.commitment, &note2.commitment));
    }
    
    #[test]
    fn test_commitment_different_secrets_different_commitments(
        value in 1u64..=1000000u64,
        secret1_bytes in prop::collection::vec(8u8..=255u8, 16..=256),
        secret2_bytes in prop::collection::vec(8u8..=255u8, 16..=256)
    ) {
        // Skip if secrets are equal
        prop_assume!(secret1_bytes != secret2_bytes);
        
        let secret1 = Secret::new(secret1_bytes);
        let secret2 = Secret::new(secret2_bytes);
        
        let note1 = create_note(value, secret1).unwrap();
        let note2 = create_note(value, secret2).unwrap();
        
        // Different secrets should produce different commitments
        prop_assert!(!constant_time_eq(&note1.commitment, &note2.commitment));
    }
    
    #[test]
    fn test_commitment_binding(
        value in 1u64..=1000000u64,
        secret_bytes in prop::collection::vec(8u8..=255u8, 16..=256)
    ) {
        let secret = Secret::new(secret_bytes);
        let note = create_note(value, secret).unwrap();
        
        // Commitment should always be 48 bytes (compressed BLS12-381 G1 point)
        prop_assert_eq!(note.commitment.len(), 48);
        
        // Commitment should not be all zeros (extremely unlikely)
        let all_zeros = note.commitment.iter().all(|&b| b == 0);
        prop_assert!(!all_zeros);
    }
    
    #[test]
    fn test_commitment_different_values_different_commitments(
        value1 in 1u64..=1000000u64,
        value2 in 1u64..=1000000u64,
        secret_bytes in prop::collection::vec(8u8..=255u8, 16..=256)
    ) {
        // Skip if values are equal
        prop_assume!(value1 != value2);
        
        let secret = Secret::new(secret_bytes);
        
        let note1 = create_note(value1, secret.clone()).unwrap();
        let note2 = create_note(value2, secret).unwrap();
        
        // Different values should produce different commitments
        prop_assert!(!constant_time_eq(&note1.commitment, &note2.commitment));
    }
    
    #[test]
    fn test_nullifier_generation_deterministic(
        value in 1u64..=1000000u64,
        secret_bytes in prop::collection::vec(8u8..=255u8, 16..=256)
    ) {
        let secret = Secret::new(secret_bytes);
        let note = create_note(value, secret.clone()).unwrap();
        
        let nullifier1 = generate_nullifier(&note, &secret);
        let nullifier2 = generate_nullifier(&note, &secret);
        
        // Same note and secret should produce same nullifier
        prop_assert!(constant_time_eq(nullifier1.as_bytes(), nullifier2.as_bytes()));
        
        // Nullifier should always be 32 bytes
        prop_assert_eq!(nullifier1.as_bytes().len(), 32);
    }
    
    #[test]
    fn test_nullifier_different_secrets_different_nullifiers(
        value in 1u64..=1000000u64,
        secret1_bytes in prop::collection::vec(8u8..=255u8, 16..=256),
        secret2_bytes in prop::collection::vec(8u8..=255u8, 16..=256)
    ) {
        // Skip if secrets are equal
        prop_assume!(secret1_bytes != secret2_bytes);
        
        let secret1 = Secret::new(secret1_bytes);
        let secret2 = Secret::new(secret2_bytes);
        let note = create_note(value, secret1.clone()).unwrap();
        
        let nullifier1 = generate_nullifier(&note, &secret1);
        let nullifier2 = generate_nullifier(&note, &secret2);
        
        // Different secrets should produce different nullifiers
        prop_assert!(!constant_time_eq(nullifier1.as_bytes(), nullifier2.as_bytes()));
    }
}

