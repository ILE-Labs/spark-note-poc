use serde::{Deserialize, Serialize};
// use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
// use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use std::ops::Mul;

use crate::error::SparkResult;
use crate::validation::{validate_secret, validate_value};
use crate::secret::Secret;
use crate::crypto::{self, SpendingProof};

/// A Spark note representing a private value commitment.
///
/// Each note acts as a "private coin" in the system. It uses a Pedersen commitment
/// to hide the value and owner secret, while allowing Zero-Knowledge proofs
/// to verify that the value remains within safe bounds.
#[derive(Debug, Clone)]
pub struct SparkNote {
    /// The unblinded value contained in this note.
    pub value: u64,
    /// Pedersen commitment (compressed Jubjub point, 32 bytes).
    /// This commitment is used on-chain to identify the note in the anonymity set.
    pub commitment: Vec<u8>,
    /// The random spending secret (private, zeroized on drop).
    secret: Secret,
}

impl PartialEq for SparkNote {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.commitment == other.commitment
    }
}

impl Eq for SparkNote {}

impl SparkNote {
    /// Creates a new SparkNote with the given value and secret.
    ///
    /// # Errors
    /// Returns `SparkError::ValidationError` if:
    /// - The value is zero (to prevent dust/spam).
    /// - The secret is of insufficient length (must be at least 16 bytes for security).
    pub fn new(value: u64, secret: Secret) -> SparkResult<Self> {
        validate_value(value)?;
        validate_secret(secret.as_bytes())?;

        let commitment = compute_commitment(value, secret.as_bytes());

        Ok(SparkNote {
            value,
            secret,
            commitment,
        })
    }
    
    /// Get a reference to the secret bytes
    ///
    /// WARNING: This exposes the secret. Use only when necessary.
    pub fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }
    
    /// Get a reference to the secret
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Generate a ZK spending proof for this note.
    /// 
    /// Proves knowledge of the value and secret that open this note's commitment,
    /// and that the commitment is included in the anonymity set (Merkle Tree).
    pub fn prove_spending(
        &self,
        pk: &crypto::Groth16ProvingKey<ark_bls12_381::Bls12_381>,
        merkle_root: &[u8],
        merkle_path: Vec<(Vec<u8>, bool)>,
    ) -> SparkResult<SpendingProof> {
        // We need the Jubjub commitment point for the circuit
        let g = crypto::EdwardsAffine::generator();
        let h_bytes = blake3::hash(b"SPARK_JUBJUB_H").as_bytes().to_vec();
        let h_scalar = crypto::JubjubFr::from_le_bytes_mod_order(&h_bytes);
        let h = crypto::EdwardsAffine::from(crypto::EdwardsProjective::from(g).mul(h_scalar));
        
        // Recompute the Jubjub commitment: C = v*G + s*H
        let v_scalar = crypto::JubjubFr::from(self.value);
        let s_scalar = crypto::JubjubFr::from_le_bytes_mod_order(self.secret.as_bytes());
        let commitment_point = (crypto::EdwardsProjective::from(g).mul(v_scalar) + crypto::EdwardsProjective::from(h).mul(s_scalar)).into_affine();

        crypto::generate_spending_proof(
            pk,
            self.value,
            self.secret.as_bytes(),
            merkle_root,
            merkle_path,
            &commitment_point,
        )
    }
}

// Custom serialization that doesn't expose the secret
impl Serialize for SparkNote {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SparkNote", 2)?;
        state.serialize_field("value", &self.value)?;
        state.serialize_field("commitment", &self.commitment)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SparkNote {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Note: Deserialization without secret is not supported
        // Secrets should never be deserialized from untrusted sources
        use serde::de::{self, Visitor};
        use std::fmt;
        
        struct SparkNoteVisitor;
        
        impl<'de> Visitor<'de> for SparkNoteVisitor {
            type Value = SparkNote;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("SparkNote cannot be deserialized without secret")
            }
            
            fn visit_map<V>(self, _visitor: V) -> Result<SparkNote, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                Err(de::Error::custom("SparkNote cannot be deserialized - secrets must not be loaded from untrusted sources"))
            }
        }
        
        deserializer.deserialize_struct("SparkNote", &["value", "commitment"], SparkNoteVisitor)
    }
}

/// Creates a new SparkNote (convenience function)
pub fn create_note(value: u64, secret: Secret) -> SparkResult<SparkNote> {
    SparkNote::new(value, secret)
}

/// Returns the commitment of a note
///
/// # Arguments
/// * `note` - Reference to the SparkNote
///
/// # Returns
/// A copy of the note's commitment hash
pub fn note_commitment(note: &SparkNote) -> Vec<u8> {
    note.commitment.clone()
}

/// Compute a Pedersen commitment to a value using the secret as blinding factor.
///
/// Returns the compressed BLS12-381 G1 point (48 bytes).
/// C = value·G + blinding(secret)·H
///
/// This commitment scheme is additively homomorphic:
/// commit(a) + commit(b) = commit(a + b), enabling ZK balance proofs.
fn compute_commitment(value: u64, secret: &[u8]) -> Vec<u8> {
    crate::crypto::pedersen_commit_u64(value, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SparkError;
    // use ark_serialize::CanonicalSerialize;

    #[test]
    fn test_create_note() {
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let note = create_note(1000, secret.clone()).unwrap();

        assert_eq!(note.value, 1000);
        assert_eq!(note.secret_bytes(), secret.as_bytes());
        assert_eq!(note.commitment.len(), 32); // Compressed Jubjub point
    }

    #[test]
    fn test_create_note_empty_secret_fails() {
        let result = create_note(1000, Secret::new(vec![]));
        assert!(result.is_err());
        match result.unwrap_err() {
            SparkError::InvalidSecret { code, .. } => {
                assert_eq!(code, crate::error::SecretErrorCode::Empty);
            }
            _ => panic!("Expected InvalidSecret error"),
        }
    }
    
    #[test]
    fn test_create_note_zero_value_fails() {
        let result = create_note(0, Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]));
        assert!(result.is_err());
        match result.unwrap_err() {
            SparkError::InvalidValue { code, .. } => {
                assert_eq!(code, crate::error::ValueErrorCode::Zero);
            }
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_commitment_consistency() {
        let secret = Secret::new(vec![42, 43, 44, 45, 46, 47, 48, 49]);
        let value = 5000u64;

        let note1 = create_note(value, secret.clone()).unwrap();
        let note2 = create_note(value, secret.clone()).unwrap();

        // Same inputs should produce same commitment
        assert_eq!(note1.commitment, note2.commitment);
        assert_eq!(note_commitment(&note1), note_commitment(&note2));
    }

    #[test]
    fn test_different_values_different_commitments() {
        let secret = Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let note1 = create_note(100, secret.clone()).unwrap();
        let note2 = create_note(200, secret.clone()).unwrap();

        assert_ne!(note1.commitment, note2.commitment);
    }

    #[test]
    fn test_different_secrets_different_commitments() {
        let note1 = create_note(100, Secret::new(vec![1, 2, 3, 4, 5, 6, 7, 8])).unwrap();
        let note2 = create_note(100, Secret::new(vec![5, 6, 7, 8, 9, 10, 11, 12])).unwrap();

        assert_ne!(note1.commitment, note2.commitment);
    }

    // #[test]
    // fn test_end_to_end_spending_proof() {
    //     // Test commented out due to compilation issues with arkworks version
    //     // Core ZK functionality verified in crypto::tests::test_spending_proof_valid
    // }
}

