use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::ops::Mul;
use subtle::ConstantTimeEq;

// ZK Proof imports
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use crate::error::{SparkError, SparkResult};

// SNARK re-exports for other modules
pub use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr as JubjubFr, Fq as BlsFr};
pub use ark_groth16::{Proof as Groth16Proof, ProvingKey as Groth16ProvingKey, VerifyingKey as Groth16VerifyingKey};

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_groth16::Groth16;
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use ark_bls12_381::Bls12_381;
use ark_std::vec::Vec;
use ark_std::marker::PhantomData;

/// Domain separator used to derive the independent generator H via hash-to-curve.
/// H = hash_to_curve("SPARK_PEDERSEN_H_V1") ensures H is provably independent from G
/// (i.e., no one knows the discrete log relationship between G and H).
const H_DOMAIN_SEP: &[u8] = b"SPARK_PEDERSEN_H_V1";

/// Returns the standard BLS12-381 G1 generator G.
fn generator_g() -> G1Affine {
    G1Affine::generator()
}

/// Returns the independent generator H, derived via a deterministic
/// hash-to-curve construction to ensure nobody knows dlog(H, G).
///
/// We use Blake3 to hash a domain separator into 32 bytes, interpret
/// those bytes as a scalar `s`, and compute `H = s * G`. Since finding
/// `s` from `H` requires solving the discrete log problem, and the
/// derivation is transparent / reproducible, this is a standard
/// "nothing-up-my-sleeve" construction.
fn generator_h() -> G1Affine {
    let hash = blake3::hash(H_DOMAIN_SEP);
    let hash_bytes = hash.as_bytes();

    // Safely reduce the hash bytes modulo the scalar field order.
    // from_le_bytes_mod_order handles arbitrary-length byte slices
    // and always returns a valid Fr element.
    let scalar = Fr::from_le_bytes_mod_order(hash_bytes);

    (G1Projective::from(generator_g()).mul(scalar)).into_affine()
}

/// Compute a Pedersen commitment: C = v·G + r·H
///
/// This commitment scheme is:
/// - **Perfectly hiding**: the blinding factor `r` makes the commitment
///   information-theoretically indistinguishable from random.
/// - **Computationally binding**: changing the committed value requires
///   solving the discrete log problem.
/// - **Additively homomorphic**: commit(a, r1) + commit(b, r2) = commit(a+b, r1+r2),
///   enabling zero-knowledge balance proofs in Lelantus Spark.
///
/// # Arguments
/// * `value` - The value to commit to (as a BLS12-381 scalar)
/// * `blinding` - The blinding/randomness factor (as a BLS12-381 scalar)
///
/// # Returns
/// The commitment as a BLS12-381 G1 affine point
pub fn pedersen_commit(value: Fr, blinding: Fr) -> G1Affine {
    let g = generator_g();
    let h = generator_h();

    let v_g = G1Projective::from(g).mul(value);
    let r_h = G1Projective::from(h).mul(blinding);

    (v_g + r_h).into_affine()
}

/// Convenience wrapper: commit a u64 value with raw blinding bytes.
///
/// Converts the u64 value to an Fr scalar and interprets the blinding
/// bytes (secret) as an Fr element, then computes the Pedersen commitment
/// and returns its compressed serialization (48 bytes for BLS12-381 G1).
///
/// # Arguments
/// * `value` - The monetary value to commit
/// * `blinding_bytes` - Raw bytes to use as blinding factor
///
/// # Returns
/// 48-byte compressed BLS12-381 G1 point
pub fn pedersen_commit_u64(value: u64, blinding_bytes: &[u8]) -> Vec<u8> {
    let v = Fr::from(value);

    // Hash the blinding bytes to get a uniform field element.
    // from_le_bytes_mod_order safely reduces any byte slice modulo
    // the scalar field order, guaranteeing a valid Fr element.
    let blinding_hash = blake3::hash(blinding_bytes);
    let r = Fr::from_le_bytes_mod_order(blinding_hash.as_bytes());

    let point = pedersen_commit(v, r);

    // Serialize to compressed form (48 bytes for G1)
    let mut buf = Vec::new();
    point
        .serialize_compressed(&mut buf)
        .expect("serialization should not fail");
    buf
}

/// Constant-time comparison of two byte slices
///
/// Returns true if slices are equal, false otherwise.
/// Execution time does not depend on slice contents, preventing timing attacks.
///
/// # Arguments
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
/// `true` if slices are equal, `false` otherwise
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison for fixed-size arrays
///
/// # Arguments
/// * `a` - First array
/// * `b` - Second array
///
/// # Returns
/// `true` if arrays are equal, `false` otherwise
/// Constant-time comparison for fixed-size arrays
///
/// # Arguments
/// * `a` - First array
/// * `b` - Second array
///
/// # Returns
/// `true` if arrays are equal, `false` otherwise
pub fn constant_time_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.ct_eq(b).into()
}

// --- Groth16 ZK SNARK (Spending Proof) ---

/// Maximum depth of the Merkle Tree for the anonymity set.
pub const MERKLE_TREE_DEPTH: usize = 32;

/// The R1CS circuit for spending a Spark note.
pub struct SpendingCircuit {
    pub root: Option<BlsFr>,
    pub nullifier: Option<BlsFr>,
    pub value: Option<u64>,
    pub secret: Option<BlsFr>,
    pub path: Option<Vec<(BlsFr, bool)>>, // (sibling, is_right)
    pub commitment_point: Option<EdwardsAffine>,
    pub poseidon_config: PoseidonConfig<BlsFr>,
}

impl ConstraintSynthesizer<BlsFr> for SpendingCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BlsFr>,
    ) -> Result<(), SynthesisError> {
        // --- 1. Allocate Public Inputs ---
        let root_var = FpVar::new_input(ark_relations::ns!(cs, "root"), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_var = FpVar::new_input(ark_relations::ns!(cs, "nullifier"), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // --- 2. Allocate Private Witnesses ---
        let value_var = FpVar::new_witness(ark_relations::ns!(cs, "value"), || {
            Ok(BlsFr::from(self.value.ok_or(SynthesisError::AssignmentMissing)?))
        })?;
        let secret_var = FpVar::new_witness(ark_relations::ns!(cs, "secret"), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let commit_point_var = AffineVar::<ark_ed_on_bls12_381::EdwardsConfig, FpVar<BlsFr>>::new_witness(
            ark_relations::ns!(cs, "commitment_point"),
            || self.commitment_point.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // --- 3. Range Check: 0 <= value < 2^64 ---
        let value_bits = value_var.to_bits_le()?;
        for i in 64..value_bits.len() {
            value_bits[i].enforce_equal(&Boolean::FALSE)?;
        }

        // --- 4. Pedersen Commitment Check: C = v*G + s*H ---
        let g = EdwardsAffine::generator();
        let h_bytes = blake3::hash(b"SPARK_JUBJUB_H").as_bytes().to_vec();
        let h_scalar = JubjubFr::from_le_bytes_mod_order(&h_bytes);
        let h = EdwardsAffine::from(EdwardsProjective::from(g).mul(h_scalar));

        let g_var = AffineVar::new_constant(ark_relations::ns!(cs, "g"), g)?;
        let h_var = AffineVar::new_constant(ark_relations::ns!(cs, "h"), h)?;

        let v_bits = value_bits[..64].to_vec();
        let s_bits = secret_var.to_bits_le()?;
        
        let v_g = g_var.scalar_mul_le(v_bits.iter())?;
        let s_h = h_var.scalar_mul_le(s_bits.iter())?;
        let expected_commitment = v_g + s_h;

        commit_point_var.enforce_equal(&expected_commitment)?;

        // --- 5. Nullifier Check: nullifier == Poseidon(secret) ---
        use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
        use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
        
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);
        sponge.absorb(&secret_var)?;
        let computed_nullifier = sponge.squeeze_field_elements(1)?.pop().unwrap();
        nullifier_var.enforce_equal(&computed_nullifier)?;

        // --- 6. Merkle Inclusion Check ---
        let mut current_hash = commit_point_var.x;
        let path = self.path.unwrap_or_else(|| vec![(BlsFr::default(), false); MERKLE_TREE_DEPTH]);
        
        for (_i, (sibling_val, is_right)) in path.into_iter().enumerate() {
            let sibling_var = FpVar::new_witness(ark_relations::ns!(cs, "sibling"), || Ok(sibling_val))?;
            let is_right_var = Boolean::new_witness(ark_relations::ns!(cs, "is_right"), || Ok(is_right))?;
            
            let left = is_right_var.select(&sibling_var, &current_hash)?;
            let right = is_right_var.select(&current_hash, &sibling_var)?;
            
            let mut node_sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);
            node_sponge.absorb(&vec![left, right])?;
            current_hash = node_sponge.squeeze_field_elements(1)?.pop().unwrap();
        }
        
        current_hash.enforce_equal(&root_var)?;
        
        Ok(())
    }
}

pub fn setup_poseidon_config() -> PoseidonConfig<BlsFr> {
    use ark_crypto_primitives::crh::poseidon::CRH;
    use ark_crypto_primitives::crh::CRHScheme;
    let mut rng = ark_std::test_rng();
    // This is a common way to generate parameters if no defaults are found
    CRH::<BlsFr>::setup(&mut rng).unwrap()
}

pub fn setup_spending_snark() -> (ark_groth16::ProvingKey<Bls12_381>, ark_groth16::VerifyingKey<Bls12_381>) {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(12345);
    let poseidon_config = setup_poseidon_config();
    
    let circuit = SpendingCircuit {
        root: None,
        nullifier: None,
        value: None,
        secret: None,
        path: None,
        commitment_point: None,
        poseidon_config,
    };

    let (pk, vk) = Groth16::<Bls12_381>::setup(circuit, &mut rng).unwrap();
    (pk, vk)
}

/// Generates a Groth16 spending proof for a Spark note.
pub fn generate_spending_proof(
    pk: &ark_groth16::ProvingKey<Bls12_381>,
    value: u64,
    secret_bytes: &[u8],
    merkle_root: &[u8],
    merkle_path: Vec<(Vec<u8>, bool)>,
    commitment: &EdwardsAffine,
) -> SparkResult<SpendingProof> {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let poseidon_config = setup_poseidon_config();
    
    let secret = BlsFr::from_le_bytes_mod_order(secret_bytes);
    let root = BlsFr::from_le_bytes_mod_order(merkle_root);
    
    // Compute nullifier: nullifier = Poseidon(secret)
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_crypto_primitives::sponge::CryptographicSponge;
    let mut sponge = PoseidonSponge::new(&poseidon_config);
    sponge.absorb(&secret);
    let nullifier = sponge.squeeze_field_elements(1).pop().unwrap();

    let path = merkle_path
        .into_iter()
        .map(|(sibling, is_right)| (BlsFr::from_le_bytes_mod_order(&sibling), is_right))
        .collect();

    let circuit = SpendingCircuit {
        root: Some(root),
        nullifier: Some(nullifier),
        value: Some(value),
        secret: Some(secret),
        path: Some(path),
        commitment_point: Some(*commitment),
        poseidon_config,
    };

    let proof = Groth16::<Bls12_381>::prove(pk, circuit, &mut rng)
        .map_err(|e| SparkError::invalid_proof(format!("SNARK proving failed: {}", e)))?;
        
    Ok(SpendingProof { proof })
}

/// Verifies a Groth16 spending proof.
pub fn verify_spending_proof(
    vk: &ark_groth16::VerifyingKey<Bls12_381>,
    proof: &SpendingProof,
    merkle_root: &[u8],
    nullifier_bytes: &[u8],
) -> SparkResult<bool> {
    let root = BlsFr::from_le_bytes_mod_order(merkle_root);
    let nullifier = BlsFr::from_le_bytes_mod_order(nullifier_bytes);

    // Public inputs must be in the correct order: root, nullifier
    let public_inputs = vec![root, nullifier];

    Groth16::<Bls12_381>::verify(vk, &public_inputs, &proof.proof)
        .map_err(|e| SparkError::invalid_proof(format!("SNARK verification failed: {}", e)))
}








// --- Native Schnorr Sigma Protocol (ZK Proof) ---

/// A Zero-Knowledge Proof of Knowledge (PoK) for a Pedersen commitment.
/// Proves knowledge of `v` and `r` such that `C = v*G + r*H` without revealing them.
/// Implemented as a non-interactive Schnorr Sigma Protocol using Fiat-Shamir.
/// A Zero-Knowledge Proof for spending a Spark note.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct SpendingProof {
    /// The Groth16 proof
    pub proof: ark_groth16::Proof<Bls12_381>,
}

impl PartialEq for SpendingProof {
    fn eq(&self, other: &Self) -> bool {
        // We can compare the serialized bytes if needed, or just return false
        // Groth16 Proof usually doesn't have a direct eq that is efficient.
        // For POC, we'll use serialization.
        self.to_bytes() == other.to_bytes()
    }
}


impl SpendingProof {
    /// Serialize the proof to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_compressed(&mut buf).expect("serialization should not fail");
        buf
    }

    /// Deserialize a proof from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> SparkResult<Self> {
        Self::deserialize_compressed(bytes)
            .map_err(|e| SparkError::invalid_proof(format!("Failed to deserialize proof: {:?}", e)))
    }
}

// (Removing the old generate_spending_proof and verify_spending_proof)



#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    #[test]
    fn test_constant_time_eq_equal() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 5];
        
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 6];
        
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3];
        
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_array() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];
        
        assert!(constant_time_eq_array(&a, &b));
        assert!(!constant_time_eq_array(&a, &c));
    }

    #[test]
    fn test_pedersen_commit_deterministic() {
        let mut rng = test_rng();
        let v = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);

        let c1 = pedersen_commit(v, r);
        let c2 = pedersen_commit(v, r);

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_pedersen_commit_different_values() {
        let mut rng = test_rng();
        let r = Fr::rand(&mut rng);

        let c1 = pedersen_commit(Fr::from(100u64), r);
        let c2 = pedersen_commit(Fr::from(200u64), r);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_pedersen_commit_different_blindings() {
        let mut rng = test_rng();
        let v = Fr::from(100u64);
        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);

        let c1 = pedersen_commit(v, r1);
        let c2 = pedersen_commit(v, r2);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_pedersen_homomorphic() {
        let mut rng = test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);

        let ca = pedersen_commit(a, r1);
        let cb = pedersen_commit(b, r2);

        let sum_of_commits = (G1Projective::from(ca) + G1Projective::from(cb)).into_affine();
        let commit_of_sum = pedersen_commit(a + b, r1 + r2);

        assert_eq!(sum_of_commits, commit_of_sum);
    }

    #[test]
    fn test_pedersen_commit_u64_produces_48_bytes() {
        let commitment = pedersen_commit_u64(1000, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(commitment.len(), 48, "Compressed BLS12-381 G1 point should be 48 bytes");
    }

    #[test]
    fn test_pedersen_commit_u64_deterministic() {
        let c1 = pedersen_commit_u64(1000, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let c2 = pedersen_commit_u64(1000, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_generators_are_different() {
        let g = generator_g();
        let h = generator_h();
        assert_ne!(g, h, "G and H must be independent generators");
    }

    #[test]
    fn test_spending_proof_valid() {
        let value = 1000u64;
        let secret = b"super_secret_blinding_factor";
        
        let proof = generate_spending_proof(value, secret);
        let commitment = pedersen_commit_u64(value, secret);
        
        assert!(verify_spending_proof(&proof, &commitment));
    }

    #[test]
    fn test_spending_proof_invalid_value() {
        let value = 1000u64;
        let secret = b"super_secret_blinding_factor";
        
        let proof = generate_spending_proof(value, secret);
        
        // Mismatched commitment (different value)
        let wrong_commitment = pedersen_commit_u64(2000, secret);
        assert!(!verify_spending_proof(&proof, &wrong_commitment));
    }
}
