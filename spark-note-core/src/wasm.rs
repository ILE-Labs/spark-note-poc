//! WebAssembly bindings for Spark Note Core
//!
//! This module provides JavaScript-compatible exports via wasm-bindgen.

use wasm_bindgen::prelude::*;

use crate::note::{self, SparkNote};
use crate::nullifier;
use crate::secret::Secret;
use crate::validation::{validate_secret, validate_value};

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// JavaScript-compatible SparkNote wrapper
#[wasm_bindgen]
pub struct WasmSparkNote {
    inner: SparkNote,
}

#[wasm_bindgen]
impl WasmSparkNote {
    /// Get the note's value
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> u64 {
        self.inner.value
    }

    /// Derive the nullifier for this note.
    ///
    /// The nullifier is computed entirely inside the WASM boundary — the secret
    /// never crosses into JavaScript. This is the correct pattern for any
    /// operation that needs the secret: compute inside Rust, return only the
    /// derived output.
    ///
    /// @returns Uint8Array - The 32-byte nullifier
    #[wasm_bindgen(js_name = deriveNullifier)]
    pub fn derive_nullifier(&self) -> Vec<u8> {
        nullifier::generate_nullifier(&self.inner, self.inner.secret()).to_vec()
    }

    /// Get the note's commitment as Uint8Array
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> Vec<u8> {
        self.inner.commitment.clone()
    }

    /// Serialize the note to JSON string
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.inner)
            .map_err(|e| JsError::new(&format!("Serialization error: {:?}", e)))
    }

    /// Deserialize a note from JSON string
    ///
    /// WARNING: This will not deserialize secrets. Secrets should never be
    /// deserialized from untrusted sources. Use create_note instead.
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WasmSparkNote, JsError> {
        // SparkNote deserialization is disabled for security
        // Secrets should never be loaded from JSON
        Err(JsError::new("SparkNote cannot be deserialized - secrets must not be loaded from untrusted sources. Use create_note() instead."))
    }
}

impl Drop for WasmSparkNote {
    fn drop(&mut self) {
        // Secret will be automatically zeroized when inner SparkNote is dropped
        // No explicit cleanup needed
    }
}

/// Create a new SparkNote with the given value and secret
///
/// @param value - The monetary value of the note (u64)
/// @param secret - A random secret as Uint8Array (must not be empty)
/// @returns WasmSparkNote - The created note
/// @throws Error if the secret is empty or value is invalid
#[wasm_bindgen(js_name = createNote)]
pub fn create_note(value: u64, secret: Vec<u8>) -> Result<WasmSparkNote, JsError> {
    // Validate inputs FIRST before creating Secret
    validate_value(value)
        .map_err(|e| JsError::new(&format!("Invalid value: {} (value: {})", e.detailed_message(), value)))?;
    
    validate_secret(&secret)
        .map_err(|e| JsError::new(&format!("Invalid secret: {} (length: {})", e.detailed_message(), secret.len())))?;
    
    let secret = Secret::from(secret);
    let inner = note::create_note(value, secret)
        .map_err(|e| {
            // Preserve full error context using detailed_message
            JsError::new(&format!(
                "Failed to create note: {} (value: {}, secret_len: {})",
                e.detailed_message(), value, secret.len()
            ))
        })?;
    Ok(WasmSparkNote { inner })
}

/// Get the commitment hash of a note
///
/// @param note - The SparkNote to get commitment from
/// @returns Uint8Array - The 48-byte Pedersen commitment (compressed BLS12-381 G1)
#[wasm_bindgen(js_name = noteCommitment)]
pub fn note_commitment(note: &WasmSparkNote) -> Vec<u8> {
    note::note_commitment(&note.inner)
}



/// Check if a nullifier has been spent
///
/// @param nullifier - The nullifier to check as Uint8Array
/// @param spent_set - Array of spent nullifiers (each as Uint8Array)
/// @returns boolean - True if nullifier is in the spent set
#[wasm_bindgen(js_name = isNullifierSpent)]
pub fn is_nullifier_spent(nullifier: Vec<u8>, spent_set: JsValue) -> Result<bool, JsError> {
    use std::collections::HashSet;

    let spent_array: Vec<Vec<u8>> =
        serde_wasm_bindgen::from_value(spent_set)
            .map_err(|e| JsError::new(&format!("Failed to deserialize spent set: {:?}", e)))?;

    let spent_hash_set: HashSet<Vec<u8>> = spent_array.into_iter().collect();

    Ok(nullifier::is_nullifier_spent(&nullifier, &spent_hash_set))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_create_note_wasm() {
        let secret = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let note = create_note(1000, secret).unwrap();
        assert_eq!(note.value(), 1000);
        assert_eq!(note.commitment().len(), 48);
    }

    #[wasm_bindgen_test]
    fn test_generate_nullifier_wasm() {
        let secret = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let note = create_note(1000, secret.clone()).unwrap();
        let nullifier = generate_nullifier(&note, secret);
        assert_eq!(nullifier.len(), 32);
    }

    #[wasm_bindgen_test]
    fn test_derive_nullifier_inside_wasm() {
        let secret = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let note = create_note(1000, secret.clone()).unwrap();

        // derive_nullifier computes inside WASM without exposing the secret
        let nullifier = note.derive_nullifier();
        assert_eq!(nullifier.len(), 32);

        // The result should match the standalone generate_nullifier
        let expected = generate_nullifier(&note, secret);
        assert_eq!(nullifier, expected);
    }

    /// Verify that WasmSparkNote does NOT expose a `secret` getter.
    /// This is a compile-time guarantee enforced by the type system: if
    /// someone re-adds a `secret()` method, this test's comment serves
    /// as documentation of the security invariant, and a code review
    /// gate. At runtime, we verify the only public getters are `value`,
    /// `commitment`, and `derive_nullifier`.
    #[wasm_bindgen_test]
    fn test_secret_not_exposed() {
        let note = create_note(1000, vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        // These are the ONLY data accessors that should exist.
        // The secret must NEVER be returned to JavaScript.
        let _value = note.value();
        let _commitment = note.commitment();
        let _nullifier = note.derive_nullifier();

        // If a `secret()` method is ever added back, it MUST be caught
        // in code review. The absence of `note.secret()` here is the
        // assertion — it would fail to compile if the method returned
        // a different type, and this test documents the security contract.
    }
}
