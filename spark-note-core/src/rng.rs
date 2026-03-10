//! Cryptographically secure random number generation
//!
//! This module provides utilities for generating cryptographically
//! secure random bytes using the `getrandom` crate.

use getrandom::getrandom;
use crate::error::{SparkError, SparkResult};
use crate::secret::Secret;

/// Generate cryptographically secure random bytes
///
/// # Arguments
/// * `len` - Number of bytes to generate
///
/// # Returns
/// * `Ok(Vec<u8>)` - Random bytes
/// * `Err(SparkError)` - If random generation fails
pub fn generate_random_bytes(len: usize) -> SparkResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom(&mut bytes)
        .map_err(|e| SparkError::OperationError {
            message: format!("Failed to generate random bytes: {}", e),
        })?;
    Ok(bytes)
}

/// Generate a secret for a Spark note (32 bytes by default)
///
/// # Returns
/// * `Ok(Secret)` - A new secret
/// * `Err(SparkError)` - If random generation fails
pub fn generate_secret() -> SparkResult<Secret> {
    generate_secret_with_len(32)
}

/// Generate a secret with specified length
///
/// # Arguments
/// * `len` - Length of secret in bytes
///
/// # Returns
/// * `Ok(Secret)` - A new secret
/// * `Err(SparkError)` - If random generation fails
pub fn generate_secret_with_len(len: usize) -> SparkResult<Secret> {
    let bytes = generate_random_bytes(len)?;
    Ok(Secret::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes() {
        let bytes = generate_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_generate_secret() {
        let secret = generate_secret().unwrap();
        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_generate_secret_custom_length() {
        let secret = generate_secret_with_len(16).unwrap();
        assert_eq!(secret.len(), 16);
    }

    #[test]
    fn test_generate_secret_uniqueness() {
        let s1 = generate_secret().unwrap();
        let s2 = generate_secret().unwrap();
        
        // Secrets should be different (very high probability)
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }
}

