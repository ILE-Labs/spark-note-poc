//! Input validation utilities
//!
//! This module provides validation functions for secrets, values, and nullifiers
//! with comprehensive error reporting.

use crate::error::{SecretErrorCode, SparkError, ValueErrorCode};

/// Minimum secret length in bytes
pub const MIN_SECRET_LENGTH: usize = 8;
/// Maximum secret length in bytes (reasonable limit)
pub const MAX_SECRET_LENGTH: usize = 1024;
/// Expected nullifier length in bytes (BLAKE3 output)
pub const NULLIFIER_LENGTH: usize = 32;

/// Validates a secret byte array
///
/// # Arguments
/// * `secret` - The secret to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(SparkError)` if invalid
pub fn validate_secret(secret: &[u8]) -> Result<(), SparkError> {
    if secret.is_empty() {
        return Err(SparkError::invalid_secret(
            SecretErrorCode::Empty,
            "Secret cannot be empty",
        ));
    }
    
    if secret.len() < MIN_SECRET_LENGTH {
        return Err(SparkError::invalid_secret(
            SecretErrorCode::TooShort,
            format!("Secret must be at least {} bytes, got {}", MIN_SECRET_LENGTH, secret.len()),
        ));
    }
    
    if secret.len() > MAX_SECRET_LENGTH {
        return Err(SparkError::invalid_secret(
            SecretErrorCode::TooLong,
            format!("Secret must be at most {} bytes, got {}", MAX_SECRET_LENGTH, secret.len()),
        ));
    }
    
    Ok(())
}

/// Validates a note value
///
/// # Arguments
/// * `value` - The value to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(SparkError)` if invalid
pub fn validate_value(value: u64) -> Result<(), SparkError> {
    if value == 0 {
        return Err(SparkError::invalid_value(
            ValueErrorCode::Zero,
            "Value must be greater than zero",
        ));
    }
    
    // u64::MAX is the maximum, but we could add a reasonable upper limit if needed
    // For now, any non-zero u64 is valid
    
    Ok(())
}

/// Validates a nullifier byte array
///
/// # Arguments
/// * `nullifier` - The nullifier to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(SparkError)` if invalid
pub fn validate_nullifier(nullifier: &[u8]) -> Result<(), SparkError> {
    if nullifier.is_empty() {
        return Err(SparkError::nullifier_error(
            crate::error::NullifierErrorCode::Empty,
            "Nullifier cannot be empty",
        ));
    }
    
    if nullifier.len() != NULLIFIER_LENGTH {
        return Err(SparkError::nullifier_error(
            crate::error::NullifierErrorCode::WrongLength,
            format!("Nullifier must be exactly {} bytes, got {}", NULLIFIER_LENGTH, nullifier.len()),
        ));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_secret_empty() {
        assert!(validate_secret(&[]).is_err());
    }
    
    #[test]
    fn test_validate_secret_too_short() {
        let short = vec![1; MIN_SECRET_LENGTH - 1];
        assert!(validate_secret(&short).is_err());
    }
    
    #[test]
    fn test_validate_secret_valid() {
        let valid = vec![1; MIN_SECRET_LENGTH];
        assert!(validate_secret(&valid).is_ok());
    }
    
    #[test]
    fn test_validate_secret_too_long() {
        let long = vec![1; MAX_SECRET_LENGTH + 1];
        assert!(validate_secret(&long).is_err());
    }
    
    #[test]
    fn test_validate_value_zero() {
        assert!(validate_value(0).is_err());
    }
    
    #[test]
    fn test_validate_value_valid() {
        assert!(validate_value(1).is_ok());
        assert!(validate_value(u64::MAX).is_ok());
    }
    
    #[test]
    fn test_validate_nullifier_empty() {
        assert!(validate_nullifier(&[]).is_err());
    }
    
    #[test]
    fn test_validate_nullifier_wrong_length() {
        let wrong = vec![1; NULLIFIER_LENGTH - 1];
        assert!(validate_nullifier(&wrong).is_err());
    }
    
    #[test]
    fn test_validate_nullifier_valid() {
        let valid = vec![1; NULLIFIER_LENGTH];
        assert!(validate_nullifier(&valid).is_ok());
    }
}

