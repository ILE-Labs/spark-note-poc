//! Comprehensive error types for Spark Note operations
//!
//! This module provides detailed error types for all operations in the Spark Note SDK,
//! with proper error codes and user-friendly messages.

use serde::{Deserialize, Serialize};
// use thiserror::Error;

/// Comprehensive error types for Spark Note operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)] // uniffi::Error
pub enum SparkError {
    /// Secret validation errors
    #[error("Invalid secret: {message}")]
    InvalidSecret {
        /// Human-readable error message
        message: String,
        /// Error code for programmatic handling
        code: SecretErrorCode,
    },
    
    /// Value validation errors
    #[error("Invalid value: {message}")]
    InvalidValue {
        /// Human-readable error message
        message: String,
        /// Error code for programmatic handling
        code: ValueErrorCode,
    },
    
    /// Nullifier-related errors
    #[error("Nullifier error: {message}")]
    NullifierError {
        /// Human-readable error message
        message: String,
        /// Error code for programmatic handling
        code: NullifierErrorCode,
    },
    
    /// WASM initialization errors
    #[error("WASM initialization failed: {message}")]
    WASMInitializationError {
        /// Human-readable error message
        message: String,
    },
    
    /// Serialization/deserialization errors
    #[error("Serialization error: {message}")]
    SerializationError {
        /// Human-readable error message
        message: String,
    },
    
    /// General operation errors
    #[error("Operation failed: {message}")]
    OperationError {
        /// Human-readable error message
        message: String,
    },
    
    #[error("Proof error: {message}")]
    ProofError {
        /// Human-readable error message
        message: String,
    },
    
    /// Tezos blockchain errors
    #[error("Tezos error: {message}")]
    TezosError {
        /// Human-readable error message
        message: String,
    },
}

/// Error codes for secret validation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // uniffi::Enum
pub enum SecretErrorCode {
    /// Secret is empty
    Empty,
    /// Secret is too short
    TooShort,
    /// Secret is too long
    TooLong,
    /// Secret has invalid format
    InvalidFormat,
}

/// Error codes for value validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] // uniffi::Enum
pub enum ValueErrorCode {
    /// Value is zero
    Zero,
    /// Value exceeds maximum allowed
    ExceedsMax,
    /// Value is invalid
    Invalid,
}

/// Error codes for nullifier operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] // uniffi::Enum
pub enum NullifierErrorCode {
    /// Nullifier is already spent
    AlreadySpent,
    /// Nullifier has invalid format
    InvalidFormat,
    /// Nullifier is empty
    Empty,
    /// Nullifier has wrong length
    WrongLength,
}

impl SparkError {
    /// Get the error code as a string for programmatic handling
    pub fn error_code(&self) -> String {
        match self {
            SparkError::InvalidSecret { code, .. } => format!("SECRET_{:?}", code),
            SparkError::InvalidValue { code, .. } => format!("VALUE_{:?}", code),
            SparkError::NullifierError { code, .. } => format!("NULLIFIER_{:?}", code),
            SparkError::WASMInitializationError { .. } => "WASM_INIT_ERROR".to_string(),
            SparkError::SerializationError { .. } => "SERIALIZATION_ERROR".to_string(),
            SparkError::OperationError { .. } => "OPERATION_ERROR".to_string(),
            SparkError::ProofError { .. } => "PROOF_ERROR".to_string(),
            SparkError::TezosError { .. } => "TEZOS_ERROR".to_string(),
        }
    }
    
    /// Get a detailed error message with context
    pub fn detailed_message(&self) -> String {
        match self {
            SparkError::InvalidSecret { message, code } => {
                format!("Invalid secret (code: {:?}): {}", code, message)
            }
            SparkError::InvalidValue { message, code } => {
                format!("Invalid value (code: {:?}): {}", code, message)
            }
            SparkError::NullifierError { message, code } => {
                format!("Nullifier error (code: {:?}): {}", code, message)
            }
            SparkError::WASMInitializationError { message } => {
                format!("WASM initialization failed: {}", message)
            }
            SparkError::SerializationError { message } => {
                format!("Serialization error: {}", message)
            }
            SparkError::OperationError { message } => {
                format!("Operation failed: {}", message)
            }
            SparkError::ProofError { message } => {
                format!("Proof error: {}", message)
            }
            SparkError::TezosError { message } => {
                format!("Tezos error: {}", message)
            }
        }
    }
    
    /// Create an invalid secret error
    pub fn invalid_secret(code: SecretErrorCode, message: impl Into<String>) -> Self {
        SparkError::InvalidSecret {
            message: message.into(),
            code,
        }
    }
    
    /// Create an invalid value error
    pub fn invalid_value(code: ValueErrorCode, message: impl Into<String>) -> Self {
        SparkError::InvalidValue {
            message: message.into(),
            code,
        }
    }
    
    /// Create a nullifier error
    pub fn nullifier_error(code: NullifierErrorCode, message: impl Into<String>) -> Self {
        SparkError::NullifierError {
            message: message.into(),
            code,
        }
    }

    /// Create a proof error
    pub fn invalid_proof(message: impl Into<String>) -> Self {
        SparkError::ProofError {
            message: message.into(),
        }
    }

    /// Create a Tezos error
    pub fn tezos_error(message: impl Into<String>) -> Self {
        SparkError::TezosError {
            message: message.into(),
        }
    }
}

/// Result type alias for Spark operations
pub type SparkResult<T> = Result<T, SparkError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_codes() {
        let err = SparkError::invalid_secret(SecretErrorCode::Empty, "Secret cannot be empty");
        assert_eq!(err.error_code(), "SECRET_Empty");
        
        let err = SparkError::invalid_value(ValueErrorCode::Zero, "Value cannot be zero");
        assert_eq!(err.error_code(), "VALUE_Zero");
        
        let err = SparkError::nullifier_error(NullifierErrorCode::AlreadySpent, "Already spent");
        assert_eq!(err.error_code(), "NULLIFIER_AlreadySpent");
    }
    
    #[test]
    fn test_error_serialization() {
        let err = SparkError::invalid_secret(SecretErrorCode::TooShort, "Secret too short");
        let serialized = serde_json::to_string(&err).unwrap();
        let deserialized: SparkError = serde_json::from_str(&serialized).unwrap();
        assert_eq!(err.error_code(), deserialized.error_code());
    }
}

