//! Serialization and data format utilities
//!
//! This module provides functions for serializing and deserializing
//! Spark Note data structures with versioning support.

use std::collections::HashSet;
use serde::{Deserialize, Serialize};

use crate::error::{SparkError, SparkResult};
use crate::validation::validate_nullifier;

/// Current data format version
pub const CURRENT_VERSION: u32 = 1;

/// Versioned nullifier set for export/import
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct NullifierSetExport {
    /// Format version
    pub version: u32,
    /// Array of nullifiers (hex-encoded)
    pub nullifiers: Vec<String>,
}

/// Exports a nullifier set to JSON
///
/// # Arguments
/// * `spent_set` - The set of spent nullifiers
///
/// # Returns
/// JSON string representation
pub fn export_nullifier_set(spent_set: &HashSet<Vec<u8>>) -> SparkResult<String> {
    let nullifiers: Vec<String> = spent_set
        .iter()
        .map(|n| hex::encode(n))
        .collect();
    
    let export = NullifierSetExport {
        version: CURRENT_VERSION,
        nullifiers,
    };
    
    serde_json::to_string(&export)
        .map_err(|e| SparkError::SerializationError {
            message: format!("Failed to serialize nullifier set: {}", e),
        })
}

/// Imports a nullifier set from JSON
///
/// # Arguments
/// * `json` - JSON string representation
///
/// # Returns
/// * `Ok(HashSet<Vec<u8>>)` - The imported nullifier set
/// * `Err(SparkError)` if deserialization or validation fails
pub fn import_nullifier_set(json: &str) -> SparkResult<HashSet<Vec<u8>>> {
    let export: NullifierSetExport = serde_json::from_str(json)
        .map_err(|e| SparkError::SerializationError {
            message: format!("Failed to deserialize nullifier set: {}", e),
        })?;
    
    // Check version compatibility
    if export.version > CURRENT_VERSION {
        return Err(SparkError::SerializationError {
            message: format!(
                "Unsupported version: {} (current: {})",
                export.version, CURRENT_VERSION
            ),
        });
    }
    
    let mut spent_set = HashSet::new();
    
    for hex_nullifier in export.nullifiers {
        let nullifier = hex::decode(&hex_nullifier)
            .map_err(|e| SparkError::SerializationError {
                message: format!("Invalid hex encoding: {}", e),
            })?;
        
        validate_nullifier(&nullifier)?;
        spent_set.insert(nullifier);
    }
    
    Ok(spent_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_export_import_nullifier_set() {
        let mut spent_set = HashSet::new();
        spent_set.insert(vec![1; 32]);
        spent_set.insert(vec![2; 32]);
        spent_set.insert(vec![3; 32]);
        
        let json = export_nullifier_set(&spent_set).unwrap();
        let imported = import_nullifier_set(&json).unwrap();
        
        assert_eq!(spent_set.len(), imported.len());
        for nullifier in &spent_set {
            assert!(imported.contains(nullifier));
        }
    }
    
    #[test]
    fn test_import_invalid_json() {
        let result = import_nullifier_set("invalid json");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_import_invalid_hex() {
        let export = NullifierSetExport {
            version: 1,
            nullifiers: vec!["invalid hex".to_string()],
        };
        let json = serde_json::to_string(&export).unwrap();
        let result = import_nullifier_set(&json);
        assert!(result.is_err());
    }
}

