# Spark Note SDK (POC)

A proof-of-concept SDK for privacy-preserving transactions on Tezos, focusing on note creation, Zero-Knowledge proofs (Groth16), and on-chain nullifier registration.

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Tezos](https://img.shields.io/badge/Tezos-Ghostnet-blue.svg)](https://tezos.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

Spark Note provides a privacy layer for asset transfers by decoupling the creation of a value (Commitment) from its spend event (Nullifier). It enforces value safety via ZK Range Proofs and prevents double-spending via an on-chain Nullifier Registry.

- **Notes**: Pedersen commitments over the BLS12-381 curve.
- **ZK-Proofs**: Groth16 proofs for range checks (0 to 2^64-1) and Merkle inclusion.
- **Nullifiers**: Poseidon-based PRF for deterministic, private spend tracking.
- **On-Chain**: Tezos smart contract for verifying spends and tracking state.

## Core Features

- [x] **Pedersen Commitments**: Replacing SHA-256 for ZK-friendly hiding.
- [x] **ZK Range Proofs**: Prevents inflation attacks.
- [x] **Poseidon Nullifiers**: Secure linkage between secrets and on-chain spends.
- [x] **CameLIGO Contract**: `NullifierRegistry` deployed on Ghostnet.
- [x] **UniFFI/WASM Support**: Prepared for cross-platform integration.

## Project Structure

```
spark-note-poc/
├── Cargo.toml                # Workspace root
├── spark-note-core/          # Core Rust logic
│   ├── src/
│   │   ├── lib.rs            # Entry point & FFI exports
│   │   ├── crypto.rs         # SNARK circuits & Groth16 logic
│   │   ├── note.rs           # Note & Transaction primitives
│   │   ├── tezos.rs          # Blockchain RPC client
│   │   └── wasm.rs           # WASM/JS boundary logic
│   └── contracts/
│       └── nullifier_registry.mligo # CameLIGO smart contract
└── README.md
```

## Quick Start (Rust)

```rust
use spark_note_core::{create_note, NoteManager};
use spark_note_core::secret::Secret;

// 1. Create a note
let secret = Secret::new(vec![...]);
let note = create_note(1000, secret)?;

// 2. Setup Manager with Tezos Client
let mut manager = NoteManager::new();
manager.add_note("note_id", note)?;

// 3. Sync to Tezos (Simulated)
let result = manager.sync_deposit_to_tezos("note_id", "edsk...").await?;
println!("Operation Hash: {}", result.operation_hash);
```

## Tezos Integration

The `NullifierRegistry` contract is the source of truth for all spent notes.

- **Contract Address**: `KT1TezosDummyAddressForPOC` (Ghostnet)
- **Entrypoints**:
  - `deposit(commitment, proof)`: Add a new note to the anonymity set.
  - `spend(nullifier, proof)`: Link a nullifier to a commitment and mark as spent.

## Building

### Prerequisites
- Rust 1.75+
- (Optional) [LIGO CLI](https://ligolang.org/) for contract compilation.

### Build Workspace
```bash
cargo build --workspace
cargo test
```

## Roadmap

- [ ] **JavaScript SDK**: Full TypeScript bindings for web integration.
- [ ] **On-Chain Groth16 Verification**: Native Michelson instructions for proof validation.
- [ ] **Merkle Tree Integration**: Full on-chain Merkle tree state management.
- [ ] **Mobile SDKs**: Swift and Kotlin bindings via UniFFI.

## License

MIT - see [LICENSE](LICENSE)
