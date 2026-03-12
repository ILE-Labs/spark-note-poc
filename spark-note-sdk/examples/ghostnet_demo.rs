use spark_note_sdk::{NoteManager, create_note};
use spark_note_sdk::secret::Secret;
use spark_note_sdk::tezos::TezosClient;
// use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Spark Note Ghostnet Demo ---");

    // 1. Initialize NoteManager with a Tezos Client
    // In a real scenario, this would be a Ghostnet node and a deployed contract address
    let rpc_node = "https://rpc.ghostnet.teztnets.com";
    let contract_address = "KT1TezosDummyAddressForPOC";
    let tezos_client = TezosClient::new(rpc_node, contract_address);
    
    let mut manager = NoteManager::new().with_tezos_client(tezos_client);
    println!("Manager initialized with Tezos Client (RPC: {})", rpc_node);

    // 2. Create a new Spark Note
    let secret = Secret::new(vec![0, 1, 2, 3, 4, 5, 6, 7]);
    let value = 1000u64;
    let note = create_note(value, secret)?;
    let note_id = "demo_note_001";
    
    manager.add_note(note_id.to_string(), note)?;
    println!("Created note {} with value {} and commitment {}", 
        note_id, value, hex::encode(manager.get_note(note_id).unwrap().note.commitment));

    // 3. Simulate Deposit to Tezos
    println!("\nStep 3: Depositing note to Tezos Ghostnet...");
    let deposit_result = manager.sync_deposit_to_tezos(note_id, "edsk..._dummy_key").await?;
    println!("Deposit successful! Operation Hash: {}", deposit_result.operation_hash);

    // 4. Scan the blockchain for new notes (Simulation)
    println!("\nStep 4: Scanning blockchain for commitments...");
    let viewing_key = vec![0u8; 32];
    let found = manager.scan(&viewing_key).await?;
    println!("Scan complete. Discovered {} notes belonging to user.", found);

    // 5. Spend the note on Tezos
    println!("\nStep 5: Generating nullifier and spending note...");
    let secret_bytes = vec![0, 1, 2, 3, 4, 5, 6, 7];
    manager.generate_nullifier_for_note(note_id, secret_bytes)?;
    
    let spend_result = manager.sync_spend_to_tezos(note_id, "edsk..._dummy_key").await?;
    println!("Spend successful! Operation Hash: {}", spend_result.operation_hash);
    
    let final_entry = manager.get_note(note_id).unwrap();
    println!("Final Note State: {:?}", final_entry.state);

    println!("\n--- Demo Completed Successfully ---");
    Ok(())
}
