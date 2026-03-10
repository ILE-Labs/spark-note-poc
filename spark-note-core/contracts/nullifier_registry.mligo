type storage = {
  nullifiers : bytes set;
  commitments : bytes set;
  vk_hash : bytes;
}

type return = operation list * storage

type parameter =
  | Deposit of (bytes * bytes) // commitment, proof
  | Spend of (bytes * bytes)   // nullifier, proof

let deposit (commitment, _proof : bytes * bytes) (s : storage) : return =
  if Set.mem commitment s.commitments then
    (failwith "Commitment already exists" : return)
  else
    let s = { s with commitments = Set.add commitment s.commitments } in
    (([] : operation list), s)

let spend (nullifier, _proof : bytes * bytes) (s : storage) : return =
  if Set.mem nullifier s.nullifiers then
    (failwith "Nullifier already spent" : return)
  else
    let s = { s with nullifiers = Set.add nullifier s.nullifiers } in
    (([] : operation list), s)

let main (p, s : parameter * storage) : return =
  match p with
  | Deposit args -> deposit args s
  | Spend args -> spend args s
