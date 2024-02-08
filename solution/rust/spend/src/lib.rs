#![allow(unused)]
extern crate balance;
use balance::{bcli, WalletState, UTXO};

use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

use hex;

use sha2::{Digest, Sha256};

const FEE: u64 = 1000;
const AMT: u64 = 1000000;

use tracing::{debug, info};

#[derive(Debug)]
pub enum SpendError {
    MissingCodeCantRun,
    InsufficientFunds,
}

pub struct Outpoint {
    txid: [u8; 32],
    index: u32,
}

// Given 2 compressed public keys as byte arrays, construct
// a 2-of-2 multisig output script. No length byte prefix is necessary.
fn create_multisig_script(keys: Vec<Vec<u8>>) -> Vec<u8> {
    let (first, second) = (keys[0].clone(), keys[1].clone());
    debug!("First pubkey: {:?}", hex::encode(first.clone()));
    debug!("Second pubkey: {:?}", hex::encode(second.clone()));
    let mut script = Vec::new();
    script.push(0x52); // OP_2
    script.push(0x21); // size of pub key (33 byte)
    assert_eq!(first.len(), 33, "First key size is wrong");
    script.extend(first);
    script.push(0x21); // size of pub key (33 byte)
    assert_eq!(second.len(), 33, "Second key size is wrong");
    script.extend(second);
    script.push(0x52);
    script.push(0xAE); // OP_CHECKMULTISIG
    debug!("Multisig script: {:?}", hex::encode(script.clone()));
    script
}

// Given an output script as a byte array, compute the p2wsh witness program
// This is a segwit version 0 pay-to-script-hash witness program.
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
fn get_p2wsh_program(script: &[u8], version: Option<u32>) -> Vec<u8> {
    let script_hash = Sha256::digest(script);
    let mut program = Vec::new();
    assert_eq!(script_hash.len(), 32, "Script size is wrong");
    match version {
        Some(v) => program.push((v as u8).to_le()),
        None => {
            program.push(0x00); // Version 0 for P2WSH
        }
    }
    program.push(0x20);
    program.extend_from_slice(&script_hash);
    program
}

// Given an outpoint, return a serialized transaction input spending it
// Use hard-coded defaults for sequence and scriptSig
fn input_from_utxo(txid: &[u8], index: u32) -> Vec<u8> {
    assert_eq!(txid.len(), 32, "Txid not long enough");
    let mut input = Vec::new();
    input.extend(txid);
    input.extend(index.to_le_bytes());
    input.push(0x00);
    input.extend((0xffffffff as u32).to_le_bytes());
    input
}

// Given an output script and value (in satoshis), return a serialized transaction output
fn output_from_options(script: &[u8], amount: u64) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend(&amount.to_le_bytes());
    output.push(script.len() as u8);
    output.extend_from_slice(script);
    output
}

// Given a Utxo object, extract the public key hash from the output script
// and assemble the p2wpkh scriptcode as defined in BIP143
// <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
fn get_p2wpkh_scriptcode(utxo: &UTXO) -> Vec<u8> {
    debug!("Public key: {:?}", hex::encode(&utxo.script_pubkey));
    // Extract the public key hash from the scriptPubKey
    let pubkey_hash = if utxo.script_pubkey.starts_with(&[0x00, 0x14]) {
        // P2WPKH scriptPubKey format: 0x0014{20-byte-key-hash}
        utxo.script_pubkey[2..22].to_vec()
    } else if utxo.script_pubkey.len() == 25
        && utxo.script_pubkey.starts_with(&[0x76, 0xa9, 0x14])
        && utxo.script_pubkey.ends_with(&[0x88, 0xac])
    {
        utxo.script_pubkey[3..23].to_vec()
    } else {
        panic!("ScriptPubKey not recognized");
    };

    // Assemble the scriptCode for P2WPKH: OP_DUP OP_HASH160 {pubkey hash} OP_EQUALVERIFY OP_CHECKSIG
    let mut script_code = Vec::with_capacity(25);
    script_code.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 and push 20 bytes
    script_code.extend_from_slice(&pubkey_hash);
    script_code.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

    script_code
}

fn get_p2pk_scriptcode(utxo: &UTXO) -> Vec<u8> {
    debug!("UTXO ScriptPubKey: {:?}", hex::encode(&utxo.script_pubkey));

    if utxo.script_pubkey.last() == Some(&0xAC) {
        utxo.script_pubkey.clone()
    } else {
        panic!("ScriptPubKey does not match P2PK format");
    }
}

fn hash256(data: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(data);
    Sha256::digest(&hash).to_vec()
}
// Compute the commitment hash for a single input and return bytes to sign.
// This implements the BIP 143 transaction digest algorithm
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
// We assume only a single input and two outputs,
// as well as constant default values for sequence and locktime
fn get_commitment_hash(
    outpoint: Outpoint,
    scriptcode: &[u8],
    value: u64,
    outputs: Vec<UTXO>,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(&2u32.to_le_bytes());
    let mut outpoints = Vec::new();
    outpoints.extend_from_slice(&outpoint.txid);
    outpoints.extend(&outpoint.index.to_le_bytes());
    data.extend(&hash256(&outpoints));
    let sequence = 0xffffffffu32;
    data.extend(&hash256(&sequence.to_le_bytes()));
    data.extend_from_slice(&outpoint.txid);
    data.extend(&outpoint.index.to_le_bytes());
    data.push(scriptcode.len() as u8);
    data.extend_from_slice(scriptcode);
    data.extend(&value.to_le_bytes());
    data.extend(&sequence.to_le_bytes());
    let mut outputs_data = Vec::new();
    for output in outputs {
        outputs_data.extend(&output.amount.to_le_bytes());
        outputs_data.push(output.script_pubkey.len() as u8);
        outputs_data.extend_from_slice(&output.script_pubkey);
    }
    data.extend(&hash256(&outputs_data));
    let locktime = 0u32; // Default locktime
    data.extend(&locktime.to_le_bytes());
    data.extend(&1u32.to_le_bytes()); // SIGHASH_ALL
    let commitment_hash = hash256(&data);
    debug!("Commitment hash: {:?}", hex::encode(&commitment_hash));
    debug!("Commitment img: {:?}", hex::encode(&data));
    commitment_hash
}
// Given a JSON utxo object and a list of all of our wallet's witness programs,
// return the index of the derived key that can spend the coin.
// This index should match the corresponding private key in our wallet's list.
fn get_key_index(utxo: &UTXO, programs: &Vec<String>) -> u32 {
    let key_hash_str = hex::encode(&utxo.script_pubkey);

    for (index, program) in programs.iter().enumerate() {
        // debug!("Key hash: {:?} - {:?}", key_hash_str, program);
        if program == &key_hash_str {
            return index as u32;
        }
    }
    panic!("No key index found for utxo and programs");
}

// Given a private key and message digest as bytes, compute the ECDSA signature.
// Bitcoin signatures:
// - Must be strict-DER encoded
// - Must have the SIGHASH_ALL byte (0x01) appended
// - Must have a low s value as defined by BIP 62:
//   https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures
fn sign(privkey: &[u8; 32], msg: Vec<u8>) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(privkey).expect("Invalid private key");
    let message = Message::from_slice(&msg).expect("Invalid message");
    let mut signature = secp.sign_ecdsa(&message, &secret_key);
    signature.normalize_s();
    let der_sign = signature.serialize_der();
    let mut final_signature = der_sign.as_ref().to_vec();
    final_signature.push(0x01); // Append SIGHASH_ALL
    return final_signature;
}

// Given a private key and transaction commitment hash to sign,
// compute the signature and assemble the serialized p2pkh witness
// as defined in BIP 141 (2 stack items: signature, compressed public key)
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
fn get_p2wpkh_witness(privkey: &[u8; 32], msg: Vec<u8>) -> Vec<u8> {
    let secp = Secp256k1::new();
    let der_signature = sign(&privkey, msg);
    let secret_key = SecretKey::from_slice(privkey).expect("Invalid private key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let compressed_pubkey = public_key.serialize();
    //println!("Building witness privkey: {:?}", hex::encode(&privkey));
    //println!(
    //    "Building witness pubkey: {:?}",
    //    hex::encode(&compressed_pubkey)
    //);

    assert_eq!(
        compressed_pubkey.len(),
        33,
        "Compressed pubkey size is wrong"
    );
    assert!(
        compressed_pubkey[0] == 0x02 || compressed_pubkey[0] == 0x03,
        "Invalid pubkey"
    );

    let mut serialized_witness = Vec::new();
    serialized_witness.push(0x02);
    serialized_witness.push(der_signature.len() as u8);
    serialized_witness.extend(&der_signature);
    serialized_witness.push(compressed_pubkey.len() as u8);
    serialized_witness.extend(&compressed_pubkey);
    serialized_witness
}

// Given two private keys and a transaction commitment hash to sign,
// compute both signatures and assemble the serialized p2pkh witness
// as defined in BIP 141
// Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
// https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
fn get_p2wsh_witness(privs: Vec<&[u8; 32]>, msg: Vec<u8>, redeem_script: &[u8]) -> Vec<u8> {
    let mut serialized_witness = Vec::new();
    serialized_witness.push(0);
    serialized_witness.push(0x00);
    let mut witness_count = 1;
    for privkey in privs {
        let der_signature = sign(privkey, msg.clone());
        serialized_witness.push(der_signature.len() as u8);
        serialized_witness.extend(&der_signature);
        witness_count += 1;
    }

    serialized_witness.push(redeem_script.len() as u8);
    serialized_witness.extend_from_slice(redeem_script);
    witness_count += 1;

    serialized_witness[0] = witness_count as u8;
    serialized_witness
}

// Given arrays of inputs, outputs, and witnesses, assemble the complete
// transaction and serialize it for broadcast. Return bytes as hex-encoded string
// suitable to broadcast with Bitcoin Core RPC.
// https://en.bitcoin.it/wiki/Protocol_documentation#tx
fn assemble_transaction(
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<u8>>,
) -> Vec<u8> {
    assert!(inputs.len() > 0, "No inputs");
    assert_eq!(
        inputs.len(),
        witnesses.len(),
        "len of inputs diff from wintess len"
    );
    let mut tx = Vec::new();
    // Version
    tx.extend(0x02u32.to_le_bytes());
    tx.push(0x00);
    tx.push(0x01);
    tx.push(inputs.len() as u8);
    for input in inputs {
        tx.extend(&input);
    }
    tx.push(outputs.len() as u8);
    for output in outputs {
        tx.extend(&output);
    }
    for witness in witnesses {
        tx.extend(&witness);
    }
    tx.extend(&0u32.to_le_bytes());
    tx
}

// Given arrays of inputs and outputs (no witnesses!) compute the txid.
// Return the 32 byte txid as a *reversed* hex-encoded string.
// https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
fn get_txid(inputs: Vec<Vec<u8>>, outputs: Vec<Vec<u8>>) -> [u8; 32] {
    let mut tx = Vec::new();
    tx.extend(&0x00000002u32.to_le_bytes());
    tx.push((inputs.len() as u8).to_le());

    for input in inputs {
        tx.extend(&input);
    }
    tx.push((outputs.len() as u8).to_le());
    for output in outputs {
        tx.extend_from_slice(&output);
        //tx.extend(&output.amount.to_le_bytes());
        //tx.push(output.script_pubkey.len() as u8);
        //tx.extend(&output.script_pubkey);
    }
    tx.extend(&0u32.to_le_bytes());
    let hash = Sha256::digest(&Sha256::digest(&tx));
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&hash);
    txid.reverse();
    txid
}
// Spend a p2wpkh utxo to a 2 of 2 multisig p2wsh and return the (txid, transaction) tupple
pub fn spend_p2wpkh(wallet_state: &WalletState) -> Result<([u8; 32], Vec<u8>), SpendError> {
    // FEE = 1000
    // AMT = 1000000
    // Choose an unspent coin worth more than 0.01 BTC
    let utxo = wallet_state
        .utxos
        .iter()
        .find(|u| u.amount > AMT + FEE)
        .ok_or(SpendError::InsufficientFunds)?;

    //println!("Utxo: {:#?}", &utxo);
    debug!("Utxo script: {:?}", hex::encode(&utxo.script_pubkey));
    debug!("Utxo txid: {:?}", &utxo.txid);

    // Create the input from the utxo
    // Reverse the txid hash so it's little-endian
    let txid = hex::decode(&utxo.txid).unwrap();
    let txid_rev: Vec<u8> = txid.iter().rev().cloned().collect();
    assert_eq!(
        &txid[0..1],
        &txid_rev[txid_rev.len() - 1..],
        "Txid not reversed correctly"
    );
    debug!("Utxo Txid reversed: {:#?}", hex::encode(&txid_rev));
    let input = input_from_utxo(&txid_rev, utxo.index);

    // Compute destination output script and output
    let multisig_script = create_multisig_script(wallet_state.public_keys.clone());
    let witness_program = get_p2wsh_program(&multisig_script, None);
    let destination_output = output_from_options(&witness_program, AMT);

    let previous_output_script = get_p2wpkh_scriptcode(utxo);
    debug!(
        "Previous output script: {:?}",
        hex::encode(&previous_output_script)
    );

    // Compute change output script and output
    let mut change_script = Vec::with_capacity(25);
    change_script.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 and push 20 bytes
    change_script.extend_from_slice(&wallet_state.witness_programs[0][2..22]);
    change_script.extend_from_slice(&[0x88, 0xac]);
    let change_output = output_from_options(&change_script, utxo.amount as u64 - AMT - FEE);
    debug!("Change script: {:?}", hex::encode(&change_script));
    debug!("Change value: {:?}", utxo.amount as u64 - AMT - FEE);

    // // Get the message to sign
    let commitment_hash = get_commitment_hash(
        Outpoint {
            txid: txid_rev.try_into().unwrap(),
            index: utxo.index,
        },
        &previous_output_script,
        utxo.amount,
        vec![
            UTXO {
                script_pubkey: witness_program.clone(),
                amount: AMT,
                txid: "".to_string(),
                index: 0,
                raw_utxo: vec![],
            },
            UTXO {
                script_pubkey: change_script.clone(),
                amount: utxo.amount as u64 - AMT - FEE,
                txid: "".to_string(),
                index: 0,
                raw_utxo: vec![],
            },
        ],
    );
    // Fetch the private key we need to sign with
    let programs: Vec<String> = wallet_state
        .witness_programs
        .iter()
        .map(|x| hex::encode(x))
        .collect();

    let utxo_key_index = get_key_index(&utxo, &programs);
    let private_key = wallet_state
        .private_keys
        .get(utxo_key_index as usize)
        .ok_or(SpendError::MissingCodeCantRun)?;
    let public_key = wallet_state
        .public_keys
        .get(utxo_key_index as usize)
        .ok_or(SpendError::MissingCodeCantRun)?;

    //println!("Utxo PrivateKey: {:?}", hex::encode(private_key));
    //println!("Utxo PublicKey: {:?}", hex::encode(public_key));

    let privkey_slice = &private_key.to_vec()[1..33];
    // debug!(
    //     "Got the private key: {:?}, len({:?})",
    //     privkey_slice,
    //     privkey_slice.len()
    // );

    let witness = get_p2wpkh_witness(&privkey_slice.try_into().unwrap(), commitment_hash);
    debug!("Witness: {:?}", hex::encode(witness.clone()));

    let trans_input = vec![input.clone()];
    debug!("Inputs has size: {}", trans_input.len());
    // Assemble
    let transaction = assemble_transaction(
        trans_input,
        vec![destination_output.clone(), change_output.clone()],
        vec![witness],
    );

    // Reserialize without witness data and double-SHA256 to get the txid
    let txid = get_txid(vec![input], vec![destination_output, change_output]);

    // For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here

    // return txid, final-tx
    Ok((txid, transaction))
}

//// Spend a 2-of-2 multisig p2wsh utxo and return the transaction
pub fn spend_p2wsh(
    wallet_state: &WalletState,
    txid: [u8; 32],
) -> Result<([u8; 32], Vec<u8>), SpendError> {
    // COIN_VALUE = 1000000
    // FEE = 1000
    // AMT = 0
    // Create the input from the utxo
    // Reverse the txid hash so it's little-endian

    // Compute destination output script and output

    // Compute change output script and output

    // Get the message to sign

    // Sign!

    // Assemble

    // For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    // return txid final-tx
    const FEE: u64 = 1000;
    const AMT: u64 = 0;
    let prev_utxo_amount = 1000000u64;
    let txid_rev: Vec<u8> = txid.iter().rev().cloned().collect();

    let multisig_script = create_multisig_script(wallet_state.public_keys.clone());
    let witness_program = get_p2wsh_program(&multisig_script, None);

    let utxo = UTXO {
        txid: hex::encode(txid_rev.clone()),
        index: 0,
        amount: prev_utxo_amount,
        script_pubkey: witness_program.clone(),
        raw_utxo: vec![],
    };

    let input = input_from_utxo(&txid_rev.clone(), 0);

    let op_return_data = b"Henrique dos Santos Goulart";
    let mut op_return_script = Vec::new();
    op_return_script.push(0x6a);
    op_return_script.push(op_return_data.len() as u8);
    op_return_script.extend_from_slice(op_return_data);

    let mut op_return_output = Vec::new();
    op_return_output.extend(AMT.to_le_bytes());
    op_return_output.push(op_return_script.len() as u8);
    op_return_output.extend_from_slice(&op_return_script);

    let change_amount = prev_utxo_amount - AMT - FEE;
    let mut change_script = Vec::with_capacity(25);
    change_script.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 and push 20 bytes
    change_script.extend_from_slice(&wallet_state.witness_programs[0][2..22]);
    change_script.extend_from_slice(&[0x88, 0xac]);
    let change_output = output_from_options(&change_script, change_amount);

    let commitment_hash = get_commitment_hash(
        Outpoint {
            txid: txid_rev.clone().try_into().unwrap(),
            index: 0,
        },
        &multisig_script,
        prev_utxo_amount,
        vec![
            UTXO {
                script_pubkey: op_return_script.clone(),
                amount: AMT,
                txid: "".to_string(),
                index: 0,
                raw_utxo: vec![],
            },
            UTXO {
                script_pubkey: change_script.clone(),
                amount: change_amount,
                txid: "".to_string(),
                index: 0,
                raw_utxo: vec![],
            },
        ],
    );
    let private_keys = &wallet_state.private_keys[0..2];
    let witness = get_p2wsh_witness(
        vec![
            &private_keys[0][1..33].try_into().unwrap(),
            &private_keys[1][1..33].try_into().unwrap(),
        ],
        commitment_hash,
        &multisig_script,
    );

    let transaction = assemble_transaction(
        vec![input.clone()],
        vec![op_return_output.clone(), change_output.clone()],
        vec![witness],
    );
    let final_txid = get_txid(vec![input], vec![op_return_output, change_output]);
    Ok((final_txid, transaction))
}

fn create_op_return_output(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    assert!(
        data.len() <= 80,
        "Data size exceeds maximum allowed for OP_RETURN outputs"
    );
    output.extend(&0u64.to_le_bytes());
    let mut script = Vec::new();
    script.push(0x6a);
    assert!(
        data.len() <= 0xFF,
        "Data length exceeds maximum that can be encoded with one byte"
    );
    script.push(data.len() as u8);
    script.extend(data);
    output.push(script.len() as u8);
    output.extend(script);
    output
}

fn get_commitment_hash2(
    outpoint: Outpoint,
    outpoint2: Outpoint,
    scriptcode: &[u8],
    scriptcode2: &[u8],
    value: u64,
    value2: u64,
    outputs: Vec<UTXO>,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(&1u32.to_le_bytes());
    let mut outpoints = Vec::new();
    outpoints.extend_from_slice(&outpoint.txid);
    outpoints.extend(&outpoint.index.to_le_bytes());
    outpoints.extend_from_slice(&outpoint2.txid);
    outpoints.extend(&outpoint2.index.to_le_bytes());
    let hash_prevouts = &hash256(&outpoints);
    println!("Hash prevouts: {:?}", hex::encode(&hash_prevouts));
    data.extend(hash_prevouts);
    let sequence1 = 0xeeffffffu32;
    let sequence2 = 0xffffffffu32;
    let sequence = 0xffffffffffffffeeu64;
    let hashed_seq = &hash256(&sequence.to_le_bytes());
    println!("Hashed sequence: {:?}", hex::encode(&hashed_seq));
    data.extend(hashed_seq);
    println!(
        "Outpoint: {:?}{:?}",
        hex::encode(&outpoint2.txid),
        hex::encode(&outpoint2.index.to_le_bytes())
    );
    data.extend_from_slice(&outpoint2.txid);
    data.extend_from_slice(&outpoint2.index.to_le_bytes());

    //data.extend(&outpoint.index.to_le_bytes());
    //data.extend_from_slice(scriptcode);
    //data.extend(&value.to_le_bytes());
    //data.extend(&sequence1.to_le_bytes());

    let mut scriptcode_with_len: Vec<u8> = vec![];
    scriptcode_with_len.push(scriptcode2.len() as u8);
    scriptcode_with_len.extend_from_slice(scriptcode2);

    println!("Scriptcode: {:?}", hex::encode(&scriptcode_with_len));
    data.extend_from_slice(&scriptcode_with_len);

    println!("Amount: {:?}", hex::encode(&value2.to_le_bytes()));
    data.extend(&value2.to_le_bytes());
    println!("Sequence: {:?}", hex::encode(&sequence2.to_le_bytes()));
    data.extend(&sequence2.to_le_bytes());

    let mut outputs_data = Vec::new();
    for output in outputs {
        println!(
            "Output amount and pubkey: {:?} {:?}",
            hex::encode(output.amount.to_le_bytes()),
            hex::encode(&output.script_pubkey)
        );
        outputs_data.extend(&output.amount.to_le_bytes());
        outputs_data.push(output.script_pubkey.len() as u8);
        outputs_data.extend_from_slice(&output.script_pubkey);
    }
    let hash_outs = &hash256(&outputs_data);
    println!("Hash outputs: {:?}", hex::encode(&hash_outs));
    data.extend(hash_outs);

    let locktime = 0x11u32; // Default locktime
    let locktime_bytes = &locktime.to_le_bytes();
    println!("Locktime: {:?}", hex::encode(locktime_bytes));
    data.extend(locktime_bytes);
    let sighash_all_bytes = &1u32.to_le_bytes();
    println!("Sighash all: {:?}", hex::encode(sighash_all_bytes));
    data.extend(sighash_all_bytes); // SIGHASH_ALL
    let commitment_hash = hash256(&data);
    println!("sigHash: {:?}", hex::encode(&commitment_hash));
    println!("preImage: {:?}", hex::encode(&data));
    //commitment_hash
    data
}

// write test for fn get_commitment_hash function
#[cfg(test)]
mod tests {
    use super::*;
    use balance::recover_wallet_state;
    use hex;

    #[test]
    fn test_get_commitment_hash() {
        let utxo = UTXO {
            txid: "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f".to_string(),
            index: 0,
            amount: (6.25 * 100_000_000_f64) as u64,
            script_pubkey: hex::decode(
                "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
            )
            .unwrap(),
            raw_utxo: vec![],
        };
        let utxo2 = UTXO {
            txid: "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a".to_string(),
            index: 1,
            amount: 6 * 100_000_000,
            script_pubkey: hex::decode("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap(),
            raw_utxo: vec![],
        };
        let commitment_hash = get_commitment_hash2(
            Outpoint {
                txid: hex::decode(&utxo.txid).unwrap().try_into().unwrap(),
                index: utxo.index,
            },
            Outpoint {
                txid: hex::decode(&utxo2.txid).unwrap().try_into().unwrap(),
                index: utxo2.index,
            },
            &get_p2pk_scriptcode(&utxo),
            &get_p2wpkh_scriptcode(&utxo2),
            utxo.amount,
            utxo2.amount,
            vec![
                UTXO {
                    script_pubkey: hex::decode(
                        "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac",
                    )
                    .unwrap(),
                    amount: 112340000,
                    txid: "".to_string(),
                    index: 0,
                    raw_utxo: vec![],
                },
                UTXO {
                    script_pubkey: hex::decode(
                        "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac",
                    )
                    .unwrap(),
                    amount: 223450000,
                    txid: "".to_string(),
                    index: 0,
                    raw_utxo: vec![],
                },
            ],
        );
        assert_eq!(hex::encode(commitment_hash), "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000");
    }
}
