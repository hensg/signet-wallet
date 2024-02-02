#![allow(unused)]
extern crate balance;
use balance::WalletState;

use hex;
use libsecp256k1::curve::Scalar;
use libsecp256k1::{Message, PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha256};

const FEE: u64 = 1000;
const AMT: u64 = 1000000; // 0.01 BTC in satoshis

#[derive(Debug)]
pub enum SpendError {
    MissingCodeCantRun,
    InsufficientFunds,
    // Add more relevant error variants
}

pub struct Utxo {
    script_pubkey: Vec<u8>,
    amount: u32,
}

pub struct Outpoint {
    txid: [u8; 32],
    index: u32,
}

// Given 2 compressed public keys as byte arrays, construct
// a 2-of-2 multisig output script. No length byte prefix is necessary.
fn create_multisig_script(keys: Vec<Vec<u8>>) -> Vec<u8> {
    let (first, second) = (&keys[0], &keys[1]);
    let mut script = Vec::new();
    script.push(0x52); // OP_2 is 0x52 in hex
    script.extend_from_slice(first);
    script.extend_from_slice(second);
    script.push(0x52); // OP_2 is 0x52 in hex
    script.push(0xAE); // OP_CHECKMULTISIG is 0xAE in hex
    script
}

// Given an output script as a byte array, compute the p2wsh witness program
// This is a segwit version 0 pay-to-script-hash witness program.
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
fn get_p2wsh_program(script: &[u8], version: Option<u32>) -> Vec<u8> {
    let script_hash = Sha256::digest(script);
    let mut program = Vec::new();
    match version {
        Some(v) => program.push(v as u8),
        None => program.push(0x00), // Version 0 for P2WSH
    }
    program.extend_from_slice(&script_hash);
    program
}

// Given an outpoint, return a serialized transaction input spending it
// Use hard-coded defaults for sequence and scriptSig
fn input_from_utxo(txid: &[u8], index: u32) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend(txid.iter().rev()); // 32
    input.extend(&index.to_le_bytes()); // 4
    input.push(0x00); //scriptSig
    input.extend(&0xffffffffu32.to_le_bytes()); //sequence
    input
}

// Given an output script and value (in satoshis), return a serialized transaction output
fn output_from_options(script: &[u8], value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend(&value.to_le_bytes());
    assert!(script.len() <= 0xff, "Script is too long");
    output.push(script.len() as u8);
    output.extend_from_slice(script);
    output
}

// Given a Utxo object, extract the public key hash from the output script
// and assemble the p2wpkh scriptcode as defined in BIP143
// <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
fn get_p2wpkh_scriptcode(utxo: Utxo) -> Vec<u8> {
    // Extract the public key hash from the scriptPubKey
    // Assuming the scriptPubKey follows the standard format
    let pubkey_hash = if utxo.script_pubkey.starts_with(&[0x00, 0x14]) {
        // P2WPKH scriptPubKey format: 0x0014{20-byte-key-hash}
        utxo.script_pubkey[2..22].to_vec()
    } else if utxo.script_pubkey.len() == 25
        && utxo.script_pubkey.starts_with(&[0x76, 0xa9, 0x14])
        && utxo.script_pubkey.ends_with(&[0x88, 0xac])
    {
        // P2PKH scriptPubKey format: 76a914{20-byte-key-hash}88ac
        utxo.script_pubkey[3..23].to_vec()
    } else {
        // If the scriptPubKey is not a recognized format, return an empty vector or handle as needed
        return Vec::new();
    };

    // Assemble the scriptCode for P2WPKH: OP_DUP OP_HASH160 {pubkey hash} OP_EQUALVERIFY OP_CHECKSIG
    let mut script_code = Vec::with_capacity(25);
    script_code.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 and push 20 bytes
    script_code.extend_from_slice(&pubkey_hash);
    script_code.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

    script_code
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
    value: u32,
    outputs: Vec<Utxo>,
) -> Vec<u8> {
    // Version

    // All TX input outpoints (only one in our case)

    // All TX input sequences (only one for us, always default value)

    // Single outpoint being spent

    // Scriptcode (the scriptPubKey in/implied by the output being spent, see BIP 143)

    // Value of output being spent

    // Sequence of output being spent (always default for us)

    // All TX outputs

    // Locktime (always default for us)

    // SIGHASH_ALL (always default for us)

    let mut data = Vec::new();
    // Version
    data.extend(&1u32.to_le_bytes());
    // HashPrevouts
    let mut outpoints = Vec::new();
    outpoints.extend_from_slice(&outpoint.txid);
    outpoints.extend(&outpoint.index.to_le_bytes());
    data.extend(&hash256(&outpoints));
    // HashSequence
    let sequence = 0xffffffffu32;
    data.extend(&hash256(&sequence.to_le_bytes()));
    // Outpoint
    data.extend_from_slice(&outpoint.txid);
    data.extend(&outpoint.index.to_le_bytes());
    // ScriptCode
    data.extend_from_slice(scriptcode);
    // Value of output being spent
    data.extend(&value.to_le_bytes());
    // Sequence
    data.extend(&sequence.to_le_bytes());
    // HashOutputs
    let mut outputs_data = Vec::new();
    for output in outputs {
        outputs_data.extend(&output.amount.to_le_bytes());
        outputs_data.push(output.script_pubkey.len() as u8);
        outputs_data.extend_from_slice(&output.script_pubkey);
    }
    data.extend(&hash256(&outputs_data));
    // Locktime
    let locktime = 0u32; // Default locktime
    data.extend(&locktime.to_le_bytes());

    // Sighash type
    data.extend(&1u32.to_le_bytes()); // SIGHASH_ALL
    hash256(&data)
}

// Given a JSON utxo object and a list of all of our wallet's witness programs,
// return the index of the derived key that can spend the coin.
// This index should match the corresponding private key in our wallet's list.
fn get_key_index(utxo: Utxo, programs: Vec<&str>) -> u32 {
    // Extract the relevant part of the scriptPubKey
    // This depends on the script type. For example:
    // - For P2PKH: bytes 3-22 (after OP_DUP OP_HASH160 <size>)
    // - For P2WPKH: bytes 2-21 (after OP_0 <size>)
    let key_hash = if utxo.script_pubkey.starts_with(&[0x00, 0x14]) {
        // P2WPKH format
        utxo.script_pubkey[2..22].to_vec()
    } else if utxo.script_pubkey.len() == 25
        && utxo.script_pubkey.starts_with(&[0x76, 0xa9, 0x14])
        && utxo.script_pubkey.ends_with(&[0x88, 0xac])
    {
        // P2PKH format
        utxo.script_pubkey[3..23].to_vec()
    } else {
        // If the scriptPubKey is not a recognized format
        panic!("ScriptPubKey not recognized");
    };

    // Convert the key hash to a string to compare with the provided programs
    let key_hash_str = hex::encode(key_hash);

    // Iterate over the programs to find a match
    for (index, program) in programs.iter().enumerate() {
        if *program == key_hash_str {
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
    // Keep signing until we produce a signature with "low s value"
    // We will have to decode the DER-encoded signature and extract the s value to check it
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    let secret_key = SecretKey::parse_slice(privkey).expect("Invalid private key");
    let message = Message::parse_slice(&msg).expect("Invalid message");
    loop {
        let (signature, recover_id) = libsecp256k1::sign(&message, &secret_key);
        if signature.r.is_high() {
            continue; // Re-sign if 's' value is high
        }

        let der_sign = signature.serialize_der();
        let mut final_signature = der_sign.as_ref().to_vec();
        final_signature.push(0x01); // Append SIGHASH_ALL
        return final_signature;
    }
}

// Given a private key and transaction commitment hash to sign,
// compute the signature and assemble the serialized p2pkh witness
// as defined in BIP 141 (2 stack items: signature, compressed public key)
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
fn get_p2wpkh_witness(privkey: &[u8; 32], msg: Vec<u8>) -> Vec<u8> {
    // Use the sign function to get the signature
    let der_signature = sign(privkey, msg);

    // Compute the compressed public key
    let secret_key = SecretKey::parse_slice(privkey).expect("Invalid private key");
    let public_key = PublicKey::from_secret_key(&secret_key);
    let compressed_pubkey = public_key.serialize().to_vec();

    // Assemble the witness
    let mut serialized_witness = Vec::new();
    serialized_witness.push(der_signature.len() as u8);
    serialized_witness.extend(&der_signature);
    serialized_witness.push(compressed_pubkey.len() as u8);
    serialized_witness.extend(&compressed_pubkey);
    serialized_witness.to_vec()
}

// Given two private keys and a transaction commitment hash to sign,
// compute both signatures and assemble the serialized p2pkh witness
// as defined in BIP 141
// Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
// https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
fn get_p2wsh_witness(privs: Vec<&[u8; 32]>, msg: Vec<u8>) -> Vec<u8> {
    let mut serialized_witness = Vec::new();
    // Add a 0x00 byte for CHECKMULTISIG bug
    serialized_witness.push(0x00);
    for privkey in privs {
        // Sign the message
        let der_signature = sign(privkey, msg.clone());

        serialized_witness.push(der_signature.len() as u8);
        serialized_witness.extend(der_signature);
    }

    serialized_witness
}

// Given arrays of inputs, outputs, and witnesses, assemble the complete
// transaction and serialize it for broadcast. Return bytes as hex-encoded string
// suitable to broadcast with Bitcoin Core RPC.
// https://en.bitcoin.it/wiki/Protocol_documentation#tx
fn assemble_transaction(
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Utxo>,
    witnesses: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut tx = Vec::new();
    // Version
    tx.extend(&2u32.to_le_bytes()); // Assuming version 2 for SegWit
                                    // Marker and Flag for SegWit
    tx.push(0x00); // Marker
    tx.push(0x01); // Flag
                   // Input count
    tx.push(inputs.len() as u8); // Simplified, assumes less than 0xFD inputs
                                 // Inputs
    for input in inputs {
        tx.extend(input);
    }
    // Output count
    tx.push(outputs.len() as u8); // Simplified, assumes less than 0xFD outputs
                                  // Outputs
    for output in outputs {
        tx.extend(&output.amount.to_le_bytes()); // Serialize the value
        tx.push(output.script_pubkey.len() as u8); // Length of scriptPubKey
        tx.extend(&output.script_pubkey); // scriptPubKey
    }
    // Witnesses
    for witness in witnesses {
        // Assuming each witness is already serialized with elements prefixed by their length
        tx.extend(witness);
    }
    // Locktime (assuming 0 for simplicity)
    tx.extend(&0u32.to_le_bytes());
    tx
}

// Given arrays of inputs and outputs (no witnesses!) compute the txid.
// Return the 32 byte txid as a *reversed* hex-encoded string.
// https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
fn get_txid(inputs: Vec<Vec<u8>>, outputs: Vec<Utxo>) -> [u8; 32] {
    let mut tx = Vec::new();
    // Version (4 bytes, little-endian)
    tx.extend(&2u32.to_le_bytes()); // Assuming version 2
                                    // Input count (VarInt)
    tx.push(inputs.len() as u8); // Simplified, assuming less than 0xFD inputs
                                 // Inputs
    for input in inputs {
        tx.extend(&input);
    }
    // Output count (VarInt)
    tx.push(outputs.len() as u8); // Simplified, assuming less than 0xFD outputs
                                  // Outputs
    for output in outputs {
        tx.extend(&output.amount.to_le_bytes()); // Serialize the value
        tx.push(output.script_pubkey.len() as u8); // Length of scriptPubKey
        tx.extend(&output.script_pubkey); // scriptPubKey
    }
    // Locktime (4 bytes, little-endian)
    tx.extend(&0u32.to_le_bytes()); // Assuming a locktime of 0
                                    // Double SHA256 of the serialized transaction
    let hash = Sha256::digest(&Sha256::digest(&tx));
    // Reverse the hash to get the txid
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

    // Create the input from the utxo
    // Reverse the txid hash so it's little-endian

    // Compute destination output script and output

    // Compute change output script and output

    // Get the message to sign

    // Fetch the private key we need to sign with

    // Sign!

    // Assemble

    // Reserialize without witness data and double-SHA256 to get the txid

    // For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here

    // return txid, final-tx
    let utxo = wallet_state
        .utxos
        .iter()
        .find(|u| u.amount > AMT + FEE)
        .ok_or(SpendError::InsufficientFunds)?;

    // Create the input from the utxo
    // Reverse the txid hash so it's little-endian
    let input = input_from_utxo(utxo.txid.as_bytes(), utxo.output_index);

    // Compute destination and change output scripts and outputs
    let multsig_script = create_multisig_script(wallet_state.public_keys);
    let p2wsh_program = get_p2wsh_program(&multsig_script, None);

    let destination_output_script = output_from_options(&multsig_script, AMT);
    let change_output_script = output_from_options(&multsig_script, utxo.amount - FEE - AMT);
    let outputs = vec![destination_output_script, change_output_script];

    // Get the message to sign (Transaction hash for signing)
    let msg_to_sign = compute_transaction_hash_for_signing(&inputs, &outputs);

    // Fetch the private key(s) needed to sign
    let priv_keys = fetch_private_keys_for_signing(wallet_state, &utxo);

    // Sign the transaction
    let signature = sign_transaction(&msg_to_sign, &priv_keys);

    // Assemble the transaction with signatures
    let final_tx = assemble_transaction(&inputs, &outputs, &signature);

    // Reserialize without witness data and double-SHA256 to get the txid
    let txid = compute_txid(&inputs, &outputs);

    // Return txid and final transaction
    Ok((txid, final_tx))
}

// Spend a 2-of-2 multisig p2wsh utxo and return the transaction
pub fn spend_p2wsh(wallet_state: &WalletState, txid: [u8; 32]) -> Result<Vec<Vec<u8>>, SpendError> {
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

    unimplemented!("implement the logic")
}
