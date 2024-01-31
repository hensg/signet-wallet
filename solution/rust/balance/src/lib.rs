#![allow(unused)]
use std::{path::PathBuf, process::Command};

// TODO: completly remove the btc dependency for pub key generation
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Address, Network};
use bs58::{decode, encode};
use std::collections::{HashMap, HashSet};

use ripemd::Ripemd160;
use secp256k1::SecretKey;
use serde_json::Value;
use std::str::from_utf8;

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use anyhow::anyhow;

use hex_literal::hex;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = Hmac<Sha512>;
// Provided by administrator
pub const WALLET_NAME: &str = "wallet_121";
pub const EXTENDED_PRIVATE_KEY: &str = "wpkh(tprv8ZgxMBicQKsPeDsCumcxgvEWN7usEqePaobYYM7r5ABem6hbM8aYKj42eCxgEmDrYd4xSrH5faBReXhcXGZbMNJnAkm4oxEsAQkTpKkXdZL/84h/1h/0h/0/*)#s5lj8x07";

//const P: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
//const A: isize = 0;
//const B: isize = 7;
//const GX: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
//const GY: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    ErrorOnBtcCli,
}

#[derive(Debug, PartialEq, Clone)]
struct ExKey {
    version: [u8; 4],
    depth: [u8; 1],
    finger_print: [u8; 4],
    child_number: [u8; 4],
    chaincode: [u8; 32],
    key: [u8; 33], // TODO: back to 32
}

// final wallet state struct
pub struct WalletState {
    utxos: Vec<Vec<u8>>,
    witness_programs: Vec<Vec<u8>>,
    public_keys: Vec<Vec<u8>>,
    private_keys: Vec<Vec<u8>>,
}

impl WalletState {
    // Given a WalletState find the balance is satoshis
    pub fn balance(&self) -> f64 {
        self.utxos
            .iter()
            .map(|utxo| {
                let value_bytes = &utxo[..8]; // First 8 bytes represent the value
                f64::from_be_bytes(value_bytes.try_into().expect("Invalid UTXO format"))
            })
            .sum()
    }
}

// Decode a base58 string into an array of bytes
fn base58_decode(base58_string: &str) -> Vec<u8> {
    let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Convert Base58 string to a big integer
    let base: BigUint = BigUint::from(58u32);
    let value_decimal: BigUint =
        base58_string
            .chars()
            .rev()
            .enumerate()
            .fold(BigUint::zero(), |acc, (i, c)| {
                let pos = base58_alphabet
                    .find(c)
                    .expect("Invalid character in Base58 string");
                let value = BigUint::from(pos) * base.pow(i as u32);
                acc + value
            });
    // Convert the integer to bytes
    let value_bytes = value_decimal.to_bytes_be();
    // Chop off the 32 checksum bits and return
    let (data_with_version_byte, checksum) = value_bytes.split_at(value_bytes.len() - 4);
    // BONUS POINTS: Verify the checksum!
    let mut hasher = Sha256::new();
    hasher.update(data_with_version_byte);
    let hashed = hasher.finalize();
    let mut hasher2 = Sha256::new();
    hasher2.update(&hashed);
    let hash_of_hash = hasher2.finalize();
    let calculated_checksum = &hash_of_hash[0..4];
    // println!("Calculated checksum: {:?}", calculated_checksum);
    assert_eq!(calculated_checksum, checksum);
    value_bytes.to_vec()
}

// Deserialize the extended key bytes and return a JSON object
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
// 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
// 32 bytes: the chain code
// 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
fn deserialize_key(bytes: &[u8]) -> ExKey {
    ExKey {
        version: bytes[0..4].try_into().unwrap(),
        depth: [bytes[4]],
        finger_print: bytes[5..9].try_into().unwrap(),
        child_number: bytes[9..13].try_into().unwrap(),
        chaincode: bytes[13..45].try_into().expect("chaincode"),
        key: bytes[45..78].try_into().expect("failed key"),
    }
}

// Derive the secp256k1 compressed public key from a given private key
// BONUS POINTS: Implement ECDSA yourself and multiply you key by the generator point!
fn derive_public_key_from_private(key: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&key[1..]).expect("Expected 32 bytes");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    public_key.serialize().to_vec()
}

// Perform a BIP32 parent private key -> child private key derivation
// Return a derived child Xpriv, given a child_number. Check the struct docs for APIs.
// Key derivation steps: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Private_parent_key_rarr_private_child_key
fn derive_priv_child(key: ExKey, child_num: u32) -> ExKey {
    assert!(key.key.len() == 33, "Key should be 33 bytes long");

    let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
    let mut data = Vec::with_capacity(37);

    let hardned = child_num >= 2147483648;
    if hardned {
        data.extend_from_slice(&key.key);
    } else {
        data.extend_from_slice(&derive_public_key_from_private(&key.key));
    }
    data.extend_from_slice(&child_num.to_be_bytes());

    let mut mac =
        HmacSha512::new_from_slice(&key.chaincode).expect("HMAC can take key of any size");
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    let (left, right) = result.split_at(32);
    let k_i = (BigUint::from_bytes_be(left) + BigUint::from_bytes_be(&key.key)) % &n;
    let mut k_i_bytes = k_i.to_bytes_be();
    while k_i_bytes.len() < 32 {
        k_i_bytes.insert(0, 0);
    }
    let mut key_bytes = [0; 33];
    key_bytes[1..].copy_from_slice(&k_i_bytes);
    ExKey {
        version: key.version,
        depth: [key.depth[0] + 1],
        finger_print: [0; 4],
        child_number: child_num.to_be_bytes(),
        chaincode: right.try_into().unwrap(),
        key: key_bytes,
    }
}

// Given an extended private key and a BIP32 derivation path, compute the child private key found at the path
fn get_child_key_at_path(key: ExKey, derivation_path: &str) -> ExKey {
    let mut derived_key = key.clone();
    // skip 'm'
    for component in derivation_path.split('/').skip(1) {
        let hardened = component.ends_with("'") || component.ends_with("h");
        let index_str = component.trim_end_matches("'").trim_end_matches("h");
        let child_num = index_str.parse::<u32>().expect("Invalid child number");

        // Adjust child_num for hardened keys
        let child_num = if hardened {
            child_num + 2147483648
        } else {
            child_num
        };
        derived_key = derive_priv_child(derived_key, child_num);
    }
    derived_key
}

// Compute the first N child private keys.
// Return an array of keys.
fn get_keys_at_child_key_path(child_key: ExKey, num_keys: u32) -> Vec<ExKey> {
    let mut keys = Vec::with_capacity(num_keys as usize);
    for i in 0..num_keys {
        let key = derive_priv_child(child_key.clone(), i);
        keys.push(key);
    }
    keys
}

// Derive the p2wpkh witness program (aka scriptPubKey) for a given compressed public key
// Return a bytes array to be compared with the JSON output of Bitcoin Core RPC getblock
// so we can find our received transactions in blocks
// These are segwit version 0 pay-to-public-key-hash witness programs
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-P2WPKH
fn get_p2wpkh_program(pubkey: &[u8]) -> Vec<u8> {
    let sha256_hash = Sha256::digest(pubkey);
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);

    let mut script = Vec::with_capacity(22);
    script.push(0x00); // Witness version 0
    script.push(0x14); // Push the size of the key hash (20 bytes)
    script.extend_from_slice(&ripemd160_hash);
    script
}

// Assuming Bitcoin Core is running and connected to signet using default datadir,
// execute an RPC and return its value or error message.
// https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
// Examples: bcli("getblockcount")
//            bcli("getblockhash 100")
fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
    let args = cmd.split(' ').collect::<Vec<&str>>();

    let result = Command::new("bitcoin-cli")
        .args(&args)
        .output()
        .map_err(|_| BalanceError::MissingCodeCantRun)?;

    if result.status.success() {
        return Ok(result.stdout);
    } else {
        eprintln!(
            "BTC cli error: \nCommand args: {:?}\n{:#?}",
            args,
            String::from_utf8(result.stderr)
        );
        return Err(BalanceError::ErrorOnBtcCli);
    }
}

pub fn extract_base58(extended_private_key: &str) -> &str {
    let begin = extended_private_key
        .find("(")
        .expect("Could't find the initial '(' char");
    let end = extended_private_key
        .find("/")
        .expect("Could't find the final '/' char");
    return &extended_private_key[begin + 1..end];
}

pub fn extract_descriptor(extended_private_key: &str) -> &str {
    let begin = extended_private_key
        .find("(")
        .expect("Could't find the initial '(' char");
    let end = extended_private_key
        .find("/")
        .expect("Could't find the final '/' char");
    return &extended_private_key[begin + 1..end];
}

fn base58_encode(key: &[u8]) -> String {
    let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut key_num = BigUint::from_bytes_be(key);
    let base = BigUint::from(58_u32);
    let mut result = String::new();
    while key_num > BigUint::zero() {
        let remainder: usize = (&key_num % &base)
            .try_into()
            .expect("Failed to convert to usize");
        key_num /= &base;
        result.push(
            base58_alphabet
                .chars()
                .nth(remainder)
                .expect("Invalid index"),
        );
    }
    for &byte in key.iter() {
        if byte == 0 {
            result.push('1');
        } else {
            break;
        }
    }
    result.chars().rev().collect()
}

// public function that will be called by `run` here as well as the spend program externally
pub fn recover_wallet_state(
    extended_private_key: &str,
    cookie_filepath: &str,
) -> Result<WalletState, BalanceError> {
    let decoded_key_bytes = base58_decode(extract_base58(EXTENDED_PRIVATE_KEY));
    // Deserialize the provided extended private key
    let deserialized_key = deserialize_key(&decoded_key_bytes);
    // Derive the key and chaincode at the path in the descriptor (`84h/1h/0h/0`)
    let derivation_path = "m/84'/1'/0'/0";
    // Get the child key at the derivation path
    let child_key = get_child_key_at_path(deserialized_key, derivation_path);
    // Compute 2000 private keys from the child key path
    let private_keys = get_keys_at_child_key_path(child_key, 2000);
    let mut public_keys = HashSet::new();
    let mut witness_programs = HashSet::new();

    for key in private_keys.iter() {
        let public_key = derive_public_key_from_private(&key.key);
        public_keys.insert(public_key.clone());

        let witness_program = get_p2wpkh_program(&public_key);
        witness_programs.insert(witness_program);
    }
    let mut outgoing_txs: Vec<Vec<u8>> = vec![];
    let mut my_vouts_by_txid: HashMap<String, Vec<u32>> = HashMap::new();
    let mut spending_txs: Vec<Vec<u8>> = vec![];
    let mut utxos: Vec<Vec<u8>> = vec![];

    // FIXME: horrible bcli usage
    let latest_block_result = bcli(&format!("-signet getblockcount"))?;
    let latest_block_count = std::str::from_utf8(&latest_block_result)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    let start_block = 1;
    let end_block = latest_block_count.min(310);

    for block_number in start_block..=end_block {
        // FIXME: horrible bcli usage
        let block_hash_cmd = format!("-signet getblockhash {}", block_number);
        //println!("Executing: {}", block_hash_cmd);
        let block_hash_result = bcli(&block_hash_cmd).unwrap();
        let block_hash = std::str::from_utf8(&block_hash_result).unwrap().trim();

        let block_cmd = format!("-signet getblock {}", block_hash);
        //println!("Executing: {}", block_cmd);
        let block_result = bcli(&block_cmd).unwrap();
        let block_data = std::str::from_utf8(&block_result).unwrap();

        let block_json: Value = match serde_json::from_str(block_data) {
            Ok(data) => data,
            Err(error) => {
                anyhow::anyhow!(error);
                continue;
            }
        };

        //
        // FIXME: refactor this papiro ridiculous code
        //
        //println!("Processing block: {}/{}", block_number, end_block);
        if let Some(transactions) = block_json["tx"].as_array() {
            for tx in transactions {
                let txd: &str = tx.as_str().unwrap();
                let gettrans = format!("-signet getrawtransaction {} 2 {}", txd, block_hash);
                let trans_result = bcli(&gettrans).unwrap();
                let trans_data = std::str::from_utf8(&trans_result).unwrap();
                let transaction: Value = match serde_json::from_str(trans_data) {
                    Ok(data) => data,
                    Err(error) => {
                        anyhow::anyhow!(error);
                        continue;
                    }
                };
                if let Some(vout) = transaction["vout"].as_array() {
                    for output in vout {
                        if let Some(script_pub_key) = output.get("scriptPubKey") {
                            //println!("{}", script_pub_key);
                            if let Some(typ) = script_pub_key.get("type") {
                                match typ.as_str() {
                                    Some("witness_v0_keyhash") => {
                                        let hex_key =
                                            script_pub_key.get("hex").unwrap().as_str().unwrap();
                                        if witness_programs.contains(&hex::decode(hex_key).unwrap())
                                        {
                                            outgoing_txs
                                                .push(serde_json::to_vec(&transaction).unwrap());
                                            //println!("{:#?}", vout);
                                            let vouts = my_vouts_by_txid
                                                .entry(txd.to_string())
                                                .or_insert(vec![]);
                                            vouts.push(
                                                output
                                                    .get("n")
                                                    .unwrap()
                                                    .as_i64()
                                                    .unwrap()
                                                    .try_into()
                                                    .unwrap(),
                                            );
                                        }
                                    }
                                    Some(_) => {}
                                    None => {}
                                }
                            }
                        }
                    }
                }
                //Check every tx input (witness) for our own compressed public keys. These are coins we have spent.
                if let Some(vin) = transaction["vin"].as_array() {
                    for input in vin {
                        //println!("{:#?}", input);
                        if let Some(txinwitness) = input.get("txinwitness").unwrap().as_array() {
                            if txinwitness.len() == 2 {
                                let tx_pub_key = txinwitness[1].as_str().unwrap();
                                let tx_pub_key_bytes = hex::decode(tx_pub_key)
                                    .expect("Invalid hex code for txinwitness pubkey");
                                if public_keys.contains(&tx_pub_key_bytes) {
                                    spending_txs.push(serde_json::to_vec(&transaction).unwrap());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut spent_txid_vout: HashMap<String, HashSet<u32>> = HashMap::new();
    for transaction in spending_txs {
        let tx_data: Value = serde_json::from_slice(&transaction).expect("Unable to decode json");
        //println!("{:#?}", tx_data);
        if let Some(vin) = tx_data["vin"].as_array() {
            for input in vin {
                let txid = input.get("txid").expect("Missing txid").as_str().unwrap();
                let vout = input.get("vout").expect("Missing vout").as_i64().unwrap();
                //println!("txid: {}, vout: {}", txid, vout);
                spent_txid_vout
                    .entry(txid.to_string())
                    .and_modify(|values| {
                        values.insert(vout.try_into().unwrap());
                    })
                    .or_insert(HashSet::from([vout.try_into().unwrap()]));
            }
        }
    }
    for transaction in outgoing_txs {
        let tx_data: Value = serde_json::from_slice(&transaction).unwrap();
        let txid = tx_data["txid"].as_str().unwrap();
        if let Some(vouts) = tx_data["vout"].as_array() {
            for vout_n in my_vouts_by_txid.get(txid).unwrap() {
                let my_vout = &vouts[*vout_n as usize];
                if spent_txid_vout
                    .get(txid)
                    .is_some_and(|v| v.contains(vout_n))
                {
                    //println!(
                    //    "Spent   tx: {}, n: {}, value: {}",
                    //    txid,
                    //    vout_n,
                    //    &my_vout.get("value").unwrap()
                    //);
                    // println!("tx: {}, n: {}, vout: {:?}", txid, vout_n, my_vout);
                } else {
                    //println!(
                    //    "Unspent tx: {}, n: {}, value: {}",
                    //    txid,
                    //    vout_n,
                    //    &my_vout.get("value").unwrap()
                    //);

                    utxos.push(
                        my_vout
                            .get("value")
                            .unwrap()
                            .as_f64()
                            .unwrap()
                            .to_be_bytes()
                            .to_vec(),
                    );
                }
            }
        }

        //match txid_vout.get(txid) {
        //    Some(vout_index) => {

        //        //if let Some(vout) = tx_data["vout"].as_array() {
        //        //    let output = &vout[*vout_index];
        //        //    let value = &output["value"]
        //        //        .as_f64()
        //        //        .expect("Failed to decode value as f64");
        //        //    //println!("Spent: {:#?}", &value);
        //        //}
        //    }
        //    None => {
        //        // utxo
        //        let my_vouts = my_vouts_by_txid.get(txid).unwrap();
        //        let vouts = tx_data["vout"].as_array();
        //        for my_vout in my_vouts {
        //            println!("Vouts: {:#?}", my_vout);
        //        }
        //        let utxo_value: Vec<u8> = vec![];
        //        utxos.push(utxo_value);
        //    }
        //}
    }

    // Check every tx input (witness) for our own compressed public keys. These are coins we have spent.
    // Check every tx output for our own witness programs. These are coins we have received.
    // Keep track of outputs by their outpoint so we can check if it was spent later by an input
    // Collect outputs that have not been spent into a utxo set
    // Return Wallet State
    Ok(WalletState {
        utxos,
        public_keys: public_keys.into_iter().collect(),
        private_keys: private_keys.into_iter().map(|k| k.key.to_vec()).collect(),
        witness_programs: witness_programs.into_iter().collect(),
    })
}

fn hash_public_key(pubkey: &[u8]) -> Vec<u8> {
    // Assuming get_p2wpkh_program generates the full scriptPubKey including version and length bytes
    get_p2wpkh_program(pubkey).to_vec()
}

pub fn run(rpc_cookie_filepath: &str) -> Result<(), ()> {
    let utxos = recover_wallet_state(EXTENDED_PRIVATE_KEY, rpc_cookie_filepath).unwrap();
    let balance = utxos.balance();
    println!("{} {:.8}", WALLET_NAME, balance);
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{
        base58_decode, base58_encode, derive_priv_child, derive_public_key_from_private,
        deserialize_key, extract_base58, get_child_key_at_path, get_keys_at_child_key_path,
        get_p2wpkh_program, ExKey, EXTENDED_PRIVATE_KEY,
    };
    use bs58;
    use sha2::{Digest, Sha256, Sha512};

    #[test]
    fn test_extract_base58_from_extended_private_key() {
        let base58_string = extract_base58(EXTENDED_PRIVATE_KEY);
        assert_eq!(base58_string, "tprv8ZgxMBicQKsPeDsCumcxgvEWN7usEqePaobYYM7r5ABem6hbM8aYKj42eCxgEmDrYd4xSrH5faBReXhcXGZbMNJnAkm4oxEsAQkTpKkXdZL");
    }

    #[test]
    fn test_decode_base58() {
        let base58_string = extract_base58(EXTENDED_PRIVATE_KEY);
        let bytes = base58_decode(base58_string);
        assert_eq!(
            bytes,
            vec![
                4, 53, 131, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 135, 141, 251, 49, 228, 93, 140, 124,
                159, 184, 75, 165, 29, 191, 9, 45, 148, 99, 95, 75, 125, 50, 66, 185, 25, 81, 33,
                167, 40, 97, 137, 29, 0, 222, 75, 162, 129, 97, 71, 183, 119, 57, 29, 131, 11, 238,
                147, 207, 239, 167, 6, 242, 51, 137, 24, 102, 220, 89, 160, 76, 34, 115, 25, 88,
                187, 147, 245, 35, 195
            ]
        );
    }

    #[test]
    fn test_encode_base58() {
        let base58_string = extract_base58(EXTENDED_PRIVATE_KEY);
        let bytes = vec![
            4, 53, 131, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 135, 141, 251, 49, 228, 93, 140, 124, 159,
            184, 75, 165, 29, 191, 9, 45, 148, 99, 95, 75, 125, 50, 66, 185, 25, 81, 33, 167, 40,
            97, 137, 29, 0, 222, 75, 162, 129, 97, 71, 183, 119, 57, 29, 131, 11, 238, 147, 207,
            239, 167, 6, 242, 51, 137, 24, 102, 220, 89, 160, 76, 34, 115, 25, 88, 187, 147, 245,
            35, 195,
        ];
        assert_eq!(base58_encode(&bytes), base58_string);
    }

    #[test]
    fn test_deserialize_master_key() {
        let base58_string = extract_base58(EXTENDED_PRIVATE_KEY);
        let base58_decoded = base58_decode(&base58_string);
        let deserialized = deserialize_key(&base58_decoded);

        assert_eq!(deserialized.version, [0x04, 0x35, 0x83, 0x94]);
        assert_eq!(deserialized.depth, [0x00]);

        assert_eq!(deserialized.finger_print, [0x00; 4]);
        assert_eq!(deserialized.child_number, [0x00; 4]);
    }

    #[test]
    fn test_deserialize_master_key2() {
        let base58_string = "xprv9s21ZrQH143K3Fvpg64L6GCe8fVkP9LeLCVKyK1B3amfYDrhcZ6e5wZHcPivoVxvpuyGpbCMfT3qD3PeYbNmXB2SrfgWTAVbDwSmxT1EpHj";
        let base58_decoded = base58_decode(&base58_string);
        let deserialized = deserialize_key(&base58_decoded);

        assert_eq!(deserialized.version, [0x04, 0x88, 0xad, 0xe4]);
        assert_eq!(deserialized.depth, [0x00]);
        assert_eq!(deserialized.finger_print, [0x00; 4]);
        assert_eq!(
            deserialized.chaincode,
            hex::decode("787b1375b503093b192c4092b3af79d735afdc9e77811ed5620feb4b67715c77")
                .unwrap()[..]
        );
        assert_eq!(
            deserialized.key,
            hex::decode("00a20c006354d00ad2ae07e55e31b7a17d8d60b74745ec777eeb5e9ae703dff028")
                .unwrap()[..]
        );
    }

    #[test]
    fn test_derive_child_priv() {
        let priv_key: Vec<u8> =
            hex::decode("0069facdd19cd20ba5484ffa3a651ba749acc77dcfa54988f1b178e8cac44dae46")
                .unwrap();
        let chaincode: Vec<u8> =
            hex::decode("aab064f8ebf229408083a0b341d0c4297b6cd3717141383b42d3dc833ef1f0f5")
                .unwrap();

        let ex_key = ExKey {
            version: [0x04, 0x35, 0x83, 0x94],
            depth: [0x00],
            finger_print: [0x00; 4],
            child_number: [0x00; 4],
            chaincode: chaincode.try_into().unwrap(),
            key: priv_key.try_into().unwrap(),
        };
        let derived_priv_child = derive_priv_child(ex_key.clone(), 2147483648); //0'
        assert_eq!(
            hex::encode(derived_priv_child.key),
            "003136fdff6a23c71986b0adc6f9d81e7865101a74c5598d782aa6ecaf249d4732"
        );
        let derived_priv_child = derive_priv_child(ex_key.clone(), 2147483649); //1'
        assert_eq!(
            hex::encode(derived_priv_child.key),
            "00b25d9ffff7e3cbb91336d4fe4f7d0afd862a3236e9b1fa0616ebc7ebb2baf2a9"
        );
    }

    #[test]
    fn test_get_child_key_at_path() {
        let priv_key: Vec<u8> =
            hex::decode("00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
                .unwrap();
        let chaincode: Vec<u8> =
            hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
                .unwrap();

        let ex_key = ExKey {
            version: [0x04, 0x35, 0x83, 0x94],
            depth: [0x00],
            finger_print: [0x00; 4],
            child_number: [0x00; 4],
            chaincode: chaincode.try_into().unwrap(),
            key: priv_key.try_into().unwrap(),
        };
        let derived_hardned_child_0 = get_child_key_at_path(ex_key.clone(), "m/0'");
        assert_eq!(
            hex::encode(derived_hardned_child_0.key),
            "00edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        let derived_hardned_normal_child = get_child_key_at_path(ex_key.clone(), "m/0'/1");
        assert_eq!(
            hex::encode(derived_hardned_normal_child.key),
            "003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        let derived_long_path = get_child_key_at_path(ex_key.clone(), "m/0'/1/2'/2/1000000000");
        assert_eq!(
            hex::encode(derived_long_path.key),
            "00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        );
        assert_eq!(
            hex::encode(derived_long_path.chaincode),
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
        );
    }

    #[test]
    fn test_get_n_childs() {
        let priv_key: Vec<u8> =
            hex::decode("00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
                .unwrap();
        let chaincode: Vec<u8> =
            hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
                .unwrap();

        let ex_key = ExKey {
            version: [0x04, 0x35, 0x83, 0x94],
            depth: [0x00],
            finger_print: [0x00; 4],
            child_number: [0x00; 4],
            chaincode: chaincode.try_into().unwrap(),
            key: priv_key.try_into().unwrap(),
        };
        let derived_long_path = get_child_key_at_path(ex_key.clone(), "m/0'/1/2'");
        let children = get_keys_at_child_key_path(derived_long_path, 100);
        assert_eq!(
            hex::encode(children[2].key),
            "000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
        );
    }

    #[test]
    fn test_derive_pub_key() {
        let priv_key: Vec<u8> =
            hex::decode("00081549973bafbba825b31bcc402a3c4ed8e3185c2f3a31c75e55f423e9629aa3")
                .unwrap();

        let pub_key = derive_public_key_from_private(&priv_key);
        assert_eq!(
            hex::encode(pub_key),
            "0343b337dec65a47b3362c9620a6e6ff39a1ddfa908abab1666c8a30a3f8a7cccc"
        );
    }

    #[test]
    fn test_p2wpkh_program() {
        let pub_key_hex = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
        let pub_key_bytes = hex::decode(pub_key_hex).unwrap();
        let p2wpkh = hex::encode(get_p2wpkh_program(&pub_key_bytes));
        assert_eq!(p2wpkh, "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1");
    }
}
