extern crate balance;
use balance::{bcli, recover_wallet_state, EXTENDED_PRIVATE_KEY};

use hex;
use tracing::debug;
use tracing_subscriber;

use serde_json::Value;

use spend::{spend_p2wpkh, spend_p2wsh};

fn print_fields(tx_hex: &str) {
    let version = &tx_hex[0..8];
    let marker = &tx_hex[8..10];
    let flag = &tx_hex[10..12];
    let input_count = &tx_hex[12..14];
    let input_tx = &tx_hex[14..78];
    let input_prev_output_idx = &tx_hex[78..86];
    let input_length = &tx_hex[86..88];
    let sequence = &tx_hex[88..96];

    debug!("Version: {}", version);
    debug!("Marker: {}", marker);
    debug!("Flag: {}", flag);
    debug!("Input Count: {}", input_count);
    debug!("Input tx: {}", input_tx);
    debug!("Input prev output idx: {}", input_prev_output_idx);
    debug!("Input script length: {}", input_length);
    debug!("Sequence: {}", sequence);

    let output_count = hex::decode(&tx_hex[96..98]).unwrap()[0];
    let mut last_output_end = 98;
    debug!("Output Count: {}", output_count);
    for _ in 0..output_count {
        let output_value = &tx_hex[last_output_end..last_output_end + 16];
        let output_length = &tx_hex[last_output_end + 16..last_output_end + 18];
        let output_length_u8: u8 = hex::decode(output_length).unwrap()[0];
        let output_script = if output_length_u8 > 0 {
            &tx_hex[last_output_end + 18..last_output_end + 18 + (output_length_u8 as usize * 2)]
        } else {
            ""
        };
        last_output_end += 18 + (output_length_u8 as usize * 2);
        debug!(
            "Output Value: {}",
            u64::from_le_bytes(hex::decode(output_value).unwrap().try_into().unwrap())
        );
        debug!("Output Length: {}", output_length);
        debug!("Output Script: {}", output_script);
    }
    //let witness_count = hex::decode(&tx_hex[last_output_end..last_output_end + 2]).unwrap()[0];
    //debug!("Witness Count: {}", witness_count);
    //let mut last_witness_end = last_output_end + 2;
    //for _ in 0..witness_count {
    //    let witness_length = &tx_hex[last_witness_end..last_witness_end + 2];
    //    let witness_length_u8: u8 = hex::decode(witness_length).unwrap()[0];
    //    let witness =
    //        &tx_hex[last_witness_end + 2..last_witness_end + 2 + (witness_length_u8 as usize * 2)];
    //    last_witness_end += 2 + (witness_length_u8 as usize * 2);
    //    debug!("Witness Length: {}", witness_length);
    //    debug!("Witness: {}", witness);
    //}
    //let locktime = &tx_hex[last_witness_end..last_witness_end + 8];
    //debug!("Locktime: {}", locktime);
    //let sighash = &tx_hex[last_witness_end + 8..last_witness_end + 16];
    //debug!("Sighash: {}", sighash);
    //let txid = &tx_hex[last_witness_end + 16..last_witness_end + 16 + 64];
    //debug!("Txid: {}", txid);
}

fn main() {
    tracing_subscriber::fmt::init();
    // Default Bitcoin Core cookie path
    let cookie_filepath = "~/.bitcoin/signet/.cookie";

    let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY, cookie_filepath).unwrap();
    let (txid1, tx1) = spend_p2wpkh(&wallet_state).unwrap();

    let txhex = &hex::encode(&tx1);
    print_fields(txhex);
    println!("tx1: {:?}", txhex);

    let decoderawtransaction = bcli(&format!("-signet decoderawtransaction {}", txhex)).unwrap();
    let trans: Value = serde_json::from_slice(&decoderawtransaction).unwrap();
    println!("decoderawtransaction: {:#?}", trans);

    let mempool_resp = bcli(&format!("-signet testmempoolaccept [\"{}\"]", txhex)).unwrap();
    let mempool: Value = serde_json::from_slice(&mempool_resp).unwrap();
    println!("mempool_resp: {:#?}", mempool);

    let tx2 = spend_p2wsh(&wallet_state, txid1).unwrap();
    println!("tx2: {:?}", tx2);
}
