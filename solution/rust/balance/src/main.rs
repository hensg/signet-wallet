use balance::{recover_wallet_state, EXTENDED_PRIVATE_KEY, WALLET_NAME};

fn main() {
    // Default Bitcoin Core cookie path
    let cookie_filepath = "~/.bitcoin/signet/.cookie";

    let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY, cookie_filepath).unwrap();
    let balance = wallet_state.balance() as f64 / 100_000_000.0;

    println!("{} {:.8}", WALLET_NAME, balance);
}
