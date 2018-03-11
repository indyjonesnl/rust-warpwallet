
extern crate hex;
extern crate xor;
extern crate time;
extern crate rand;

mod pbkdf2;
mod scrypt;
mod warpwallet;
mod bitcoin;
mod hexxor;
mod sha256;

use time::PreciseTime;
use rand::{thread_rng, Rng};
use std::thread;

// println! in tests are only visible with:
//      cargo test -- --nocapture
// or when running 1 test function
//      cargo test name_of_function -- --nocapture

const WARP_WALLET_SALT: &str = "a@b.c";
const WARP_WALLET_SEARCH: &str = "1MkupVKiCik9iyfnLrJoZLx9RH4rkF3hnA";

fn main() {
    let start = PreciseTime::now();

    // A simple speed test, to see how long it takes to generate this many new warpwallet addresses.
    generate_new_keypair(20);

    let end = PreciseTime::now();
    println!("{} seconds for this round.", start.to(end));
}

#[test]
fn test_hex_decode() {
    println!("{:?}", hex::decode("aa2d3c4a4ae6559e9f13f093cc6e32459c5249da723de810651b4b54373385e2").unwrap());
}

// bitcoin: 1Awesome4ZhNYmUp5PApkz1qQMVkkVYLhA
// dogecoin: DJonesU36d76kN83wM9sdqddxKFVCYdyPf
//
// ___________((_____))
// ____________))___((
// ___________((_____))
// ____________))___((
// ___________((_____))____________$$$$$$
// ____________))___((____________$$____$$
// _$$$$$$$$$$$$$$$$$$$$$$$$$$$$$______$$
// __$$$$$$$$$$$$$$$$$$$$$$$$$$$_______$$
// ___$$$$$$$$$$$$$$$$$$$$$$$$________$$
// ____$$$$$$$$$$$$$$$$$$$$$$________$$
// ____$$$$$$$$$$$$$$$$$$$$$$______$$
// _____$$$$$$$$$$$$$$$$$$$$_____$$
// _____$$$$$$$$$$$$$$$$$$$$$$$$$
// ______$$$$$$$$$$$$$$$$$$
// _______$$$$$$$$$$$$$$$$
// _________$$$$$$$$$$$$
// ___________$$$$$$$$
// _$$$$$$$$$$$$$$$$$$$$$$$$$$$$
// ___$$$$$$$$$$$$$$$$$$$$$$$$
// _____$$$$$$$$$$$$$$$$$$$$__

fn generate_new_keypair(iterations: usize) {
    for i in 0..iterations {
        // Generate random string of 8 chars
        let random_string = generate_random_string(8);
        let exp = warpwallet::warpwallet(&random_string, WARP_WALLET_SALT);
        let uncompressed_private = bitcoin::secret_exponent_to_private_key(exp.clone(), false);
        let uncompressed_addr = bitcoin::private_key_wif_to_public_address(&uncompressed_private);
        let compressed_private = bitcoin::secret_exponent_to_private_key(exp, true);
        let compressed_addr = bitcoin::private_key_wif_to_public_address(&compressed_private);

        // Print the resulting address anyway
        println!("{}: {} uncompressed {} {}", i, random_string, uncompressed_addr, uncompressed_private);
        println!("{}: {} compressed {} {}", i, random_string, compressed_addr, compressed_private);

       if WARP_WALLET_SEARCH == uncompressed_addr {
           println!("== ADDRESS FOUND == {}", &uncompressed_addr);
       } else if WARP_WALLET_SEARCH == compressed_addr {
           println!("== ADDRESS FOUND == {}", &compressed_addr);
       }
    }
}

fn generate_random_string(char_length: usize) -> String {
    let handle = thread::spawn(move || {
        thread_rng()
            .gen_ascii_chars()
            .take(char_length)
            .collect::<String>()
    });
    handle.join().unwrap()
}

#[test]
fn test_generate_random_string() {
    let char_length = 8;
    for _i in 0..10 {
        let random_string = generate_random_string(char_length);
        assert_eq!(char_length, random_string.len());
    }
}

#[test]
fn test_from_hex() {
    assert_eq!(
        hex::decode("48656c6c6f20776f726c6421"),
        Ok("Hello world!".to_owned().into_bytes())
    );
}

#[test]
fn test_to_hex() {
    assert_eq!("666f6f626172", hex::encode("foobar"));
    assert_eq!("68656c6c6f20776f726c64", hex::encode("hello world"));
    assert_eq!("48656c6c6f20776f726c6421", hex::encode("Hello world!"));
}
