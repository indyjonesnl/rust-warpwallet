
extern crate hex;
extern crate xor;
extern crate threadpool;
extern crate time;
extern crate rand;

mod pbkdf2;
mod scrypt;
mod warpwallet;
mod bitcoin;
mod hexxor;
mod sha256;
mod threadtest;

use time::PreciseTime;
use rand::{thread_rng, Rng};
use std::thread;

use threadpool::ThreadPool;
use std::sync::mpsc;
use std::sync::mpsc::channel;

// println! in tests are only visible with:
//      cargo test -- --nocapture
// or when running 1 test function
//      cargo test name_of_function -- --nocapture

const WARP_WALLET_SALT: &str = "a@b.c";
const WARP_WALLET_SEARCH: &str = "1MkupVKiCik9iyfnLrJoZLx9RH4rkF3hnA";

fn main() {
    let start = PreciseTime::now();
    let iterations = 50;

    let (tx, rx): (mpsc::Sender<Vec<String>>, mpsc::Receiver<Vec<String>>) = mpsc::channel();

    const SALT: [u8;5] = [97, 64, 98, 46, 99]; // a@b.c

    for _inner_index in 0..iterations {
        let cloned_tx = tx.clone();
        thread::spawn(move || {
            cloned_tx.send(warpwallet::print_phrase_wif_address_warp_wallet(generate_random_string(8).as_bytes().to_vec(), SALT.to_vec()));
        });
    }

    for index in 0..iterations {
        let result = rx.recv().unwrap();
        println!("phrase [{}], wif [{}], addr [{}]", result[0], result[1], result[2]);
        warpwallet::print_if_address_matches(&result[2]);
    }

    let end = PreciseTime::now();
    let run_time = start.to(end);
    println!("{} seconds for this round.", run_time);
    println!("That's {} seconds per phrase.", run_time/iterations);
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

fn generate_random_string(char_length: usize) -> String {
    thread::spawn(move || {
        thread_rng()
            .gen_ascii_chars()
            .take(char_length)
            .collect::<String>()
    }).join().unwrap()
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
