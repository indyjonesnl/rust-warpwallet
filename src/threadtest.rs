use std::thread;
use rand::{thread_rng, Rng};
use std::sync::mpsc;
use time::PreciseTime;
use bitcoin;
use xor;

use warpwallet;
use warpwallet::add_byte_to_string;

fn thread_test_simple() {
    let (tx, rx): (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::channel();
    let tx2 = tx.clone();

    // WIF: 5JzYGkShwKTyXafZtv3SkYmZAaBTThzRPVgitZxcYp3T6SjejzP
    // Address: 1FvYwuowDY1xhbwXFcvCHJP9qyfWw2A89X

    let pass_phrase = "Passphrase";
    let pass_phrase_2 = pass_phrase.to_owned();
    let salt = "a@b.c";

    thread::spawn(move || {
        let s1 = warpwallet::perform_warp_scrypt(&pass_phrase, salt);
        tx.send(s1);
    });

    thread::spawn(move || {
        let s2 = warpwallet::perform_warp_pbkdf2(&pass_phrase_2, salt);
        tx2.send(s2);
    });

    let (s3tx, s3rx): (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::channel();
    thread::spawn(move || {
        let s1 = rx.recv().unwrap();
        let s2 = rx.recv().unwrap();
        let s3 = xor::xor(&s1, &s2);
        s3tx.send(s3);
    });

    let s3 = s3rx.recv().unwrap();
    let wif = bitcoin::secret_exponent_to_private_key(s3, false);
    let address = bitcoin::private_key_wif_to_public_address(&wif);
    println!("Result: {:?}", address);
}

fn generate_random_string(char_length: usize) -> String {
    thread::spawn(move || {
        thread_rng()
            .gen_ascii_chars()
            .take(char_length)
            .collect::<String>()
    }).join().unwrap()
}

fn generate_random_bytes(byte_count: usize) -> Vec<u8> {
    thread::spawn(move || {
        thread_rng()
            .gen_ascii_chars()
            .take(byte_count)
            .collect::<String>()
            .as_bytes()
            .to_vec()
    }).join().unwrap()
}

#[test]
fn speed_test_serial() {
    let iterations = 32;

    let start = PreciseTime::now();

    const SALT: [u8;5] = [97, 64, 98, 46, 99]; // a@b.c

    for index in 0..iterations {
        let result = warpwallet::print_phrase_wif_address_warp_wallet(generate_random_bytes(8), SALT.to_vec());
        println!("phrase [{}], wif [{}], addr [{}]", result[0], result[1], result[2]);
        warpwallet::print_if_address_matches(&result[2]);
    }

    let end = PreciseTime::now();
    let run_time = start.to(end);
    println!("{} seconds for this round.", run_time);
    println!("That's {} seconds per phrase.", run_time / iterations);
}

#[test]
fn speed_test_parallel() {
    let start = PreciseTime::now();
    let iterations = 12;

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