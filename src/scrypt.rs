
extern crate hex;
extern crate crypto;

use self::crypto::scrypt::{scrypt, ScryptParams};
use std::thread;

const WARP_SCRYPT_ITERATIONS: u32 = 262144; // 2^18
const WARP_KEY_LENGTH: usize = 32;
const WARP_SCRYPT_CONCAT: &str = "\x01";
const WARP_SCRYPT_MEM_DIFF: u32 = 8;
const WARP_SCRYPT_PAR_DIFF: u32 = 1;

pub fn perform_scrypt_bytes(pass_phrase: Vec<u8>, salt: Vec<u8>, cpu_difficulty: u32, mem_difficulty: u32, parallel_difficulty: u32, key_length: usize) -> Vec<u8> {
    let handle = thread::spawn(move || {
        let mut to_store = vec![0u8; key_length];
        let params: ScryptParams = ScryptParams::new( log2(cpu_difficulty), mem_difficulty, parallel_difficulty);
        scrypt(&pass_phrase, &salt, &params, &mut to_store);
        // return the byte array
        to_store
    });
    handle.join().unwrap()
}

pub fn perform_scrypt(pass_phrase: &str, salt: &str, cpu_difficulty: u32, mem_difficulty: u32, parallel_difficulty: u32, key_length: usize) -> Vec<u8> {
    let params = ScryptParams::new( log2(cpu_difficulty), mem_difficulty, parallel_difficulty );

    let mut to_store = vec![ 0u8; key_length ];
    scrypt(pass_phrase.as_bytes(), salt.as_bytes(), &params, &mut to_store);
    // return the byte array
    to_store
}

pub fn perform_warp_scrypt(pass_phrase: &str, salt: &str) -> Vec<u8> {

//    // Im thinking something like...
//    let mut phrase_bytes: Vec<u8> = pass_phrase.as_bytes().to_vec();
//    phrase_bytes.push(0x02);
//
//    let mut salt_bytes: Vec<u8> = salt.as_bytes().to_vec();
//    salt_bytes.push(0x02);
//
//    perform_scrypt_bytes(phrase_bytes, salt_bytes)

    // There has to be a more efficient way to append 1 stupid byte to a byte array...
    let mut passphrase_extended = pass_phrase.to_string();
    passphrase_extended.push_str(WARP_SCRYPT_CONCAT);
    let mut salt_extended = salt.to_string();
    salt_extended.push_str(WARP_SCRYPT_CONCAT);
    perform_scrypt_bytes(
        passphrase_extended.as_bytes().to_vec(),
        salt_extended.as_bytes().to_vec(),
        WARP_SCRYPT_ITERATIONS,
        WARP_SCRYPT_MEM_DIFF,
        WARP_SCRYPT_PAR_DIFF,
        WARP_KEY_LENGTH
    )
}

fn log2(number: u32) -> u8 {
    match number {
        1_048_576 => 20,
        524_288 => 19,
        262_144 => 18,
        131_072 => 17,
        65_536 => 16,
        32_768 => 15,
        16_384 => 14,
        8_192 => 13,
        4096 => 12,
        2048 => 11,
        1024 => 10,
        512 => 9,
        256 => 8,
        128 => 7,
        64 => 6,
        32 => 5,
        16 => 4,
        8 => 3,
        4 => 2,
        2 => 1,
        _ => 0
    }

    // The dynamic way of doing this:
//    let handle = thread::spawn(move || {
//        let nr = number as f32;
//        nr.log2() as u8
//    });
//    handle.join().unwrap()
}

#[test]
fn test_log() {
    let vectors: Vec<(u8, u32)> = vec![
        ( 4, 16 ),
        ( 10, 1_024 ),
        ( 14, 16_384 ),
        ( 16, 65_536 ),
        ( 18, 262_144 ),
        ( 20, 1_048_576 )
    ];
    for tuple in vectors {
        assert_eq!(tuple.0, log2(tuple.1));
    }
}

#[test]
fn test_scrypt_vectors() {
    let vectors = vec![
        // Expected hash string, passPhrase, salt, iterationCount (N), mem_difficulty (R), parallel_difficulty (P), keyLength
        ( "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906", "", "", 16, 1, 1, 64 ),
        ( "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", "password", "NaCl", 1_024, 8, 16, 64 ),
        ( "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887", "pleaseletmein", "SodiumChloride", 16_384, 8, 1, 64 ),
        ( "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4", "pleaseletmein", "SodiumChloride", 1_048_576, 8, 1, 64 ), // TOO SLOW
    ];
    for tuple in vectors {
        println!("Testing phrase [{}] with salt [{}] and {} iterations.", tuple.1, tuple.2, tuple.3);
        let result = hex::encode(perform_scrypt(tuple.1, tuple.2, tuple.3, tuple.4, tuple.5, tuple.6));
        assert_eq!(tuple.0, result);
    }
}
