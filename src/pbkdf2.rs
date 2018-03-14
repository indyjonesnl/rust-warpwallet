
extern crate ring;
extern crate sha2;
extern crate hex;

use self::ring::{digest, pbkdf2};
use std::thread;

pub fn perform_pbkdf2(pass_phrase: Vec<u8>, salt: Vec<u8>, iterations: u32, key_length: usize) -> Vec<u8> {
    thread::spawn(move || {
        let mut to_store = vec![0u8; key_length];
        pbkdf2::derive(&digest::SHA256, iterations, &salt, &pass_phrase, &mut to_store);
        to_store
    }).join().unwrap()
}

#[test]
fn test_pbkdf2_vectors() {
    let vectors = vec![
        (
            "89b69d0516f829893c696226650a8687",
            "pass\0word", "sa\0lt", 4_096, 16
        ),
        (
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4_096, 40
        ),
        (
            "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46",
            "password", "salt", 16_777_216, 32
        ),
        (
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            "password", "salt", 4_096, 32
        ),
        (
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            "password", "salt", 2, 32
        ),
        (
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            "password", "salt", 1, 32
        ),
        (
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            "passwd", "salt", 1, 64
        ),
        (
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            "Password", "NaCl", 80_000, 64
        )
    ];

    for tuple in vectors {
        println!("Testing phrase [{}] with salt [{}] and {} iterations.", tuple.1, tuple.2, tuple.3);
        assert_eq!(tuple.0, hex::encode(perform_pbkdf2(tuple.1.as_bytes().to_vec(), tuple.2.as_bytes().to_vec(), tuple.3, tuple.4)));
    }
}
