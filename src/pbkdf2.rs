
extern crate ring;
extern crate sha2;
extern crate hex;

use self::ring::{digest, pbkdf2};
use std::thread;

const WARP_PBKDF2_CONCAT: &str = "\x02";
const WARP_PBKDF2_ITERATIONS: u32 = 65_536; // 2^16
const WARP_KEY_LENGTH: usize = 32;

pub fn perform_pbkdf2_bytes(pass_phrase: Vec<u8>, salt: Vec<u8>, iterations: u32, key_length: usize) -> Vec<u8> {
    let handle = thread::spawn(move || {
        let mut to_store = vec![0u8; key_length];
        pbkdf2::derive(&digest::SHA256, iterations, &salt, &pass_phrase, &mut to_store);
        to_store
    });
    handle.join().unwrap()
}

pub fn perform_pbkdf2(pass_phrase: &str, salt: &str, iterations: u32, key_length: usize) -> Vec<u8> {
    let mut to_store = vec![ 0u8; key_length ];
    pbkdf2::derive(&digest::SHA256, iterations, salt.as_bytes(), pass_phrase.as_bytes(), &mut to_store);
    to_store
}

pub fn perform_warp_pbkdf2(pass_phrase: &str, salt: &str) -> Vec<u8> {
    // There has to be a more efficient way to append 1 stupid byte to a byte array...
    let mut passphrase_extended = pass_phrase.to_string();
    passphrase_extended.push_str(WARP_PBKDF2_CONCAT);
    let mut salt_extended = salt.to_string();
    salt_extended.push_str(WARP_PBKDF2_CONCAT);
    perform_pbkdf2(&passphrase_extended, &salt_extended, WARP_PBKDF2_ITERATIONS, WARP_KEY_LENGTH)
}

#[test]
fn test_plain_pbkdf2() {
    let vectors = vec![
        ( "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783", "passwd", "salt", 1, 64 ),
        ( "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d", "Password", "NaCl", 80_000, 64 )
    ];
    for tuple in vectors {
        println!("Testing input {} with salt {} now.", tuple.1, tuple.2);
        assert_eq!(tuple.0, hex::encode(perform_pbkdf2(tuple.1, tuple.2, tuple.3, tuple.4)));
    }
}

#[test]
fn test_pbkdf2_vectors() {
    let vectors = vec![
        (
            vec![
                0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89,
                0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87
            ],
            "89b69d0516f829893c696226650a8687",
            "pass\0word", "sa\0lt", 4_096, 16
        ),
        (
            vec![
                0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
                0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
                0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
                0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
                0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9
            ],
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4_096, 40
        ),
        (
            vec![
                0xcf, 0x81, 0xc6, 0x6f, 0xe8, 0xcf, 0xc0, 0x4d,
                0x1f, 0x31, 0xec, 0xb6, 0x5d, 0xab, 0x40, 0x89,
                0xf7, 0xf1, 0x79, 0xe8, 0x9b, 0x3b, 0x0b, 0xcb,
                0x17, 0xad, 0x10, 0xe3, 0xac, 0x6e, 0xba, 0x46
            ],
            "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46",
            "password", "salt", 16_777_216, 32
        ),
        (
            vec![
                0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
                0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
                0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
                0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a
            ],
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            "password", "salt", 4_096, 32
        ),
        (
            vec![
                0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
                0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
                0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
                0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43
            ],
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            "password", "salt", 2, 32
        ),
        (
            vec![
                0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
                0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
                0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
            ],
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            "password", "salt", 1, 32
        )
    ];

    for tuple in vectors {
        println!("Testing phrase [{}] with salt [{}] and {} iterations.", tuple.2, tuple.3, tuple.4);
        assert_eq!(tuple.1, hex::encode(&tuple.0));
        assert_eq!(tuple.0, perform_pbkdf2(tuple.2, tuple.3, tuple.4, tuple.5));
    }
}

#[test]
fn test_warp_pbkdf2_to_hex_string() {
    let test_data = vec![
        // Expected S2 hex string, passPhrase string, salt string
        ( "daab156024167271f4f894e91213f6cd52cd243dd19c7126075d0c1debeef114", "ER8FT+HFjk0", "7DpniYifN6c" ),
        ( "ce5cbcf5c2d90be3e22b9e098ffc7b824827fa26f49f87fcf4b7865e47edc413", "YqIDBApDYME", "G34HqIgjrIc" ),
        ( "4a5a7a04c713922d43a9a103de4ff1c420c47db03b542f275be4939712b08557", "FPdAxCygMJg", "X+qaSwhUYXw" ),
        ( "75fe4aebad1d28d523e26c3128bac4518e78b9ad77e3be10aa643e82b67ea96c", "gdoyAj5Y+jA", "E+6ZzCnRqVM" ),
        ( "f5ea0f92683ec7986393b197129b380315bb9a08c36a70415bbab94b6492e1a6", "bS7kqw6LDMJbvHwNFJiXlw", "tzsvA87xk+Rrw/5qj580kg" ),
        ( "239cc5df0fb8d80078e8fe5aac99552aca03dd1cab7276a4cb909083dc05dd8f", "uyVkW5vKXX3RpvnUcj7U3Q", "zXrlmk3p5Lxr0vjJKdcJWQ" ),
        ( "0b91675d6ab1486fdd543f9b6949109f056fa24785c93a2a8405c207840af1f3", "5HoGwwEMOgclQyzH72B9pQ", "UGKv/5nY3ig8bZvMycvIxQ" ),
        ( "9d8aee7f419bb46d093158fe63eca5bfe38a4c7a43387ac4b0127be800bfce41", "TUMBDBWh8ArOK0+jO5glcA", "dAMOvN2WaEUTC/V5yg0eQA" ),
        ( "fafde347cb69a0aac6035506eff73d6411cff64ebadbc776617ecbcb6b759202", "rDrc5eIhSt2qP8pnpnSMu1u2/mP6KTqS", "HGM1/qHoT3XX61NXw8H1nQ" ),
        ( "24aafad8ea524a72756a3ac56297615e056aad6df9fc8b6aeae8e338d167248a", "Brd8TB3EDhegSx2wy2ffW0oGNC29vkCo", "dUBIrYPiUZ6BD/l+zBhthA" ),
        ( "4c420683306f07bff28cfb525af04d95bb5f9a168b9daebc5038a32590d2de2e", "eYuYtFxU4KrePYrbHSi/8ncAKEb+KbNH", "le5MMmWaj4AlGcRevRPEdw" ),
        ( "51543758d7bbfd715a732f6359a4c3a92b9fc42d979db79b0af801c9f7d77824", "TRGmdIHpnsSXjEnLc+U+MrRV3ryo8trG", "DhZNEt9hx08i6uMXo5DOyg" )
    ];
    for test_vector in test_data {
        println!("testing phrase: [{}] with salt: [{}]", test_vector.1, test_vector.2);
        assert_eq!(test_vector.0, hex::encode(perform_warp_pbkdf2( test_vector.1, test_vector.2 )));
    }
}