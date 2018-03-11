
extern crate bitcoin;
extern crate hex;
extern crate secp256k1;

use bitcoin::bitcoin::util::base58::{FromBase58, ToBase58};
use bitcoin::bitcoin::util::address::Privkey;
use bitcoin::bitcoin::network::constants::Network::Bitcoin;
use self::secp256k1::Secp256k1;
use self::secp256k1::key::SecretKey;
use sha256::hash256;
use std::thread;

pub fn private_key_wif_to_public_address(hex: &str) -> String {
    let sk: Privkey = FromBase58::from_base58check(hex).unwrap();
    let secp = Secp256k1::new();
    let pk = sk.to_address(&secp).unwrap();
    pk.to_base58check()
}

pub fn secret_exponent_to_private_key(exponent: Vec<u8>, compressed: bool) -> String {
    let handle = thread::spawn(move || {
        let secp: Secp256k1 = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&secp, &exponent).unwrap();
        let private_key = bitcoin::util::address::Privkey::from_key(Bitcoin, secret_key, compressed);
        private_key.to_base58check()
    });
    handle.join().unwrap()
}

#[test]
fn test_private_key_wif_to_address()
{
    let addresses = vec![
        ( "1HCtjDx7ba5CnPqVxBuYpbVj2pHkCnGvyb", "KzxtHsgVhTg6oukxv4fWJMKnjVdvTiUnvevTUxeZ879USrmiCKaC" ),
        ( "1QD6VP1zfRzUFLuAHGo52yuSeNr7Xx5YkF", "KzND5NVaS8vuH7xg3fcGuQLNxKG8MGuX3qBWxUoJT4muCE8TiL1D" ),
        ( "19xc6emYtpgnfhzyUgvNWvHfHJHMc8obbc", "L27r12xhH7AcQfP5umYoKjG4ZEoDn6VUjvY6ZTnjTAZx2PWjjVHa" ),
        ( "1DuD7QWuzfUdz93mpRvHBgQWuvXkj2kMd5", "L17p11Cjc4jg2MMbzP7KQMTLu4E5R3YCoMsMBW1Hj5CGYUrFeHtt" ),
        ( "12XcQyjPC32jn78eYKcvBaip1PjkCSNoch", "KwqTLikdY7rfGvabiuGuVxxhdV6ubbji2thhnzUBpBhu2xiH5HQ5" ),
        ( "1K3HhF9gpVixzZ4mcGYWTwsfVRvDfVs4F", "L5NwDDg1eU16VGWeszS8MNnJUAV7Ds9LK6Gag9giBrjuaWmJSsJL" ),
        ( "1ivLFdtx9uVPEr5w9ijmq5bL8Pdr83sE3", "L3Q7sknqvCPR6uH3UkNUseTWaqooDKqqaHsEhRgDbzdJU2WxK8VF" ),
        ( "1ARn6jwZypPAa7j966MF4XufEhBu5vtsz3", "L51Y8SM6rS5Kfn6zqCGpQPZhZ9efT1V1Dm7yPKL3xpdMd6dWc2GP" ),
        ( "1Hp3JytZmu8pPxJXUQ19ccUra5uDumUhSS", "5Kcx6o98wnyQyqEW8cm8SuGTpr2FXsNP3kfnS9ANd7wcQfjutCt" ),
        ( "1BJL9E7H53RUSBoswjE2AnLWQ6mqBe7gnw", "KxqXKMMu4vEW8tXp641UPmTYQTLbKF3hC2SdnFFZ9LNRLz35tXL6" ),
        ( "17njrvdw1daLBe5TW3EaD9pe39eGVRT8XM", "Ky8nhav7HSmH7zGyoggdXaWM6FnrZbt6GbQSyiKo8TCvgUSSxzsg" ),
        ( "1GkFmetdUon1coMTWwjxhnCePH6DyLWwRJ", "L3TT868nRwVtfE8pYrCacBeHiBXFYJgiRJPpGrNhKhwu7AaTJU5C" ),
        ( "1KQSqxFmjBJLtAMPw9KMcp9oi1BAKCnSbM", "L5nyJ8nNfrge6ASL8EyQAUmLnCstNiYDX2HcaGYG1ssUjnbLFPmJ" ),
        ( "1LNfsgL4bNuKMJwS2Wwz1e4W895moN45yJ", "KxHYKuNsm9Jvh4WZEGbGfeWfxLCycBZPzTHWjGRpEx6bZwLE9J9X" ),
        ( "1Hnd9UZEV3mThYAKm2XZ38kCnpPwkuVaF5", "Kwy4TvEtT6NZGCL3ba8jCK8AXCqWf8JipLMgVLgnZ1zeK3CNm6Ej" ),
        ( "1CNuw8qSzb1BNNowanK73b3EKPFEtYTJxt", "Ky5oB5KePmsq3vG8i8y2KhwDquG5DurNnRLCNhsXjrAPpQVNRxsQ" ),
        ( "1MGThKeXHcWrmcK1CWLo6yUhfzFupdacNB", "Kxnmk7wdbRfaDug7F12H7hAw4jEAY1En7VD1Vn3tbXUx78qYVd9g" ),
        ( "17ZXEvvaWSd4FF1dBNw5RYv8v8SQ5EdsKh", "L3DWYsEzNgZZB8AKcPDsy9Dz6nedsXko5nwo8zz8Frde1axteveZ" ),
        ( "1KuMENhhzaE6GZF19FZjmjMax6BLQBw536", "Kz6jjr8esU4HkbEyFzfpZv9YNXbtHmm1r7xD6rrbS2TNv5R52STi" )
    ];
    for tuple in &addresses {
        println!("Testing exponent: [{}]", tuple.1);
        assert_eq!(tuple.0, private_key_wif_to_public_address(tuple.1));
    }
}

#[test]
fn test_exponent_to_private_key() {
    let test_vectors = vec![
        // Expected private key wif, secret exponent
        ("5KDtreMojMGybkQngM9MVY7GhAygvx7iZjL7dbcjQjrcMeULjWZ", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
        ("5Kcx6o98wnyQyqEW8cm8SuGTpr2FXsNP3kfnS9ANd7wcQfjutCt", "eda71746c01c3f465ffd02b6da15a6518e6fbc8f06f1ac525be193be5507069d"),
        ("5JSTLv89xeW9QrDZMRs1AtAXuFRbeknpj2PDoFoXvmE17BECBmo", "521fe5c9ece1aa1f8b66228171598263574aefc6fa4ba06a61747ec81ee9f5a3")
    ];

    for tuple in test_vectors {
        println!("testing {}", &tuple.0);
        assert_eq!(tuple.0, secret_exponent_to_private_key(hex::decode(tuple.1).unwrap(), false));
    }
}

#[test]
fn test_private_key_from_hex_string() {
    let test_data = vec![
        (
            "hello world",
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            vec![
                185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250,
                196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233
            ],
            "5KDtreMojMGybkQngM9MVY7GhAygvx7iZjL7dbcjQjrcMeULjWZ",
            "1CS8g7nwaxPPprb4vqcTVdLCuCRirsbsMb"
        ),
        (
            "satoshi nakamoto",
            "aa2d3c4a4ae6559e9f13f093cc6e32459c5249da723de810651b4b54373385e2",
            vec![
                170, 45, 60, 74, 74, 230, 85, 158, 159, 19, 240, 147, 204, 110, 50, 69,
                156, 82, 73, 218, 114, 61, 232, 16, 101, 27, 75, 84, 55, 51, 133, 226
            ]
            ,
            "5K7EWwEuJu9wPi4q7HmWQ7xgv8GxZ2KqkFbjYMGvTCXmY22oCbr",
            "1Q7f2rL2irjpvsKVys5W2cmKJYss82rNCy"
        ),
        (
            "rust",
            "521fe5c9ece1aa1f8b66228171598263574aefc6fa4ba06a61747ec81ee9f5a3",
            vec![
                82, 31, 229, 201, 236, 225, 170, 31, 139, 102, 34, 129, 113, 89, 130, 99,
                87, 74, 239, 198, 250, 75, 160, 106, 97, 116, 126, 200, 30, 233, 245, 163
            ],
            "5JSTLv89xeW9QrDZMRs1AtAXuFRbeknpj2PDoFoXvmE17BECBmo",
            "13dtaB5KH3g8XMbgq8fAeZdkg8QcDFRz2c"
        )
    ];

    for tuple in test_data {
        println!("Hashing [{}] to a secret exponent.", tuple.0);
        assert_eq!(tuple.1, hash256(tuple.0));
        println!("Testing hex to bytes: [{}]", tuple.1);
        assert_eq!(tuple.2, hex::decode(&tuple.1).unwrap());
        println!("Testing bytes to hex [{}]", tuple.1);
        assert_eq!(tuple.1, hex::encode(&tuple.2));
        println!("Testing private key wif [{}]", tuple.3);
        assert_eq!(tuple.3, secret_exponent_to_private_key(tuple.2.to_vec(), false));
        println!("Testing private wif {} to address {}.", tuple.3, tuple.4);
        assert_eq!(tuple.4, private_key_wif_to_public_address(tuple.3));
    }
}