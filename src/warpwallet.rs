
extern crate hex;
extern crate xor;

use bitcoin::{secret_exponent_to_private_key, private_key_wif_to_public_address};
use pbkdf2::{perform_pbkdf2_bytes, perform_warp_pbkdf2};
use scrypt::{perform_scrypt_bytes, perform_warp_scrypt};
use std::thread;

const WARP_PBKDF2_CONCAT: &str = "\x02";
const WARP_PBKDF2_ITERATIONS: u32 = 65_536; // 2^16
const WARP_KEY_LENGTH: usize = 32;
const WARP_SCRYPT_ITERATIONS: u32 = 262144; // 2^18
const WARP_SCRYPT_CONCAT: &str = "\x01";
const WARP_SCRYPT_MEM_DIFF: u32 = 8;
const WARP_SCRYPT_PAR_DIFF: u32 = 1;

pub fn warpwallet(pass_phrase: &str, salt: &str) -> Vec<u8> {

    let scrypt_phrase = add_byte_to_string(pass_phrase, WARP_SCRYPT_CONCAT);
    let scrypt_salt = add_byte_to_string(salt, WARP_SCRYPT_CONCAT);
    let pbkdf2_phrase = add_byte_to_string(pass_phrase, WARP_PBKDF2_CONCAT);
    let pbkdf2_salt = add_byte_to_string(salt, WARP_PBKDF2_CONCAT);

    let s1_handle = thread::spawn(move || {
        perform_scrypt_bytes(
        scrypt_phrase,
        scrypt_salt,
        WARP_SCRYPT_ITERATIONS,
        WARP_SCRYPT_MEM_DIFF,
        WARP_SCRYPT_PAR_DIFF,
        WARP_KEY_LENGTH
        )
    });

    let s2_handle = thread::spawn(move || {
        perform_pbkdf2_bytes(
        pbkdf2_phrase,
        pbkdf2_salt,
        WARP_PBKDF2_ITERATIONS,
        WARP_KEY_LENGTH
        )
    });

    let s1 = s1_handle.join().unwrap();
    let s2 = s2_handle.join().unwrap();

    let s3_handle = thread::spawn(move || {
        // return S3
        xor::xor(&s1, &s2)
    });

    s3_handle.join().unwrap()
}

fn add_byte_to_string(input_string: &str, byte_string: &str) -> Vec<u8> {
    let mut new_string = input_string.to_string();
    new_string.push_str(byte_string);
    new_string.as_bytes().to_vec()
}

#[test]
fn test_string_byte_concatenation() {
    let input_string = "The quick fox jumped over the lazy brown dog";
    let expected = vec![
        84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 102, 111, 120, 32, 106,
        117, 109, 112, 101, 100, 32, 111, 118, 101, 114, 32, 116, 104, 101,
        32, 108, 97, 122, 121, 32, 98, 114, 111, 119, 110, 32, 100, 111, 103
    ];
    let expectation_with_concat = vec![
        84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 102, 111, 120, 32, 106,
        117, 109, 112, 101, 100, 32, 111, 118, 101, 114, 32, 116, 104, 101,
        32, 108, 97, 122, 121, 32, 98, 114, 111, 119, 110, 32, 100, 111, 103, 2
    ];
    assert_eq!(expected, input_string.as_bytes());
    let mut new_string = input_string.to_string();
    new_string.push_str("\x02");
    assert_eq!(expectation_with_concat, new_string.as_bytes());
    let try_result = add_byte_to_string("The quick fox jumped over the lazy brown dog", "\x02");
    assert_eq!(expectation_with_concat, try_result);
}

#[test]
fn test_warp_wallet_to_private_key_wif() {
    let vectors = vec![
        // private wif key, passPhrase, salt
        ("5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD", "ER8FT+HFjk0", "7DpniYifN6c"),
        ("5KUJA5iZ2zS7AXkU2S8BiBVY3xj6F8GspLfWWqL9V7CajXumBQV", "YqIDBApDYME", "G34HqIgjrIc"),
        ("5JBAonQ4iGKFJxENExZghDtAS6YB8BsCw5mwpHSvZvP3Q2UxmT1", "FPdAxCygMJg", "X+qaSwhUYXw"),
        ("5JWE9LBvFM5xRE9YCnq3FD35fDVgTPNBmksGwW2jj5fi6cSgHsC", "gdoyAj5Y+jA", "E+6ZzCnRqVM"),
        ("5K4z2kZZxxMZ4Tp6F8gqRTdcTezKdZSxVmRWtPthtDCtNbo4qnB", "PuACRv0R", ""),
        ( "5KNA7T1peej9DwF5ZALUeqBq2xN4LHetaKvH9oRr8RHdTgwohd7", "bS7kqw6LDMJbvHwNFJiXlw", "tzsvA87xk+Rrw/5qj580kg" )
    ];
    for tuple in vectors {
        println!("Testing passphrase [{}] with salt [{}].", tuple.1, tuple.2);
        let secret_exponent = warpwallet(tuple.1, tuple.2);
        let private_key_wif = secret_exponent_to_private_key(secret_exponent, false);
        assert_eq!(tuple.0, private_key_wif);
    }
}

#[test]
fn test_warp_wallet_to_secret_exponent() {
    let vectors = vec![
        // Secret exponent hex string, passPhrase, salt
        ( "6f2552e159f2a1e1e26c2262da459818fd56c81c363fcc70b94c423def42e59f", "ER8FT+HFjk0", "7DpniYifN6c" ),
        ( "da009602a5781a8795d55c6e68a4b4d52969a75955ea70255869dd17c3398592", "YqIDBApDYME", "G34HqIgjrIc" ),
        ( "2f6af9ad997b831963f4de48278c044e687ff3cecc25739d1564985b929cb3dd", "FPdAxCygMJg", "X+qaSwhUYXw" ),
        ( "5ab0b9ef00b03d19a6fd571a612300492233f252febb0e8aa6ab90e286fa1178", "gdoyAj5Y+jA", "E+6ZzCnRqVM" )
    ];

    for tuple in vectors {
        println!("Testing passphrase [{}] with salt [{}].", tuple.1, tuple.2);
        assert_eq!(tuple.0, hex::encode(warpwallet(tuple.1, tuple.2)));
    }
}

#[test]
fn test_warp_scrypt_hex_string() {
    let vectors = vec![
        // Expected S1 hex string, passPhrase string, salt string
        ( "b58e47817de4d3901694b68bc8566ed5af9bec21e7a3bd56be114e2004ac148b", "ER8FT+HFjk0", "7DpniYifN6c" ),
        ( "145c2af767a1116477fec267e758cf57614e5d7fa175f7d9acde5b4984d44181", "YqIDBApDYME", "G34HqIgjrIc" ),
        ( "653083a95e681134205d7f4bf9c3f58a48bb8e7ef7715cba4e800bcc802c368a", "FPdAxCygMJg", "X+qaSwhUYXw" ),
        ( "2f4ef304adad15cc851f3b2b4999c418ac4b4bff8958b09a0ccfae603084b814", "gdoyAj5Y+jA", "E+6ZzCnRqVM" ),
        ( "39fa48c58d6e8b81f98dc04cc8b898444410a1fc887a41d47648ba4eb93fe3ac", "bS7kqw6LDMJbvHwNFJiXlw", "tzsvA87xk+Rrw/5qj580kg" ),
        ( "235d2b1480eee07bdc04114fd83294facd8f252ac142685595046bb2e680e9dc", "uyVkW5vKXX3RpvnUcj7U3Q", "zXrlmk3p5Lxr0vjJKdcJWQ" ),
        ( "2dc5e1ad04bbd8b586563d7728e8c211537b78a8966ad71641634332c140317d", "5HoGwwEMOgclQyzH72B9pQ", "UGKv/5nY3ig8bZvMycvIxQ" ),
        ( "68a1588996ce0da29e1b219c9a1e2d663a97d8c91d52bc38ff4e9bc5bd7b462c", "TUMBDBWh8ArOK0+jO5glcA", "dAMOvN2WaEUTC/V5yg0eQA" ),
        ( "e95a1ef65063f5ab041375b33f9f4d958cd11a32ca852032cfac38d0b3b1c90d", "rDrc5eIhSt2qP8pnpnSMu1u2/mP6KTqS", "HGM1/qHoT3XX61NXw8H1nQ" ),
        ( "9f5cc8f45b5221352a487c81c7adfba40f8e3a3d860f3eaa8a0c4e0925ad054c", "Brd8TB3EDhegSx2wy2ffW0oGNC29vkCo", "dUBIrYPiUZ6BD/l+zBhthA" ),
        ( "f9f7f8d6d88c355416e53e1f0c82fb0f752551564e5d9c18ab63d6e42dd99eb0", "eYuYtFxU4KrePYrbHSi/8ncAKEb+KbNH", "le5MMmWaj4AlGcRevRPEdw" ),
        ( "22c525d1fa3820c90b4f405b204c3599d9de67cbf851bf7e0f192fb61bb15f8c", "TRGmdIHpnsSXjEnLc+U+MrRV3ryo8trG", "DhZNEt9hx08i6uMXo5DOyg" )
    ];
    for tuple in vectors {
        println!("testing phrase: [{}] with salt: [{}]", &tuple.1, &tuple.2);
        assert_eq!(tuple.0, hex::encode(perform_warp_scrypt(tuple.1, tuple.2)));
    }
}

#[test]
fn test_complete_warp_wallet() {
    let vectors = get_warp_wallet_vectors();
    for vector in vectors.iter() {
        let generated_s1 = perform_warp_scrypt(&vector.passphrase, &vector.salt);
        assert_eq!(vector.seeds[0], hex::encode(&generated_s1));

        let generated_s2 = perform_warp_pbkdf2(&vector.passphrase, &vector.salt);
        assert_eq!(vector.seeds[1], hex::encode(&generated_s2));

        let generated_xor_secret_exponent = xor::xor(&generated_s1, &generated_s2);
        assert_eq!(vector.seeds[2], hex::encode(&generated_xor_secret_exponent));

        let generated_warp_secret_exponent = warpwallet(&vector.passphrase, &vector.salt);
        assert_eq!(vector.seeds[2], hex::encode(&generated_warp_secret_exponent));

        assert_eq!(&generated_xor_secret_exponent, &generated_warp_secret_exponent);
        let generated_private_key = secret_exponent_to_private_key(generated_warp_secret_exponent, false);
        assert_eq!(vector.keys[0], generated_private_key);

        let generated_address = private_key_wif_to_public_address(&generated_private_key);
        assert_eq!(vector.keys[1], generated_address);
        println!("Completed assertions of phrase [{}] and salt [{}] becoming", vector.passphrase, vector.salt);
        println!("address [{}] with privkey [{}].", vector.keys[1], vector.keys[0]);
    }
}

pub struct WarpWalletVector {
    passphrase: &'static str,
    salt: &'static str,
    seeds: [ &'static str; 3 ],
    keys: [ &'static str; 2 ]
}

pub fn get_warp_wallet_vectors() -> [ WarpWalletVector; 12 ] {
//    N - A factor to control the overall CPU/Memory cost
//    r - A factor to control the blocksize for each mixing loop (memory usage)
//    p - A factor to control the number of independent mixing loops (parallelism)

//    s1 	=	scrypt(key=(passphrase||0x1), salt=(salt||0x1), N=262144 (2^18), r=8, p=1, dkLen=32)
//    s2 	=	pbkdf2(key=(passphrase||0x2), salt=(salt||0x2), c=65536 (2^16), dkLen=32, prf=HMAC_SHA256)
//    keypair	=	generate_bitcoin_keypair(s1 ⊕ s2)

    [
        WarpWalletVector {
            passphrase: "ER8FT+HFjk0",
            salt: "7DpniYifN6c",
            seeds: [
                "b58e47817de4d3901694b68bc8566ed5af9bec21e7a3bd56be114e2004ac148b",
                "daab156024167271f4f894e91213f6cd52cd243dd19c7126075d0c1debeef114",
                "6f2552e159f2a1e1e26c2262da459818fd56c81c363fcc70b94c423def42e59f" ],
            keys: [
                "5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD",
                "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ"
            ]
        },
        WarpWalletVector {
            passphrase: "YqIDBApDYME",
            salt: "G34HqIgjrIc",
            seeds: [
                "145c2af767a1116477fec267e758cf57614e5d7fa175f7d9acde5b4984d44181",
                "ce5cbcf5c2d90be3e22b9e098ffc7b824827fa26f49f87fcf4b7865e47edc413",
                "da009602a5781a8795d55c6e68a4b4d52969a75955ea70255869dd17c3398592"
            ],
            keys: [
                "5KUJA5iZ2zS7AXkU2S8BiBVY3xj6F8GspLfWWqL9V7CajXumBQV",
                "19aKBeXe2mi4NbQRpYUrCLZtRDHDUs9J7J"
            ]
        },
        WarpWalletVector {
            passphrase: "FPdAxCygMJg",
            salt: "X+qaSwhUYXw",
            seeds: [
                "653083a95e681134205d7f4bf9c3f58a48bb8e7ef7715cba4e800bcc802c368a",
                "4a5a7a04c713922d43a9a103de4ff1c420c47db03b542f275be4939712b08557",
                "2f6af9ad997b831963f4de48278c044e687ff3cecc25739d1564985b929cb3dd"
            ],
            keys: [
                "5JBAonQ4iGKFJxENExZghDtAS6YB8BsCw5mwpHSvZvP3Q2UxmT1",
                "14Pqeo9XNRxjtKFFYd6TvRrJuZxVpciS81"
            ]
        },
        WarpWalletVector {
            passphrase: "gdoyAj5Y+jA",
            salt: "E+6ZzCnRqVM",
            seeds: [
                "2f4ef304adad15cc851f3b2b4999c418ac4b4bff8958b09a0ccfae603084b814",
                "75fe4aebad1d28d523e26c3128bac4518e78b9ad77e3be10aa643e82b67ea96c",
                "5ab0b9ef00b03d19a6fd571a612300492233f252febb0e8aa6ab90e286fa1178"
            ],
            keys: [
                "5JWE9LBvFM5xRE9YCnq3FD35fDVgTPNBmksGwW2jj5fi6cSgHsC",
                "1KiiYhv9xkTZfcLYwqPhYHrSbvwJFFUgKv"
            ]
        },
        WarpWalletVector {
            passphrase: "bS7kqw6LDMJbvHwNFJiXlw",
            salt: "tzsvA87xk+Rrw/5qj580kg",
            seeds: [
                "39fa48c58d6e8b81f98dc04cc8b898444410a1fc887a41d47648ba4eb93fe3ac",
                "f5ea0f92683ec7986393b197129b380315bb9a08c36a70415bbab94b6492e1a6",
                "cc104757e5504c199a1e71dbda23a04751ab3bf44b1031952df20305ddad020a"
            ],
            keys: [
                "5KNA7T1peej9DwF5ZALUeqBq2xN4LHetaKvH9oRr8RHdTgwohd7",
                "17ZcmAbJ35QJzAbwqAj4evo4vL5PwA8e7C"
            ]
        },
        WarpWalletVector {
            passphrase: "uyVkW5vKXX3RpvnUcj7U3Q",
            salt: "zXrlmk3p5Lxr0vjJKdcJWQ",
            seeds: [
                "235d2b1480eee07bdc04114fd83294facd8f252ac142685595046bb2e680e9dc",
                "239cc5df0fb8d80078e8fe5aac99552aca03dd1cab7276a4cb909083dc05dd8f",
                "00c1eecb8f56387ba4ecef1574abc1d0078cf8366a301ef15e94fb313a853453"
            ],
            keys: [
                "5Hpcw1rqoojG7LTHo4MrEHBwmBQBXQQmH6dEa89ayw5qMXvZmEZ",
                "1ACJ7MhCRRTPaEvr2utat6FQjsQgC6qpE6"
            ]
        },
        WarpWalletVector {
            passphrase: "5HoGwwEMOgclQyzH72B9pQ",
            salt: "UGKv/5nY3ig8bZvMycvIxQ",
            seeds: [
                "2dc5e1ad04bbd8b586563d7728e8c211537b78a8966ad71641634332c140317d",
                "0b91675d6ab1486fdd543f9b6949109f056fa24785c93a2a8405c207840af1f3",
                "265486f06e0a90da5b0202ec41a1d28e5614daef13a3ed3cc5668135454ac08e"
            ],
            keys: [
                "5J7Ag5fBArgKN9ocVJs4rcQw1chZjHrqAb4YRuny6YiieJc5iG3",
                "1Mtb2o7AsTRAR3vjtSYjq1rgB8Q6A76avD"
            ]
        },
        WarpWalletVector {
            passphrase: "TUMBDBWh8ArOK0+jO5glcA",
            salt: "dAMOvN2WaEUTC/V5yg0eQA",
            seeds: [
                "68a1588996ce0da29e1b219c9a1e2d663a97d8c91d52bc38ff4e9bc5bd7b462c",
                "9d8aee7f419bb46d093158fe63eca5bfe38a4c7a43387ac4b0127be800bfce41",
                "f52bb6f6d755b9cf972a7962f9f288d9d91d94b35e6ac6fc4f5ce02dbdc4886d"
            ],
            keys: [
                "5KgG93ePJJ8HC2tnTerThNUnXbjyeBpUCBDRn5ZxMRB9GxiwJEK",
                "1B2VuTAHERd2GmBK522LFLUTwYWcW1vXH6"
            ]
        },
        WarpWalletVector {
            passphrase: "rDrc5eIhSt2qP8pnpnSMu1u2/mP6KTqS",
            salt: "HGM1/qHoT3XX61NXw8H1nQ",
            seeds: [
                "e95a1ef65063f5ab041375b33f9f4d958cd11a32ca852032cfac38d0b3b1c90d",
                "fafde347cb69a0aac6035506eff73d6411cff64ebadbc776617ecbcb6b759202",
                "13a7fdb19b0a5501c21020b5d06870f19d1eec7c705ee744aed2f31bd8c45b0f"
            ],
            keys: [
                "5HxwfzgQ2yem9uY5UxdiaKYPgUR251FCVHw1VuHC5bSW5NVLaok",
                "12XD7BtiU1gydRzQm3cAoui2RQjhVJfNPg"
            ]
        },
        WarpWalletVector {
            passphrase: "Brd8TB3EDhegSx2wy2ffW0oGNC29vkCo",
            salt: "dUBIrYPiUZ6BD/l+zBhthA",
            seeds: [
                "9f5cc8f45b5221352a487c81c7adfba40f8e3a3d860f3eaa8a0c4e0925ad054c",
                "24aafad8ea524a72756a3ac56297615e056aad6df9fc8b6aeae8e338d167248a",
                "bbf6322cb1006b475f224644a53a9afa0ae497507ff3b5c060e4ad31f4ca21c6"
            ],
            keys: [
                "5KF4ozGWXGZAqNydQg65JQ4XnJaUpBkU9g59C287GrbLfWVmYHL",
                "1CD93Tgj74uKh87dENR2GMWB1kpCidLZiS"
            ]
        },
        WarpWalletVector {
            passphrase: "eYuYtFxU4KrePYrbHSi/8ncAKEb+KbNH",
            salt: "le5MMmWaj4AlGcRevRPEdw",
            seeds: [
                "f9f7f8d6d88c355416e53e1f0c82fb0f752551564e5d9c18ab63d6e42dd99eb0",
                "4c420683306f07bff28cfb525af04d95bb5f9a168b9daebc5038a32590d2de2e",
                "b5b5fe55e8e332ebe469c54d5672b69ace7acb40c5c032a4fb5b75c1bd0b409e"
            ],
            keys: [
                "5KCK9EtgvjsQcPcZcfMoqcHwZKzA1MLfPUvDCYE1agiNf56CfAk",
                "18mugeQN8uecTBE9psW2uQrhRBXZJkhyB7"
            ]
        },
        WarpWalletVector {
            passphrase: "TRGmdIHpnsSXjEnLc+U+MrRV3ryo8trG",
            salt: "DhZNEt9hx08i6uMXo5DOyg",
            seeds: [
                "22c525d1fa3820c90b4f405b204c3599d9de67cbf851bf7e0f192fb61bb15f8c",
                "51543758d7bbfd715a732f6359a4c3a92b9fc42d979db79b0af801c9f7d77824",
                "739112892d83ddb8513c6f3879e8f630f241a3e66fcc08e505e12e7fec6627a8"
            ],
            keys: [
                "5JhBaSsxgNBjvZWVfdVQsnMzYf4msHMQ7HRaHLvvMy1CEgsTstg",
                "19QCgqHnKw8vrJph7wWP3nKg9tFixqYwiB"
            ]
        }
    ]
}
