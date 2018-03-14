
// Collection of HEX and XOR helpers.
// Mostly used for testing, because it's best to keep everything byte-based and then you won't
//      need any of these helper methods.

extern crate hex;
extern crate xor;

use std::thread;

pub fn threaded_xor(s1: Vec<u8>, s2:Vec<u8>) -> Vec<u8> {
    thread::spawn(move || {
        xor::xor(&s1, &s2)
    }).join().unwrap()
}

#[test]
fn test_xor_library() {
    let source = &[95, 80, 96, 71, 120, 25, 44, 92, 120, 71, 96, 79, 54];
    let key = &[23, 53, 12, 43];
    let result = xor::xor(source, key);
    if let Ok(string) = String::from_utf8(result) {
        assert_eq!("Hello, world!", string);
    }
    let threaded_result = threaded_xor(vec![95, 80, 96, 71, 120, 25, 44, 92, 120, 71, 96, 79, 54], vec![23, 53, 12, 43]);
    assert_eq!("Hello, world!", String::from_utf8(threaded_result).unwrap());
}

#[test]
fn test_hex_xor() {
    // Warpwallet test vectors!
    let vectors = vec![
        // Expected S3, given (scrypt result) S1, given (PBKDF2 result) S2
        (
            "6f2552e159f2a1e1e26c2262da459818fd56c81c363fcc70b94c423def42e59f",
            "b58e47817de4d3901694b68bc8566ed5af9bec21e7a3bd56be114e2004ac148b",
            "daab156024167271f4f894e91213f6cd52cd243dd19c7126075d0c1debeef114"
        ),
        (
            "da009602a5781a8795d55c6e68a4b4d52969a75955ea70255869dd17c3398592",
            "145c2af767a1116477fec267e758cf57614e5d7fa175f7d9acde5b4984d44181",
            "ce5cbcf5c2d90be3e22b9e098ffc7b824827fa26f49f87fcf4b7865e47edc413"
        ),
        (
            "2f6af9ad997b831963f4de48278c044e687ff3cecc25739d1564985b929cb3dd",
            "653083a95e681134205d7f4bf9c3f58a48bb8e7ef7715cba4e800bcc802c368a",
            "4a5a7a04c713922d43a9a103de4ff1c420c47db03b542f275be4939712b08557"
        ),
        (
            "5ab0b9ef00b03d19a6fd571a612300492233f252febb0e8aa6ab90e286fa1178",
            "2f4ef304adad15cc851f3b2b4999c418ac4b4bff8958b09a0ccfae603084b814",
            "75fe4aebad1d28d523e26c3128bac4518e78b9ad77e3be10aa643e82b67ea96c"
        ),
        (
            "cc104757e5504c199a1e71dbda23a04751ab3bf44b1031952df20305ddad020a",
            "39fa48c58d6e8b81f98dc04cc8b898444410a1fc887a41d47648ba4eb93fe3ac",
            "f5ea0f92683ec7986393b197129b380315bb9a08c36a70415bbab94b6492e1a6"
        ),
        (
            "00c1eecb8f56387ba4ecef1574abc1d0078cf8366a301ef15e94fb313a853453",
            "235d2b1480eee07bdc04114fd83294facd8f252ac142685595046bb2e680e9dc",
            "239cc5df0fb8d80078e8fe5aac99552aca03dd1cab7276a4cb909083dc05dd8f"
        ),
        (
            "265486f06e0a90da5b0202ec41a1d28e5614daef13a3ed3cc5668135454ac08e",
            "2dc5e1ad04bbd8b586563d7728e8c211537b78a8966ad71641634332c140317d",
            "0b91675d6ab1486fdd543f9b6949109f056fa24785c93a2a8405c207840af1f3"
        ),
        (
            "f52bb6f6d755b9cf972a7962f9f288d9d91d94b35e6ac6fc4f5ce02dbdc4886d",
            "68a1588996ce0da29e1b219c9a1e2d663a97d8c91d52bc38ff4e9bc5bd7b462c",
            "9d8aee7f419bb46d093158fe63eca5bfe38a4c7a43387ac4b0127be800bfce41"
        ),
        (
            "13a7fdb19b0a5501c21020b5d06870f19d1eec7c705ee744aed2f31bd8c45b0f",
            "e95a1ef65063f5ab041375b33f9f4d958cd11a32ca852032cfac38d0b3b1c90d",
            "fafde347cb69a0aac6035506eff73d6411cff64ebadbc776617ecbcb6b759202"
        ),
        (
            "bbf6322cb1006b475f224644a53a9afa0ae497507ff3b5c060e4ad31f4ca21c6",
            "9f5cc8f45b5221352a487c81c7adfba40f8e3a3d860f3eaa8a0c4e0925ad054c",
            "24aafad8ea524a72756a3ac56297615e056aad6df9fc8b6aeae8e338d167248a"
        ),
        (
            "b5b5fe55e8e332ebe469c54d5672b69ace7acb40c5c032a4fb5b75c1bd0b409e",
            "f9f7f8d6d88c355416e53e1f0c82fb0f752551564e5d9c18ab63d6e42dd99eb0",
            "4c420683306f07bff28cfb525af04d95bb5f9a168b9daebc5038a32590d2de2e"
        ),
        (
            "739112892d83ddb8513c6f3879e8f630f241a3e66fcc08e505e12e7fec6627a8",
            "22c525d1fa3820c90b4f405b204c3599d9de67cbf851bf7e0f192fb61bb15f8c",
            "51543758d7bbfd715a732f6359a4c3a92b9fc42d979db79b0af801c9f7d77824"
        )
    ];
    for tuple in vectors {
        println!("testing s1 [{}] and s2 [{}].", tuple.1, tuple.2);
        assert_eq!(tuple.0, hex::encode(xor::xor(&hex::decode(tuple.1).unwrap(), &hex::decode(tuple.2).unwrap())));
    }
}