
extern crate crypto;

use sha256::crypto::digest::Digest;

pub fn hash256(input: &str) -> String {
    let mut sha = crypto::sha2::Sha256::new();
    sha.input_str(input);
    sha.result_str()
}

#[test]
fn test_sha_256_hashing() {
    let test_vectors = vec![
        ("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "hello world"),
        ("c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a", "Hello world!"),
        ("eda71746c01c3f465ffd02b6da15a6518e6fbc8f06f1ac525be193be5507069d", "javascript"),
        ("521fe5c9ece1aa1f8b66228171598263574aefc6fa4ba06a61747ec81ee9f5a3", "rust"),
        ("86addef47ef3d897d2eb81e0dcc2f91634bf88b0746abfddbb34fb868fcd6f78", "test vector")
    ];

    for tuple in &test_vectors {
        println!("testing {}", tuple.1);
        assert_eq!(tuple.0, self::hash256(tuple.1));
    };
}