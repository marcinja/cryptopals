use base64;
use hex;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

use aes::*;

#[test]
fn challenge_9() {
    let test_data = "YELLOW SUBMARINE";
    let padded_data = pkcs7_pad(test_data.as_bytes(), 20);

    assert_eq!(
        padded_data,
        String::from("YELLOW SUBMARINE\x04\x04\x04\x04").into_bytes()
    );
}

#[test]
fn challenge_10() {
    let file_name: String = String::from("/home/marcinja/rustacean/cryptopals/data/10.txt");
    let mut f = File::open(file_name).expect("file not found");

    let mut input = String::new();
    f.read_to_string(&mut input)
        .expect("something went wrong reading the file");

    let input = input.replace("\n", "");
    let input_bytes: Vec<u8> = base64::decode(&input).unwrap();

    let key = String::from("YELLOW SUBMARINE").into_bytes();
    let iv = vec!['\x00' as u8; AES_BLOCKSIZE];
    assert_eq!(key.len(), iv.len());

    //let cipher = Cipher::aes_128_ecb();
    //let plaintext = decrypt(cipher, &key, Some(&iv), &input_bytes).unwrap();

    let plaintext = cbc_decrypt(&input_bytes, &key, &iv);
    let ciphertext = cbc_encrypt(&plaintext, &key, &iv);
    let plaintext2 = cbc_decrypt(&ciphertext, &key, &iv);

    //println!("PLAINTEXT {}", String::from_utf8(plaintext2).unwrap());
}
