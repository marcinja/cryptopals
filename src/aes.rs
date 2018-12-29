use base64;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

fn ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    // TODO check resultstack
    decrypt(cipher, key, None, data).unwrap()
}

fn ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    // TODO check resultstack
    encrypt(cipher, key, None, data).unwrap()
}

#[test] // Encryption and decryption should be inverse ops.
fn enc_dec_test() {
    let mut data: Vec<u8> = vec![0u8; 64];
    for i in 0..64 {
        data[i] = i as u8;
    }

    let key: Vec<u8> = String::from("YELLOW SUBMARINE").into_bytes();

    let mut copy: Vec<u8> = vec![0u8; data.len()];
    copy.copy_from_slice(&data[0..data.len()]);

    let enc = ecb_encrypt(&data, &key);
    let copy2 = ecb_decrypt(&enc[..], &key);

    for i in 0..64 {
        assert_eq!(copy[i], copy2[i]);
    }
}

#[test]
fn aes_encrypt() {
    let file_name: String =
        String::from("/home/marcinja/rustacean/cryptopals/data/challenge-7.txt");
    let mut f = File::open(file_name).expect("file not found");

    let mut input = String::new();
    f.read_to_string(&mut input)
        .expect("something went wrong reading the file");
    let input = input.replace("\n", "");

    let data = base64::decode(&input).unwrap();
    let key: Vec<u8> = String::from("YELLOW SUBMARINE").into_bytes();

    let plaintext = ecb_decrypt(&data[..], &key[..]);
    let dec = String::from_utf8(plaintext).unwrap();

    println!("{}", dec);
}
