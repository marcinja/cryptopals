use base64;
use hex;
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

#[test] // Challenge 7
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

#[test]
fn challenge_8() {
    let file_name: String =
        String::from("/home/marcinja/rustacean/cryptopals/data/challenge-8.txt");
    let mut f = File::open(file_name).expect("file not found");

    let mut input = String::new();
    f.read_to_string(&mut input)
        .expect("something went wrong reading the file");

    let mut likely_line: &str = "";
    let mut max_collisions: u32 = 0;
    for l in input.lines() {
        let data: Vec<u8> = hex::decode(l).unwrap();
        let mut collisions = 0;

        // Check how many 16 bytes blocks are exactly the same to detect ECB-mode.
        let num_blocks = data.len() / 16;
        for i in 0..num_blocks {
            for j in (i + 1)..num_blocks {
                let block1 = &data[i * 16..(i + 1) * 16];
                let block2 = &data[j * 16..(j + 1) * 16];

                if equal_blocks(block1, block2) {
                    collisions += 1;
                }
            }
        }

        if collisions >= max_collisions {
            likely_line = l;
            max_collisions = collisions;
        }
    }

    println!(
        "Num collisions : {}\n, Line: \n {}",
        max_collisions, likely_line
    );
}

fn equal_blocks(x: &[u8], y: &[u8]) -> bool {
    for i in 0..16 {
        if x[i] != y[i] {
            return false;
        }
    }

    true
}
