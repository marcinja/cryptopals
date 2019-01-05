use base64;
use hex;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
use rand::{random, thread_rng, Rng};
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

pub fn ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    // TODO check resultstack
    decrypt(cipher, key, None, data).unwrap()
}

pub fn ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    // TODO check resultstack
    encrypt(cipher, key, None, data).unwrap()
}

pub const AES_BLOCKSIZE: usize = 16;

pub fn pkcs7_pad(data: &[u8], blocksize: usize) -> Vec<u8> {
    let padding_length = blocksize - (data.len() % blocksize);

    let mut padded_data = vec![padding_length as u8; padding_length + data.len()];

    &padded_data[0..data.len()].copy_from_slice(&data);
    padded_data
}

pub fn cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();

    // When decrypting data with size of AES_BLOCKSIZE, openssl will pad with a block of 0x10
    // bytes, and promptly fail for challenge 10.
    decrypter.pad(false);

    let mut plaintext = vec![0u8; ciphertext.len() + AES_BLOCKSIZE];
    let mut count = decrypter
        .update(
            &ciphertext[0..AES_BLOCKSIZE],
            &mut plaintext[0..AES_BLOCKSIZE * 2], // openssl expects an additional block of space here because of padding?
        )
        .unwrap();

    for i in 0..AES_BLOCKSIZE {
        plaintext[i] ^= iv[i];
    }

    for i in 1..(ciphertext.len() / AES_BLOCKSIZE) {
        count += decrypter
            .update(
                &ciphertext[i * AES_BLOCKSIZE..(i + 1) * AES_BLOCKSIZE],
                &mut plaintext[i * AES_BLOCKSIZE..(i + 2) * AES_BLOCKSIZE],
            )
            .unwrap();

        for i in i * AES_BLOCKSIZE..(i + 1) * AES_BLOCKSIZE {
            plaintext[i] ^= ciphertext[i - AES_BLOCKSIZE];
        }
    }
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    plaintext
}

pub fn cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();

    // When encrypting data with size of AES_BLOCKSIZE, openssl will pad with a block of 0x10
    // bytes, and promptly fail for challenge 10.
    encrypter.pad(false);

    let mut buffer = vec![0u8; AES_BLOCKSIZE];
    &buffer.copy_from_slice(&plaintext[0..AES_BLOCKSIZE]);

    for i in 0..AES_BLOCKSIZE {
        buffer[i] ^= iv[i];
    }

    let mut ciphertext = vec![0u8; plaintext.len() + AES_BLOCKSIZE];
    let mut count = encrypter
        .update(
            &buffer[0..AES_BLOCKSIZE],
            &mut ciphertext[0..AES_BLOCKSIZE * 2], // openssl expects an additional block of space here because of padding?
        )
        .unwrap();

    &buffer.copy_from_slice(&ciphertext[0..AES_BLOCKSIZE]);

    for i in 1..(plaintext.len() / AES_BLOCKSIZE) {
        for j in 0..AES_BLOCKSIZE {
            buffer[j] ^= &plaintext[i * AES_BLOCKSIZE + j];
        }

        count += encrypter
            .update(
                &buffer,
                &mut ciphertext[i * AES_BLOCKSIZE..(i + 2) * AES_BLOCKSIZE],
            )
            .unwrap();

        &buffer.copy_from_slice(&ciphertext[i * AES_BLOCKSIZE..(i + 1) * AES_BLOCKSIZE]);
    }
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    ciphertext
}

pub fn generate_random_key(size: usize) -> Vec<u8> {
    // Generate using openssl PRG.
    let mut key = vec![0u8; size];
    rand_bytes(&mut key).unwrap();
    key
}

pub fn encryption_oracle(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let prefix_len = rng.gen_range(5, 11);
    let suffix_len = rng.gen_range(5, 11);

    let mut buf = vec![0u8; prefix_len + data.len() + suffix_len];
    &buf[prefix_len..(prefix_len + data.len())].copy_from_slice(&data[..]);

    // Generate random bytes for prefix and suffix.
    rand_bytes(&mut buf[..prefix_len]).unwrap();
    rand_bytes(&mut buf[prefix_len + data.len()..]).unwrap();

    // CBC half the time, ECB half the time.
    if random() {
        return ecb_encrypt(&buf, key);
    } else {
        let mut iv = vec![0u8; AES_BLOCKSIZE];
        rand_bytes(&mut iv).unwrap();
        return cbc_encrypt(&buf, key, &iv);
    }
}

pub fn detect_ecb(data: &[u8]) -> bool {
    // Check how many 16 bytes blocks are exactly the same to detect ECB-mode.
    let mut collisions = 0;
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

    if collisions > 0 {
        return true;
    }
    false
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
