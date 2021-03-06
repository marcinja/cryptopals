use base64;
use hex;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
use rand::{random, thread_rng, Rng};
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::result;

fn equal_blocks(x: &[u8], y: &[u8]) -> bool {
    for i in 0..16 {
        if x[i] != y[i] {
            return false;
        }
    }

    true
}

pub fn ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    // TODO check resultstack
    decrypt(cipher, key, None, data).unwrap()
}

pub fn ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();

    // When encrypting data with size of AES_BLOCKSIZE, openssl will pad with a block of 0x10
    // bytes, and promptly fail for challenge 10.
    encrypter.pad(false);
    let plaintext = pkcs7_pad(data, AES_BLOCKSIZE);

    let mut ciphertext = vec![0u8; plaintext.len() + AES_BLOCKSIZE];
    let mut count = encrypter
        .update(
            &plaintext,
            &mut ciphertext, // openssl expects an additional block of space here because of padding?
        )
        .unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    ciphertext

    /*
    let cipher = Cipher::aes_128_ecb();
    let padded_data = pkcs7_pad(data, AES_BLOCKSIZE);
    println!("pd: {:?}", padded_data);

    // TODO check resultstack
    encrypt(cipher, key, None, &padded_data[..]).unwrap()
    */
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
    let plaintext = pkcs7_pad(plaintext, AES_BLOCKSIZE);

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

// AES-128-ECB(your-string || unknown-string, random-key)
fn ch12_encryption_oracle(append_string: &[u8], data: &mut Vec<u8>, key: &[u8]) -> Vec<u8> {
    data.extend_from_slice(append_string);
    ecb_encrypt(&data, key)
}

//Same as real except using CBC-mode. Used to test EBC-mode detection.
fn fake_ch12_encryption_oracle(append_string: &[u8], data: &mut Vec<u8>, key: &[u8]) -> Vec<u8> {
    data.extend_from_slice(append_string);

    let mut iv = vec![0u8; AES_BLOCKSIZE];
    rand_bytes(&mut iv).unwrap();

    cbc_encrypt(&data, key, &iv)
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

// Decrypt inputs appended with "data"
pub fn decrypt_ecb_byte_at_a_time(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; data.len()];

    for next_byte in 0..data.len() {
        let offset = (next_byte + 1) % AES_BLOCKSIZE;
        let mut shortened_block = vec![A; AES_BLOCKSIZE - offset];
        let added_len = shortened_block.len();

        let ciphertext = ch12_encryption_oracle(&data, &mut shortened_block, &key);
        let block_wanted =
            &ciphertext[next_byte + added_len + 1 - AES_BLOCKSIZE..next_byte + added_len + 1];

        let mut test_block = vec![A; AES_BLOCKSIZE];
        // Fill in any bytes that we already know.
        if next_byte < AES_BLOCKSIZE {
            &test_block[AES_BLOCKSIZE - next_byte - 1..AES_BLOCKSIZE - 1]
                .copy_from_slice(&result[..next_byte]);
        } else {
            &test_block[..AES_BLOCKSIZE - 1]
                .copy_from_slice(&result[next_byte - AES_BLOCKSIZE + 1..next_byte]);
        }

        for b in 0x00..=0xFF {
            test_block[AES_BLOCKSIZE - 1] = b;
            let attempt = ecb_encrypt(&test_block, &key);

            if equal_blocks(&block_wanted, &attempt[..AES_BLOCKSIZE]) {
                result[next_byte] = b;
                break;
            }
        }
    }

    result
}

const A: u8 = 0x41;

#[test]
fn challenge_12() {
    let file_name: String = String::from("/home/marcinja/rustacean/cryptopals/data/12.txt");
    let mut f = File::open(file_name).expect("file not found");

    let mut input = String::new();
    f.read_to_string(&mut input)
        .expect("something went wrong reading the file");

    let input = input.replace("\n", "");
    let unknown_data = base64::decode(&input).unwrap();

    let key = generate_random_key(AES_BLOCKSIZE);

    // "Discover" blocksize. (guessing that 256 is max possible block size)
    // Add data 1 byte at a time. Size should jump from n * BLOCKSIZE to
    // (n+1) * BLOCKSIZE.
    let start_size = ch12_encryption_oracle(&unknown_data, &mut vec![0u8; 0], &key).len();
    let mut block_size = 0;
    for i in 0..256 {
        let mut data = vec![A; i];
        let len = ch12_encryption_oracle(&unknown_data, &mut data, &key).len();
        if len > start_size {
            block_size = len - start_size;
            break;
        }
    }
    assert_eq!(block_size, AES_BLOCKSIZE);

    // Test ECB-detection.
    let mut test_data = vec![A; 50];
    let ecb_ciphertext = ch12_encryption_oracle(&unknown_data, &mut test_data, &key);
    assert!(detect_ecb(&ecb_ciphertext));

    let mut test_data = vec![A; 50]; // shadow because the oracle pads input_data.
    let cbc_ciphertext = fake_ch12_encryption_oracle(&unknown_data, &mut test_data, &key);
    assert!(!detect_ecb(&cbc_ciphertext));

    // Decrypt one byte at a time.
    let result = decrypt_ecb_byte_at_a_time(&unknown_data, &key);
    let res_string = String::from_utf8(result).unwrap();
    println!("Answer:\n{}", res_string);
}

pub fn create_profile(email_addr: &str) -> String {
    let split: Vec<&str> = email_addr.splitn(2, "@").collect();

    // Remove non-alphanumeric characters that aren't '.'
    let name: String = split[0].replace(|x: char| !x.is_alphanumeric() && x != '.', "");
    let domain: String = split[1].replace(|x: char| !x.is_alphanumeric() && x != '.', "");

    // Creat random uid
    let mut rng = thread_rng();
    let uid = rng.gen_range(0, 99999);

    format!("email={}@{}&uid={}&role=user", name, domain, uid)
}

// Encrypt user profile under key.
fn ch13_enc_oracle(profile: &str, key: &[u8]) -> Vec<u8> {
    ecb_encrypt(profile.as_bytes(), key)
}

// Decrypt profile.
fn ch13_dec_oracle(enc_profile: &[u8], key: &[u8]) -> String {
    let profile_bytes = ecb_decrypt(enc_profile, key);
    String::from_utf8(profile_bytes).unwrap()
}

#[test]
fn challenge14() {}

#[derive(Debug)]
pub enum PaddingError {
    BadPadding,
}

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PaddingError::BadPadding => write!(f, "BAD PADDING!"),
        }
    }
}

impl error::Error for PaddingError {
    fn description(&self) -> &str {
        match *self {
            PaddingError::BadPadding => "Badding is no good.",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            PaddingError::BadPadding => None,
        }
    }
}

type Result<T> = result::Result<T, PaddingError>;

pub fn strip_pkcs7_padding(data: &[u8], blocksize: usize) -> Result<Vec<u8>> {
    if (data.len() % blocksize) != 0 {
        return Err(PaddingError::BadPadding);
    }

    let last_idx = data.len() - 1;
    let last_byte = data[last_idx] as usize;

    if last_byte < 0 || last_byte > blocksize - 1 {
        return Err(PaddingError::BadPadding);
    }

    let pad_idx = last_idx - last_byte + 1;
    for i in pad_idx..last_idx {
        if data[i] != data[last_idx] {
            return Err(PaddingError::BadPadding);
        }
    }

    let mut stripped_data = vec![0u8; data.len() - last_byte];
    &stripped_data[0..data.len() - last_byte].copy_from_slice(&data[0..data.len() - last_byte]);

    Ok(stripped_data)
}

#[test]
fn challenge15() {
    let test_input = String::from("ICE ICE BABY\x04\x04\x04\x04");
    assert_eq!(
        String::from("ICE ICE BABY"),
        String::from_utf8(strip_pkcs7_padding(&test_input.into_bytes(), AES_BLOCKSIZE).unwrap())
            .unwrap()
    );

    assert!(
        strip_pkcs7_padding(
            &String::from("ICE ICE BABY\x01\x01\x02\x33").into_bytes(),
            AES_BLOCKSIZE
        ).is_err()
    );
}

#[test]
fn challenge16() {}
