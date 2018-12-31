use base64;
use hex;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

const AES_BLOCKSIZE: usize = 16;

fn PKCS7_pad(data: &[u8], blocksize: usize) -> Vec<u8> {
    let padding_length = blocksize - (data.len() % blocksize);

    let mut padded_data = vec![padding_length as u8; padding_length + data.len()];

    &padded_data[0..data.len()].copy_from_slice(&data);
    padded_data
}

#[test]
fn challenge_9() {
    let test_data = "YELLOW SUBMARINE";
    let padded_data = PKCS7_pad(test_data.as_bytes(), 20);

    assert_eq!(
        padded_data,
        String::from("YELLOW SUBMARINE\x04\x04\x04\x04").into_bytes()
    );
}

fn cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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

fn cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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
