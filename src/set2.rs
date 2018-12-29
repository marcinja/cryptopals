use base64;
use hex;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

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

#[test]
fn challenge_10() {}
