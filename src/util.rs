use base64;
use hex;
use std::fs::File;
use std::io::prelude::*;

fn hex_to_base64(s: String) -> String {
    let hex_vec = hex::decode(s);
    let hex_vec = match hex_vec {
        Ok(v) => v,
        Err(error) => panic!("Problem with hex decode {}", error),
    };

    base64::encode(&hex_vec)
}

fn xor(x: &Vec<u8>, y: &Vec<u8>) -> Vec<u8> {
    if x.len() != y.len() {
        panic!("Input vector lengths should be the same!")
    }

    x.iter()
        .zip(y.iter())
        .map(|(x_elem, y_elem)| x_elem ^ y_elem)
        .collect()
}

fn xor_by_byte(x: &Vec<u8>, b: u8) -> Vec<u8> {
    x.iter().map(|c| c ^ b).collect()
}

// Both cosine similarity and distance can be used to solve challenge 3.
// (using dist, switch to minimizing distance as opposed to max of similarity)
trait SimilarityMetrics<RHS = Self> {
    fn dot(&self, other: &RHS) -> f64;
    fn cosine_similarity(&self, other: &RHS) -> f64;
    fn dist(&self, other: &RHS) -> f64;
}

impl SimilarityMetrics for Vec<f64> {
    fn dot(&self, other: &Vec<f64>) -> f64 {
        self.iter().zip(other.iter()).map(|(x, y)| x * y).sum()
    }

    fn cosine_similarity(&self, other: &Vec<f64>) -> f64 {
        if self.len() != other.len() {
            panic!("Input vector lengths should be the same!")
        }

        self.dot(other) / (self.dot(self).sqrt() * other.dot(other).sqrt())
    }

    fn dist(&self, other: &Vec<f64>) -> f64 {
        self.iter()
            .zip(other.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum()
    }
}

fn is_printable_ascii(c: &u8) -> bool {
    match *c {
        32...123 => true,
        _ => false,
    }
}

fn get_char_freq_from_file() -> Vec<f64> {
    let file_name: String = String::from("/home/marcinja/rustacean/cryptopals/moby-dick.txt");
    let mut f = File::open(file_name).expect("file not found");
    let mut input = String::new();

    f.read_to_string(&mut input)
        .expect("something went wrong reading the file");

    get_char_freq(&input.into_bytes())
}

// lowercase ascii is in [97, 122]
fn get_char_freq(input: &Vec<u8>) -> Vec<f64> {
    let mut counts: Vec<f64> = vec![0.0; 92];

    input
        .iter()
        .filter(|c| is_printable_ascii(*c))
        .for_each(|c| counts[(*c as u8 - 32) as usize] += 1.0);

    let sum: f64 = counts.iter().sum();
    counts.iter().map(|c| c / sum).collect()
}

fn likely_single_byte_xor(s: String, english_freq: Vec<f64>) -> (char, Vec<u8>) {
    let s_bytes: Vec<u8> = hex::decode(s).unwrap();

    let mut best_msg: Vec<u8> = vec![0; s_bytes.len()];
    let mut best_byte: u8 = 0;
    let mut best_score: f64 = 0.0;

    for b in 0..255 {
        let possible_msg = xor_by_byte(&s_bytes, b);
        let char_freq = get_char_freq(&possible_msg);

        let score = english_freq.cosine_similarity(&char_freq);
        if score > best_score {
            best_byte = b;
            best_score = score;
            best_msg = possible_msg;
        }
    }

    (best_byte as char, best_msg)
}

#[test]
fn set1_challenge1() {
    assert_eq!{
        hex_to_base64(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")),
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    }
}

#[test]
fn set1_challenge2() {
    let s1 = hex::decode(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
    let s2 = hex::decode(String::from("686974207468652062756c6c277320657965")).unwrap();

    let xor_result = xor(&s1, &s2);

    assert_eq!{
        hex::encode(&xor_result),
        "746865206b696420646f6e277420706c6179"
    }
}

#[test]
fn simple_dot_product() {
    let x = vec![30.0, 1.0, 2.0];
    let y = vec![1.0, 1.0, 2.0];
    assert_eq!(x.dot(&y), 35.0)
}

#[test]
fn set1_challenge3() {
    // Use Moby Dick to get {printable ASCII character] frequencies.
    let english_freq = get_char_freq_from_file();

    let test_str =
        String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let (likely_byte, likely_msg) = likely_single_byte_xor(test_str, english_freq);

    let msg: String = likely_msg.iter().map(|c| *c as char).collect();

    println!("Message: {}, {}", msg, likely_byte as u8);
}
