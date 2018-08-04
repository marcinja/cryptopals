use base64;
use hex;

fn hex_to_base64(s: String) -> String {
    let hex_vec = hex::decode(s);
    let hex_vec = match hex_vec {
        Ok(v) => v,
        Err(error) => panic!("Problem with hex decode {}", error)
    };

    let base64_res = base64::encode(&hex_vec);
    base64_res
}


#[test]
fn set1_challenge1() {
    assert_eq!{
        hex_to_base64(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")),
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    }
}
