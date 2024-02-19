mod signer;

use crate::signer::{Signer , TSigner};

use secp256k1::hashes::hex::{Case, DisplayHex};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1};

use keccak_hash::keccak_256;
use std::str;


fn main() {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    
    let  mut privKeyHex = String::new();
    for b in secret_key.secret_bytes() {
        privKeyHex.push_str(&format!("{:02x}", b));
    }
    println!("privKey_key: {:?}", privKeyHex);
    println!("public_key: {:?}", public_key);

    let mut ethAddr : [u8 ; 32] = [0 ; 32 ]; 

    keccak_256(&mut public_key.serialize_uncompressed()[1..] , &mut ethAddr);
    println!("ethAddr: {:?} ", ethAddr[12..].to_hex_string(Case::Lower));

    let mut signer = Signer::new(&secret_key);

    let message = b"hello world";

    let signature = signer.schnorr_sign(message);

    println!("R : {:?}", signature.0);
    println!("S : {:?}", signature.1);
    println!("E : {:?}", signature.2);
}
