

// y^2 = x^3 + y (mod p) --> Secp256k1 curve
// p = 115792089237316195423570985008687907853269984665640564039457584007908834671663 [2^256 – 2^32 – 977]

// Generator Point G
// x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
// y = 32670510020758816978083085130507043184471273380659243275938904335757337482424

use keccak_hash::keccak_256;
use secp256k1::{Secp256k1, SecretKey};
use secp256k1::rand::rngs::OsRng;



// only Holds spec256 Privkey
pub struct Signer<'a>{
    priv_key: &'a SecretKey,
    pub_key : secp256k1::PublicKey,
}

pub trait TSigner {
    /**
     * generate Pub_X from privKey (x)
     * generate random k [u8 : 32]
     * generate R such that R = G * k (assume R is pubKey_X and K is privKey)
     * 
     * find MessageHashE (e)
     * e = keccakHash(
     *      keccak(R.x + R.y)[last 20 bytes:], --> address
     *      parity,
     *      PubKey_X,
     *      Message
     * )
     * 
     * multiply x * e [secp256k1 multiplication mulmod]
     * now generate `s` by adding k + x * e
     * 
     * return {R.x , s , e}
     */
    fn schnorr_sign(&self, message: &[u8]) -> ([u8; 33] , [u8; 32] , [u8; 32]);
}


impl  TSigner for Signer<'_> {
    fn schnorr_sign(&self, message: &[u8]) -> ([u8; 33] , [u8; 32] , [u8; 32]) {
        let pub_x = self.pub_key.x_only_public_key();
        let xonly_pub_key = pub_x.0;

        let secp = Secp256k1::new();
        let (k, r_pub_key) = secp.generate_keypair(&mut OsRng);

        let mut r_addr : [u8 ; 32] = [0 ; 32 ]; 
        keccak_256(&mut r_pub_key.serialize_uncompressed()[1..] , &mut r_addr);
        // println!("parity : {:?}", Pub_X.1);

        let mut data = Vec::new();
        data.extend_from_slice(&r_addr[12..32]);
        data.push(pub_x.1.into());
        data.extend_from_slice(&xonly_pub_key.serialize());
        data.extend_from_slice(message);

        let mut e : [u8 ; 32] = [0 ; 32];
        keccak_256(&mut data , &mut e);
        
        // find x*e
        // find k + x * e

        let x_e = self.priv_key.mul_tweak(&secp256k1::Scalar::from_be_bytes(e).unwrap()).unwrap();
        let s = k.add_tweak(&secp256k1::Scalar::from_be_bytes(x_e.secret_bytes()).unwrap()).unwrap();

        (r_pub_key.serialize() , s.secret_bytes() , e)
    }
}

impl<'a> Signer<'a> {
    pub fn new(priv_key : &'a SecretKey ) -> Self {
        Self {
            priv_key,
            pub_key : priv_key.public_key(&Secp256k1::new()),
        }
    }
}
