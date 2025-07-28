use jsonwebtoken::{EncodingKey, DecodingKey};
use once_cell::sync::Lazy;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs8::DecodePublicKey, RsaPublicKey};
use rand::rngs::OsRng;
use std::sync::RwLock;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone)]
pub struct KeyPair {
    pub kid: String,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey<'static>,
    pub public_jwk: Jwk,
}

#[derive(Serialize, Clone)]
pub struct Jwk {
    kty: &'static str,
    kid: String,
    use_: &'static str,
    alg: &'static str,
    n: String,
    e: String,
}

static KEY_STORE: Lazy<RwLock<Vec<KeyPair>>> = Lazy::new(|| {
    let pair = generate_rsa_key();
    RwLock::new(vec![pair])
});

pub fn current_key() -> KeyPair {
    KEY_STORE.read().unwrap()[0].clone()
}

pub fn rotate_keys() -> KeyPair {
    let new_key = generate_rsa_key();
    let mut store = KEY_STORE.write().unwrap();
    store.insert(0, new_key.clone());
    // keep only last 3 keys
    if store.len() > 3 { store.truncate(3); }
    new_key
}

pub fn jwks() -> Vec<Jwk> {
    KEY_STORE.read().unwrap().iter().map(|k| k.public_jwk.clone()).collect()
}

pub fn decoding_key(kid: &str) -> Option<DecodingKey<'static>> {
    KEY_STORE.read().ok()?.iter().find(|k| k.kid == kid).map(|k| k.decoding.clone())
}

fn generate_rsa_key() -> KeyPair {
    let mut rng = OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).expect("key gen");
    let kid = Uuid::new_v4().to_string();
    let n_bytes = private.to_public_key().n().to_bytes_be();
    let e_bytes = private.to_public_key().e().to_bytes_be();
    let n_b64 = URL_SAFE_NO_PAD.encode(n_bytes);
    let e_b64 = URL_SAFE_NO_PAD.encode(e_bytes);
    let public_jwk = Jwk {
        kty: "RSA",
        kid: kid.clone(),
        use_: "sig",
        alg: "RS256",
        n: n_b64,
        e: e_b64,
    };
    let pem = private.to_pkcs1_pem(Default::default()).unwrap();
    let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let decoding = DecodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    KeyPair { kid, encoding, decoding, public_jwk }
} 