use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

// TODO mikel:
// The token service currently supports Ed25519 keys only, but
// anubis has configurable support for HS512 too.
pub struct TokenService {
    pub encoding_key: jwt::EncodingKey,
    pub decoding_key: jwt::DecodingKey,
}

impl TokenService {
    pub fn new(key: &[u8]) -> Self {
        Self {
            encoding_key: jwt::EncodingKey::from_ed_der(key),
            decoding_key: jwt::DecodingKey::from_ed_der(key),
        }
    }

    pub fn mint(&self, ip: &str, ttl_secs: u64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let claims = Claims {
            sub: ip.to_string(),
            exp: now + ttl_secs as usize,
            iat: now,
        };
        jwt::encode(&jwt::Header::default(), &claims, &self.encoding_key).unwrap()
    }

    pub fn verify(&self, token: &str) -> Option<Claims> {
        let validation = jwt::Validation::new(jwt::Algorithm::EdDSA);
        jwt::decode(token, &self.decoding_key, &validation)
            .ok()
            .map(|d| d.claims)
    }
}
