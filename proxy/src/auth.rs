use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const NBF_SECS: usize = 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub challenge: String,
    pub method: String,
    pub exp: usize,
    pub iat: usize,
    pub nbf: usize,
    // TODO mikel: add policyRule, action...
}

// TODO mikel:
// The token service currently supports Ed25519 keys only, but
// anubis has configurable support for HS512 too.
pub struct TokenService {
    pub encoding_key: jwt::EncodingKey,
    pub decoding_key: jwt::DecodingKey,
}

impl TokenService {
    pub fn new(seed: &[u8]) -> Result<Self, AuthError> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| AuthError::InvalidKeyLength)?;

        let signing_key = SigningKey::from_bytes(&seed);
        let pkcs8_der = signing_key
            .to_pkcs8_der()
            .map_err(|_| AuthError::KeyEncoding)?;

        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            encoding_key: jwt::EncodingKey::from_ed_der(pkcs8_der.as_bytes()),
            decoding_key: jwt::DecodingKey::from_ed_der(verifying_key.as_bytes()),
        })
    }

    pub fn mint(
        &self,
        challenge_id: &str,
        method: &str,
        ttl_secs: u64,
    ) -> Result<String, AuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let claims = Claims {
            challenge: challenge_id.to_string(),
            method: method.to_string(),
            exp: now + ttl_secs as usize,
            iat: now,
            nbf: now - NBF_SECS,
        };
        jwt::encode(
            &jwt::Header::new(jwt::Algorithm::EdDSA),
            &claims,
            &self.encoding_key,
        )
        .map_err(|_| AuthError::TokenCreation)
    }

    pub fn verify(&self, token: &str) -> Option<Claims> {
        let validation = jwt::Validation::new(jwt::Algorithm::EdDSA);
        jwt::decode(token, &self.decoding_key, &validation)
            .ok()
            .map(|d| d.claims)
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidKeyLength,
    KeyEncoding,
    TokenCreation,
}
