use axum::http::{HeaderMap, HeaderName};
use compact_str::CompactString;
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const NBF_SECS: usize = 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub challenge: Uuid,
    pub method: CompactString,
    pub rule_hash: u64, // Anubis uses names, but I don't think there's risk collision and hashes are cheaper
    pub exp: usize,
    pub iat: usize,
    pub nbf: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub restriction: Option<String>,
}

pub fn restriction_for_request(
    headers: &HeaderMap,
    header_name: Option<&HeaderName>,
) -> Result<Option<String>, RestrictionError> {
    let Some(header_name) = header_name else {
        return Ok(None);
    };

    let header_value = headers
        .get(header_name)
        .ok_or_else(|| RestrictionError::MissingHeader(header_name.clone()))?;

    let header_text = header_value
        .to_str()
        .map_err(|_| RestrictionError::InvalidHeaderValue(header_name.clone()))?;

    Ok(Some(sha256_to_hex(header_text)))
}

fn sha256_to_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

pub struct TokenService {
    encoding_key: jwt::EncodingKey,
    decoding_key: jwt::DecodingKey,
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
        challenge_id: Uuid,
        method: &str,
        rule_hash: u64,
        restriction: Option<String>,
        ttl_secs: u64,
    ) -> Result<String, AuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be later than the Unix epoch")
            .as_secs() as usize;

        let claims = Claims {
            challenge: challenge_id,
            method: CompactString::new(method),
            rule_hash,
            exp: now + ttl_secs as usize,
            iat: now,
            nbf: now.saturating_sub(NBF_SECS),
            restriction,
        };

        jwt::encode(
            &jwt::Header::new(jwt::Algorithm::EdDSA),
            &claims,
            &self.encoding_key,
        )
        .map_err(|_| AuthError::TokenCreation)
    }

    pub fn verify(&self, token: &str, current_restriction: Option<&str>) -> Option<Claims> {
        let validation = jwt::Validation::new(jwt::Algorithm::EdDSA);

        let claims: Claims = jwt::decode(token, &self.decoding_key, &validation)
            .ok()?
            .claims;

        if claims.restriction.as_deref() != current_restriction {
            return None;
        }

        Some(claims)
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidKeyLength,
    KeyEncoding,
    TokenCreation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestrictionError {
    MissingHeader(HeaderName),
    InvalidHeaderValue(HeaderName),
}

impl Display for RestrictionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::MissingHeader(header_name) => {
                write!(
                    formatter,
                    "configured JWT restriction header {header_name} is missing"
                )
            }
            Self::InvalidHeaderValue(header_name) => {
                write!(
                    formatter,
                    "configured JWT restriction header {header_name} is not valid text"
                )
            }
        }
    }
}

impl std::error::Error for RestrictionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const RESTRICTION_HEADER: HeaderName = HeaderName::from_static("x-real-ip");
    const RULE_HASH: u64 = 42;
    const ORIGINAL_IP: &str = "198.51.100.42";
    const DIFFERENT_IP: &str = "203.0.113.25";

    fn token_service() -> TokenService {
        TokenService::new(&[7_u8; 32]).unwrap()
    }

    fn headers_with_ip(ip: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RESTRICTION_HEADER, HeaderValue::from_static(ip));
        headers
    }

    #[test]
    fn extracts_and_hashes_the_configured_header() {
        let headers = headers_with_ip(ORIGINAL_IP);

        let restriction = restriction_for_request(&headers, Some(&RESTRICTION_HEADER)).unwrap();

        assert!(restriction.is_some());
        assert_ne!(restriction.as_deref(), Some(ORIGINAL_IP));
    }

    #[test]
    fn reports_a_missing_configured_header() {
        let error =
            restriction_for_request(&HeaderMap::new(), Some(&RESTRICTION_HEADER)).unwrap_err();

        assert_eq!(error, RestrictionError::MissingHeader(RESTRICTION_HEADER));
    }

    #[test]
    fn returns_none_when_restriction_is_disabled() {
        let restriction = restriction_for_request(&HeaderMap::new(), None).unwrap();

        assert_eq!(restriction, None);
    }

    #[test]
    fn accepts_a_token_with_the_same_restriction() {
        let service = token_service();
        let headers = headers_with_ip(ORIGINAL_IP);
        let restriction = restriction_for_request(&headers, Some(&RESTRICTION_HEADER)).unwrap();

        let token = service
            .mint(Uuid::nil(), "sha256", RULE_HASH, restriction.clone(), 60)
            .unwrap();

        assert!(service.verify(&token, restriction.as_deref()).is_some());
    }

    #[test]
    fn rejects_a_token_when_the_restriction_changes() {
        let service = token_service();

        let original =
            restriction_for_request(&headers_with_ip(ORIGINAL_IP), Some(&RESTRICTION_HEADER))
                .unwrap();

        let different =
            restriction_for_request(&headers_with_ip(DIFFERENT_IP), Some(&RESTRICTION_HEADER))
                .unwrap();

        let token = service
            .mint(Uuid::nil(), "sha256", RULE_HASH, original, 60)
            .unwrap();

        assert!(service.verify(&token, different.as_deref()).is_none());
    }

    #[test]
    fn rejects_a_restricted_token_when_restriction_is_now_disabled() {
        let service = token_service();

        let restriction =
            restriction_for_request(&headers_with_ip(ORIGINAL_IP), Some(&RESTRICTION_HEADER))
                .unwrap();

        let token = service
            .mint(Uuid::nil(), "sha256", RULE_HASH, restriction, 60)
            .unwrap();

        assert!(service.verify(&token, None).is_none());
    }

    #[test]
    fn accepts_an_unrestricted_token_only_without_a_restriction() {
        let service = token_service();

        let token = service
            .mint(Uuid::nil(), "sha256", RULE_HASH, None, 60)
            .unwrap();

        assert!(service.verify(&token, None).is_some());

        assert!(service.verify(&token, Some("unexpected")).is_none());
    }

    #[test]
    fn a_token_carries_the_rule_hash() {
        let service = token_service();
        let token = service
            .mint(Uuid::nil(), "sha256", RULE_HASH, None, 60)
            .unwrap();

        assert_eq!(service.verify(&token, None).unwrap().rule_hash, RULE_HASH);
    }
}
