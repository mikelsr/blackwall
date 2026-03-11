use rustls;
use rustls::{DigitallySignedStruct, Error, SignatureScheme, client::danger, crypto, pki_types};
use std::sync::LazyLock;

/// Accepts any server certificate. There has to be a cleaner way to do this.
#[derive(Debug)]
pub(crate) struct NilVerifier;

static SUPPORTED_SCHEMES: LazyLock<Vec<SignatureScheme>> = LazyLock::new(|| {
    crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
});

impl danger::ServerCertVerifier for NilVerifier {
    fn verify_server_cert(
        &self,
        _: &pki_types::CertificateDer<'_>,
        _: &[pki_types::CertificateDer<'_>],
        _: &pki_types::ServerName<'_>,
        _: &[u8],
        _: pki_types::UnixTime,
    ) -> Result<danger::ServerCertVerified, Error> {
        Ok(danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &pki_types::CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, Error> {
        Ok(danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &pki_types::CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, Error> {
        Ok(danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SCHEMES.clone()
    }
}
