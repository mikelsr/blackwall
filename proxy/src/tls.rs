use rustls::{DigitallySignedStruct, Error, SignatureScheme, client::danger, crypto, pki_types};

/// Verifies handshake signatures, but not certificates or hostnames
#[derive(Debug)]
pub(crate) struct SignatureVerifier;

impl danger::ServerCertVerifier for SignatureVerifier {
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
        message: &[u8],
        certificate: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, Error> {
        let provider = crypto::ring::default_provider();
        crypto::verify_tls12_signature(
            message,
            certificate,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, Error> {
        let provider = crypto::ring::default_provider();
        crypto::verify_tls13_signature(
            message,
            certificate,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
