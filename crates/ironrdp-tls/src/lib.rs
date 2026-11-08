#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]

use std::sync::Arc;

#[cfg(feature = "rustls-verifier")]
use tokio as _;
#[cfg(any(feature = "native-tls", test))]
use tokio_native_tls as _;

#[cfg(feature = "rustls-no-provider")]
#[path = "rustls.rs"]
mod impl_;

#[cfg(feature = "native-tls")]
#[path = "native_tls.rs"]
mod impl_;

#[cfg(feature = "stub")]
#[path = "stub.rs"]
mod impl_;

#[cfg(feature = "rustls-verifier")]
mod rustls_verifier;

#[cfg(any(
    not(any(
        feature = "stub",
        feature = "native-tls",
        feature = "rustls-no-provider",
        feature = "rustls-verifier"
    )),
    all(feature = "stub", feature = "native-tls"),
    all(feature = "stub", feature = "rustls-no-provider"),
    all(feature = "rustls-no-provider", feature = "native-tls"),
))]
compile_error!(
    "a TLS backend must be selected by enabling a single feature out of: `rustls`, `native-tls`, `stub` (the rustls crypto provider is chosen via `rustls`/`rustls-aws-lc-rs`/`rustls-ring`/`rustls-no-provider`)"
);

#[cfg(any(feature = "stub", feature = "native-tls", feature = "rustls-no-provider"))]
pub use impl_::{
    TlsStream, negotiated, upgrade, upgrade_with_certificate_validation, upgrade_with_certificate_validation_callback,
    upgrade_with_certificate_validation_callback_for_endpoint, upgrade_with_scoped_certificate_validation_callback,
};
#[cfg(feature = "rustls-verifier")]
pub use rustls_verifier::{rustls_client_config, rustls_client_config_with_callback_scope};

/// Called when the Rustls backend cannot validate a server certificate.
///
/// The callback receives the leaf certificate's DER encoding, the configured endpoint,
/// and a validation-error description. Returning `true` accepts that certificate for the
/// current handshake.
/// Callers must make this decision explicitly and should retain the certificate
/// fingerprint rather than accepting a host blindly.
///
/// The `native-tls` and stub backends cannot safely support this operation and return
/// an error if it is requested.
///
/// With [`CertificateValidationCallbackScope::AllCertificates`] the callback also decides on
/// certificates that pass validation; the validation-error description is empty for those.
pub type CertificateValidationCallback = Arc<dyn Fn(&[u8], &str, &str) -> bool + Send + Sync>;

/// The server certificates a [`CertificateValidationCallback`] decides on.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertificateValidationCallbackScope {
    /// Only certificates that fail strict validation; a valid certificate is accepted without the callback.
    #[default]
    InvalidCertificates,
    /// Every server certificate, after strict validation: a valid certificate is accepted only if the
    /// callback approves it too.
    ///
    /// Use this to pin certificates, so that a certificate a platform root vouches for cannot replace a
    /// pinned one.
    AllCertificates,
}

/// Certificate-validation policy applied during a TLS handshake.
///
/// [`CertificateValidation::DangerouslyAcceptInvalidCertificate`] is the default to
/// preserve the historic client behavior. Select [`CertificateValidation::Strict`] to
/// validate the peer certificate chain and server name against the platform trust store.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CertificateValidation {
    /// Validate the peer certificate chain and server name.
    Strict,
    /// Accept any peer certificate and server name, preserving historic behavior.
    ///
    /// This disables TLS authentication and is vulnerable to on-path attacks.
    #[default]
    DangerouslyAcceptInvalidCertificate,
}

/// TLS parameters negotiated during the handshake, to the extent the active
/// backend exposes them.
///
/// The `rustls` backend reports both fields. The `native-tls` and `stub`
/// backends cannot introspect the negotiated parameters, so both are `None`
/// there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NegotiatedTls {
    /// Negotiated protocol version, e.g. `"TLSv1_3"`.
    pub version: Option<String>,
    /// Negotiated cipher suite, e.g. `"TLS13_AES_256_GCM_SHA384"`.
    pub cipher_suite: Option<String>,
}

#[cfg(any(feature = "native-tls", feature = "rustls-no-provider"))]
pub fn extract_tls_server_public_key(cert: &x509_cert::Certificate) -> Option<&[u8]> {
    cert.tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
}
