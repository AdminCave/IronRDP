//! A certificate-validation callback scoped to every certificate also decides on a certificate that
//! passes strict validation.
//!
//! Strict validation trusts the platform roots, which `SSL_CERT_FILE` replaces. The handshakes run in
//! a child process started with that variable, so no other test sees the test CA as a platform root.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use ironrdp::server::TlsIdentityCtx;
use ironrdp_tls::{CertificateValidation, CertificateValidationCallback, CertificateValidationCallbackScope};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::net::{TcpListener, TcpStream};

const CERT_DIR_VARIABLE: &str = "IRONRDP_TLS_CALLBACK_SCOPE_CERT_DIR";
const CHILD_PROCESS_TEST_NAME: &str =
    "tls_callback_scope::child_process_helper_runs_handshakes_against_a_platform_trusted_certificate";
const ENDPOINT: &str = "localhost:3389";

#[test]
fn callback_scoped_to_all_certificates_decides_on_a_platform_trusted_certificate() {
    let directory = env::temp_dir().join(format!("ironrdp-tls-callback-scope-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("create certificate directory");
    write_test_ca_and_server_certificate(&directory);

    let output = Command::new(env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(CHILD_PROCESS_TEST_NAME)
        .arg("--nocapture")
        .env("SSL_CERT_FILE", directory.join("ca.pem"))
        .env_remove("SSL_CERT_DIR")
        .env(CERT_DIR_VARIABLE, &directory)
        .output()
        .expect("spawn TLS handshake process");
    fs::remove_dir_all(&directory).expect("remove certificate directory");

    assert!(
        output.status.success(),
        "TLS handshake process must succeed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "TLS handshake process must run its helper test:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn child_process_helper_runs_handshakes_against_a_platform_trusted_certificate() {
    let Some(directory) = env::var_os(CERT_DIR_VARIABLE).map(PathBuf::from) else {
        return;
    };
    let server_certificate = fs::read(directory.join("server.der")).expect("read server certificate");
    let identity = TlsIdentityCtx::init_from_paths(&directory.join("server.pem"), &directory.join("server-key.pem"))
        .expect("init TLS identity");
    let acceptor = identity.make_acceptor().expect("build TLS acceptor");
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind TLS listener");
    let address = listener.local_addr().expect("TLS listener address");
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept TLS connection");
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });

    let connect = || async { TcpStream::connect(address).await.expect("connect TLS client") };

    ironrdp_tls::upgrade_with_certificate_validation(connect().await, "localhost", CertificateValidation::Strict)
        .await
        .expect("strict validation must accept the certificate the test CA issued");

    // oracle: mutant default scope consulting the callback for a certificate that passes validation
    let default_scope_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&default_scope_calls);
    let counting: CertificateValidationCallback = Arc::new(move |_, _, _| {
        calls.fetch_add(1, Ordering::Relaxed);
        false
    });
    ironrdp_tls::upgrade_with_scoped_certificate_validation_callback(
        connect().await,
        "localhost",
        ENDPOINT,
        counting,
        CertificateValidationCallbackScope::InvalidCertificates,
    )
    .await
    .expect("the default scope must accept a valid certificate without the callback");
    assert_eq!(default_scope_calls.load(Ordering::Relaxed), 0);

    // oracle: mutant all-certificates scope skipping the callback for a certificate that passes validation
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_by_callback = Arc::clone(&seen);
    let approving: CertificateValidationCallback = Arc::new(move |certificate, endpoint, reason| {
        seen_by_callback
            .lock()
            .unwrap()
            .push((certificate.to_vec(), endpoint.to_owned(), reason.to_owned()));
        true
    });
    ironrdp_tls::upgrade_with_scoped_certificate_validation_callback(
        connect().await,
        "localhost",
        ENDPOINT,
        approving,
        CertificateValidationCallbackScope::AllCertificates,
    )
    .await
    .expect("an approving callback must accept the certificate");
    assert_eq!(
        *seen.lock().unwrap(),
        [(server_certificate, ENDPOINT.to_owned(), String::new())],
        "the callback must see the server certificate, the endpoint, and no validation error"
    );

    // oracle: mutant all-certificates scope accepting a valid certificate the callback rejects
    let rejecting: CertificateValidationCallback = Arc::new(|_, _, _| false);
    let rejected = ironrdp_tls::upgrade_with_scoped_certificate_validation_callback(
        connect().await,
        "localhost",
        ENDPOINT,
        rejecting,
        CertificateValidationCallbackScope::AllCertificates,
    )
    .await;
    assert!(
        rejected.is_err(),
        "a rejecting callback must fail the handshake even for a valid certificate"
    );
}

#[test]
fn callback_scope_to_all_certificates_requires_a_callback() {
    // oracle: mutant all-certificates scope silently accepting valid certificates without a callback
    let result = ironrdp_tls::rustls_client_config_with_callback_scope(
        CertificateValidation::Strict,
        ENDPOINT,
        None,
        CertificateValidationCallbackScope::AllCertificates,
    );
    assert!(result.is_err());
}

fn write_test_ca_and_server_certificate(directory: &Path) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    let ca_key = KeyPair::generate().expect("generate CA key");
    let ca_certificate = ca_params.self_signed(&ca_key).expect("self-sign CA certificate");
    let issuer = Issuer::new(ca_params, ca_key);

    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("server parameters");
    server_params.use_authority_key_identifier_extension = true;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("generate server key");
    let server_certificate = server_params
        .signed_by(&server_key, &issuer)
        .expect("sign server certificate");

    fs::write(directory.join("ca.pem"), ca_certificate.pem()).expect("write CA certificate");
    fs::write(directory.join("server.pem"), server_certificate.pem()).expect("write server certificate");
    fs::write(directory.join("server.der"), server_certificate.der()).expect("write server certificate");
    fs::write(directory.join("server-key.pem"), server_key.serialize_pem()).expect("write server key");
}
