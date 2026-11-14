use anyhow::{Result, anyhow, bail};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// 读取 PEM 文件中的全部证书
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow!("Failed to open certificate file '{}': {}", path, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse certificate file '{}': {}", path, e))?;
    if certs.is_empty() {
        bail!("No certificate found in '{}'", path);
    }
    Ok(certs)
}

// === 服务端配置 ===
pub fn create_server_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    // 1. 读取证书
    let certs = load_certs(cert_path)?;

    // 2. 读取私钥（自动识别 PKCS8/RSA/SEC1 格式）
    let private_key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| anyhow!("Failed to load private key '{}': {}", key_path, e))?;

    // 3. 构建配置
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// === 客户端配置 (开启验证) ===
pub fn create_client_config(ca_path: &str) -> Result<TlsConnector> {
    // 1. 创建根证书存储
    let mut root_store = rustls::RootCertStore::empty();

    // 2. 读取 CA 证书文件 (比如 ca.pem) 并加入信任列表
    // 如果你是自签名证书且没有单独的 CA，这里可以直接加载服务器的 cert.pem
    for cert in load_certs(ca_path)? {
        root_store.add(cert)?;
    }

    // 3. 构建配置
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

#[allow(dead_code)]
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 直接返回验证通过
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // 返回所有支持的签名算法，确保能和任意服务器握手
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
