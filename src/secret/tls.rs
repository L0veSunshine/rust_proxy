use anyhow::{Result, anyhow};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

// 注意：新版 Rustls 将证书类型移到了 pki_types 模块/crate 中
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// === 服务端配置 ===
pub fn create_server_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    // 1. 读取证书
    // rustls-pemfile 2.0 变更为返回 Iterator<Result<Item>>，需要 collect
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    // 2. 读取私钥
    // rustls-pemfile 2.0 提供了 private_key() 帮助函数，自动识别 PKCS8/RSA/SEC1 格式
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("No private key found in file"))?;

    // 3. 构建配置
    // .with_safe_defaults() 已被移除，现在的 builder() 默认就是安全的
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// === 客户端配置 (开启验证) ===
pub fn create_client_config(ca_path: &str) -> Result<TlsConnector> {
    // 1. 创建根证书存储
    let mut root_store = rustls::RootCertStore::empty();

    // 2. 读取 CA 证书文件 (比如 ca.pem)
    // 如果你是自签名证书且没有单独的 CA，这里可以直接加载服务器的 cert.pem
    let ca_file =
        File::open(ca_path).map_err(|e| anyhow!("Failed to open CA file '{}': {}", ca_path, e))?;
    let mut ca_reader = BufReader::new(ca_file);

    // 3. 将证书添加到信任列表
    // rustls-pemfile 2.0 返回的是 Result<Item> 的迭代器
    let certs = rustls_pemfile::certs(&mut ca_reader).collect::<Result<Vec<_>, _>>()?;

    for cert in certs {
        root_store.add(cert)?;
    }

    // 4. 构建配置
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
