use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

/// A self-signed Certificate Authority used to dynamically sign per-host
/// certificates so the proxy can terminate TLS transparently.
///
/// A fresh CA is generated on every run. The PEM certificate is saved to
/// disk so that users can install it in external browsers if needed.
#[derive(Clone)]
pub struct CertificateAuthority {
    ca_cert: Arc<rcgen::Certificate>,
    ca_key: Arc<KeyPair>,
    ca_cert_pem: String,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("ca_cert_pem_len", &self.ca_cert_pem.len())
            .finish()
    }
}

impl CertificateAuthority {
    pub fn cert_path(ca_dir: &Path) -> PathBuf {
        ca_dir.join("dothound-ca.crt")
    }

    pub fn key_path(ca_dir: &Path) -> PathBuf {
        ca_dir.join("dothound-ca.key")
    }

    /// Create or reuse a CA. Currently always generates a fresh CA;
    /// TODO(Phase 3): persist and reload CA for stable identity across runs.
    pub fn load_or_create(ca_dir: &Path) -> io::Result<Self> {
        Self::create(ca_dir)
    }

    /// Generate a fresh CA, persisting the PEM certificate and key to disk.
    pub fn create(ca_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(ca_dir)?;
        let ca = Self::generate()?;
        fs::write(Self::cert_path(ca_dir), &ca.ca_cert_pem)?;
        fs::write(Self::key_path(ca_dir), ca.ca_key.serialize_pem())?;
        Ok(ca)
    }

    fn generate() -> io::Result<Self> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "DotHound MITM CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "DotHound");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let ca_key = KeyPair::generate().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert: Arc::new(ca_cert),
            ca_key: Arc::new(ca_key),
            ca_cert_pem,
        })
    }

    /// Generate a new certificate for `hostname` signed by this CA.
    pub fn generate_host_cert(
        &self,
        hostname: &str,
    ) -> io::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::new(vec![hostname.to_owned()])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        params.distinguished_name.push(DnType::CommonName, hostname);

        let host_key = KeyPair::generate().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let host_cert = params
            .signed_by(&host_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let cert_der = CertificateDer::from(host_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(host_key.serialize_der()));

        Ok((cert_der, key_der))
    }

    /// Return the CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Build a rustls ServerConfig that presents a dynamically-generated
    /// certificate for the given hostname.
    pub fn server_config_for_host(&self, hostname: &str) -> io::Result<rustls::ServerConfig> {
        let (cert, key) = self.generate_host_cert(hostname)?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    /// Build a default rustls ClientConfig that trusts public roots.
    pub fn upstream_client_config() -> io::Result<rustls::ClientConfig> {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(config)
    }
}
