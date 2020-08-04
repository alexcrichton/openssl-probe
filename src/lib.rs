use std::env;
use std::fs;
use std::path::PathBuf;

/// The OpenSSL environment variable to configure what certificate file to use.
pub const ENV_CERT_FILE: &'static str = "SSL_CERT_FILE";

/// The OpenSSL environment variable to configure what certificates directory to use.
pub const ENV_CERT_DIR: &'static str = "SSL_CERT_DIR";

pub struct ProbeResult {
    pub cert_file: Option<PathBuf>,
    pub cert_dir: Option<PathBuf>,
}

/// Probe the system for the directory in which CA certificates should likely be
/// found.
///
/// This will only search known system locations.
pub fn find_certs_dirs() -> Vec<PathBuf> {
    // see http://gagravarr.org/writing/openssl-certs/others.shtml
    [
        "/var/ssl",
        "/usr/share/ssl",
        "/usr/local/ssl",
        "/usr/local/openssl",
        "/usr/local/etc/openssl",
        "/usr/local/share",
        "/usr/lib/ssl",
        "/usr/ssl",
        "/etc/openssl",
        "/etc/pki/ca-trust/extracted/pem",
        "/etc/pki/tls",
        "/etc/ssl",
        "/data/data/com.termux/files/usr/etc/tls",
        "/boot/system/data/ssl",
    ].iter().map(|s| PathBuf::from(*s)).filter(|p| {
        fs::metadata(p).is_ok()
    }).collect()
}

/// Probe for SSL certificates on the system, then configure the SSL certificate `SSL_CERT_FILE`
/// and `SSL_CERT_DIR` environment variables in this process for OpenSSL to use.
///
/// Preconfigured values in the environment variables will not be overwritten.
///
/// Returns `true` if any certificate file or directory was found while probing.
/// Combine this with `has_ssl_cert_env_vars()` to check whether previously configured environment
/// variables are valid.
pub fn init_ssl_cert_env_vars() -> bool {
    let ProbeResult { cert_file, cert_dir } = probe();
    match &cert_file {
        Some(path) => put(ENV_CERT_FILE, path),
        None => {}
    }
    match &cert_dir {
        Some(path) => put(ENV_CERT_DIR, path),
        None => {}
    }

    fn put(var: &str, path: &PathBuf) {
        // Don't stomp over what anyone else has set
        match env::var(var) {
            Ok(..) => {}
            Err(..) => env::set_var(var, path),
        }
    }

    cert_file.is_some() || cert_dir.is_some()
}

/// Check whether the OpenSSL `SSL_CERT_FILE` and/or `SSL_CERT_DIR` environment variable is
/// configured in this process with an existing file or directory.
///
/// That being the case would indicate that certificates will be found successfully by OpenSSL.
///
/// Returns `true` if either variable is set to an existing file or directory.
pub fn has_ssl_cert_env_vars() -> bool {
    env::var(ENV_CERT_FILE)
        .map(|file| fs::metadata(file).is_ok())
        .unwrap_or(false)
        ||
    env::var(ENV_CERT_DIR)
        .map(|dir| fs::metadata(dir).is_ok())
        .unwrap_or(false)
}

pub fn probe() -> ProbeResult {
    let mut result = ProbeResult {
        cert_file: env::var_os(ENV_CERT_FILE).map(PathBuf::from),
        cert_dir: env::var_os(ENV_CERT_DIR).map(PathBuf::from),
    };
    for certs_dir in find_certs_dirs().iter() {
        // cert.pem looks to be an openssl 1.0.1 thing, while
        // certs/ca-certificates.crt appears to be a 0.9.8 thing
        for cert in [
            "cert.pem",
            "certs.pem",
            "ca-bundle.pem",
            "certs/ca-certificates.crt",
            "certs/ca-root-nss.crt",
            "certs/ca-bundle.crt",
            "CARootCertificates.pem",
            "tls-ca-bundle.pem",
        ].iter() {
            try(&mut result.cert_file, certs_dir.join(cert));
        }
        try(&mut result.cert_dir, certs_dir.join("certs"));
    }
    result
}

fn try(dst: &mut Option<PathBuf>, val: PathBuf) {
    if dst.is_none() && fs::metadata(&val).is_ok() {
        *dst = Some(val);
    }
}
