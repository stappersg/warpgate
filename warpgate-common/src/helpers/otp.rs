use super::rng::{get_crypto_rng};
use crate::types::Secret;
use rand::Rng;
use totp_rs::{Algorithm, TOTP};

pub type OtpExposedSecretKey = [u8; 32];
pub type OtpSecretKey = Secret<OtpExposedSecretKey>;

pub fn generate_key() -> OtpSecretKey {
    Secret::new(get_crypto_rng().gen())
}

pub fn generate_setup_url(key: &OtpSecretKey, label: &str) -> Secret<String> {
    let totp = get_totp(key);
    Secret::new(totp.get_url(label, "Warpgate"))
}

fn get_totp(key: &OtpSecretKey) -> TOTP<OtpExposedSecretKey> {
    TOTP::new(Algorithm::SHA1, 6, 1, 30, key.expose_secret().clone())
}
