extern crate base64;
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::cipher::aes::{CBCCipher, CFB1Cipher, ECBCipher};
use crate::cipher::{generate_salt, ICipher};
use crate::error::{CryptError, CryptResult};

#[derive(Serialize, Deserialize)]
pub struct CipherConfig {
  algorithm: String,
  secret:    Vec<u8>
}

#[allow(dead_code)]
pub struct CipherData {
  configurations: HashMap<String, Box<CipherConfig>>,
  latest_version: String
}

impl CipherConfig {
  #[allow(dead_code)]
  pub fn new(algorithm: String, secret: Vec<u8>) -> CipherConfig {
    CipherConfig { algorithm: algorithm, secret: secret }
  }
}

impl CipherData {
  #[allow(dead_code)]
  pub fn new() -> CipherData {
    CipherData { configurations: HashMap::new(), latest_version: "0".to_string() }
  }

  pub fn contains_configuration(&self, version: &str) -> bool {
    self.configurations.contains_key(version)
  }

  pub fn insert_configuration(&mut self, version: &str, cfg: Box<CipherConfig>) {
    self.configurations.insert(version.to_string(), cfg);
    self.update_version(version);
  }

  pub fn get_latest_version(&self) -> &str {
    self.latest_version.as_str()
  }

  pub fn get_config<'a>(&'a self, version: &str) -> Option<&'a Box<CipherConfig>> {
    self.configurations.get(version)
  }

  fn update_version(&mut self, version: &str) {
    if self.latest_version.as_str() < version {
      self.latest_version = version.to_string()
    }
  }
}

#[allow(dead_code)]
pub fn generate_cipher_from_config(cfg: &CipherConfig) -> CryptResult<Box<dyn ICipher>> {
  let salt = generate_salt();

  match cfg.algorithm.as_ref() {
    "aes_cbc" => Ok(Box::new(CBCCipher::new(&cfg.secret, &salt))),
    "aes_cfb1" => Ok(Box::new(CFB1Cipher::new(&cfg.secret, &salt))),
    "aes_ecb" => Ok(Box::new(ECBCipher::new(&cfg.secret, &salt))),
    _ => Err(CryptError::CipherNotFound(cfg.algorithm.clone()))
  }
}

#[cfg(test)]
mod tests {
  use super::generate_cipher_from_config;
  use super::CipherConfig;
  #[test]
  fn aes_cbc_algorithm() {
    let secret = [11u8, 16].to_vec();
    let cfg = CipherConfig { algorithm: "aes_cbc".to_string(), secret: secret };

    let cipher = generate_cipher_from_config(&cfg).unwrap();
    let data = "very secured data";
    let crypted = cipher.encrypt(data).unwrap();

    assert_eq!(data, cipher.decrypt(&crypted).unwrap());
  }
  #[test]
  fn aes_cfb1_algorithm() {
    let secret = [11u8, 16].to_vec();
    let cfg = CipherConfig { algorithm: "aes_cfb1".to_string(), secret: secret };

    let cipher = generate_cipher_from_config(&cfg).unwrap();
    let data = "very secured data";
    let crypted = cipher.encrypt(data).unwrap();

    assert_eq!(data, cipher.decrypt(&crypted).unwrap());
  }
  #[test]
  fn aes_ecb_algorithm() {
    let secret = [11u8, 16].to_vec();
    let cfg = CipherConfig { algorithm: "aes_ecb".to_string(), secret: secret };

    let cipher = generate_cipher_from_config(&cfg).unwrap();
    let data = "very secured data";
    let crypted = cipher.encrypt(data).unwrap();

    assert_eq!(data, cipher.decrypt(&crypted).unwrap());
  }
  #[test]
  fn unknown_algorithm() {
    let secret = [11u8, 16].to_vec();
    let cfg = CipherConfig { algorithm: "unknown".to_string(), secret: secret };

    assert!(generate_cipher_from_config(&cfg).is_err());
  }
}
