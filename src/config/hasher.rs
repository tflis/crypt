extern crate base64;
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{CryptError, CryptResult};
use crate::hasher::{BcryptHasher, IHasher, Pbkdf2Hasher};

#[derive(Serialize, Deserialize)]
pub struct HasherConfig {
    algorithm: String,
    rounds: u32,
    salt: Vec<u8>,
}

#[allow(dead_code)]
pub struct HasherData {
    configurations: HashMap<String, Box<HasherConfig>>,
    latest_version: String,
}

impl HasherConfig {
    #[allow(dead_code)]
    pub fn new(algorithm: String, rounds: u32, salt: Vec<u8>) -> HasherConfig {
        HasherConfig {
            algorithm: algorithm,
            rounds: rounds,
            salt: salt,
        }
    }
}

impl HasherData {
    #[allow(dead_code)]
    pub fn new() -> HasherData {
        HasherData {
            configurations: HashMap::new(),
            latest_version: "0".to_string(),
        }
    }
    pub fn contains_configuration(&self, version: &str) -> bool {
        self.configurations.contains_key(version)
    }

    pub fn insert_configuration(&mut self, version: &str, cfg: Box<HasherConfig>) {
        self.configurations.insert(version.to_string(), cfg);
        self.update_version(version);
    }

    pub fn get_latest_version(&self) -> &str {
        self.latest_version.as_str()
    }

    pub fn get_config<'a>(&'a self, version: &str) -> Option<&'a Box<HasherConfig>> {
        self.configurations.get(version)
    }

    fn update_version(&mut self, version: &str) {
        if self.latest_version.as_str() < version {
            self.latest_version = version.to_string()
        }
    }
}

#[allow(dead_code)]
pub fn generate_hasher_from_config(cfg: &HasherConfig) -> CryptResult<Box<dyn IHasher>> {
    match cfg.algorithm.as_ref() {
        "bcrypt" => Ok(Box::new(BcryptHasher::new(cfg.rounds, &cfg.salt))),
        "pbkdf2" => Ok(Box::new(Pbkdf2Hasher::new(cfg.rounds, &cfg.salt))),
        _ => Err(CryptError::HasherNotFound(cfg.algorithm.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::generate_hasher_from_config;
    use super::HasherConfig;
    #[test]
    fn bcrypt_algorithm() {
        let rounds = 10;
        let salt = [10u8, 16].to_vec();
        let cfg = HasherConfig {
            rounds: rounds,
            salt: salt,
            algorithm: "bcrypt".to_string(),
        };

        let hasher = generate_hasher_from_config(&cfg).unwrap();
        let password = "password";
        let data = hasher.encrypt(password);

        assert!(hasher.verify(&data, password));

        let password = "password2";
        assert!(!hasher.verify(&data, password));
    }

    #[test]
    fn pbkdf2_algorithm() {
        let rounds = 10;
        let salt = [10u8, 16].to_vec();
        let cfg = HasherConfig {
            rounds: rounds,
            salt: salt,
            algorithm: "pbkdf2".to_string(),
        };

        let hasher = generate_hasher_from_config(&cfg).unwrap();
        let password = "password";
        let data = hasher.encrypt(password);

        assert!(hasher.verify(&data, password));

        let password = "password2";
        assert!(!hasher.verify(&data, password));
    }

    #[test]
    fn unknown_algorithm() {
        let rounds = 10;
        let salt = [10u8, 16].to_vec();
        let cfg = HasherConfig {
            rounds: rounds,
            salt: salt,
            algorithm: "unknown".to_string(),
        };

        let out = generate_hasher_from_config(&cfg);
        assert!(out.is_err());
    }

    #[test]
    fn mixed_algorithm() {
        let rounds = 10;
        let salt = [10u8, 16].to_vec();
        let cfg1 = HasherConfig {
            rounds: rounds,
            salt: salt,
            algorithm: "bcrypt".to_string(),
        };
        let salt = [10u8, 16].to_vec();
        let cfg2 = HasherConfig {
            rounds: rounds,
            salt: salt,
            algorithm: "pbkdf2".to_string(),
        };

        let hasher1 = generate_hasher_from_config(&cfg1).unwrap();
        let hasher2 = generate_hasher_from_config(&cfg2).unwrap();
        let password = "password";
        let data1 = hasher1.encrypt(password);
        let data2 = hasher2.encrypt(password);

        assert!(hasher1.verify(&data1, password));
        assert!(hasher2.verify(&data2, password));
        assert!(!hasher1.verify(&data2, password));
        assert!(!hasher2.verify(&data1, password));

        let password = "password2";
        assert!(!hasher1.verify(&data1, password));
        assert!(!hasher2.verify(&data2, password));
        assert!(!hasher1.verify(&data2, password));
        assert!(!hasher2.verify(&data1, password));
    }
}
