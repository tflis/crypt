extern crate base64;
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{CryptError, CryptResult};
use crate::hasher::{BcryptHasher, IHasher, Pbkdf2Hasher};

#[derive(Serialize, Deserialize)]
pub struct HashConfig {
    rounds: u32,
    salt: String,
    algorithm: String,
}

#[derive(Serialize, Deserialize)]
pub struct HashValueData {
    version: u32,
    hash: String,
}

#[allow(dead_code)]
struct HashData {
    configurations: HashMap<u32, HashConfig>,
    latest_version: u32,
}

#[allow(dead_code)]
pub fn generate_hasher_from_config(cfg: &HashConfig) -> CryptResult<Box<dyn IHasher>> {
    let salt = base64::decode(&cfg.salt)?;

    match cfg.algorithm.as_ref() {
        "bcrypt" => Ok(Box::new(BcryptHasher::new(cfg.rounds, &salt))),
        "pbkdf2" => Ok(Box::new(Pbkdf2Hasher::new(cfg.rounds, &salt))),
        _ => Err(CryptError::HasherNotFound(cfg.algorithm.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::generate_hasher_from_config;
    use super::HashConfig;
    #[test]
    fn bcrypt_algorithm() {
        let rounds = 10;
        let salt = base64::encode(&[10u8, 16]);
        let cfg = HashConfig {
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
        let salt = base64::encode(&[10u8, 16]);
        let cfg = HashConfig {
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
        let salt = base64::encode(&[10u8, 16]);
        let cfg = HashConfig {
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
        let salt = base64::encode(&[10u8, 16]);
        let cfg1 = HashConfig {
            rounds: rounds,
            salt: salt,
            algorithm: "bcrypt".to_string(),
        };
        let salt = base64::encode(&[10u8, 16]);
        let cfg2 = HashConfig {
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
