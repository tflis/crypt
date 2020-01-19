extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::{CipherConfig, CipherData, Config};
use crate::error::{CryptError, CryptResult};

#[derive(Serialize, Deserialize)]
struct Cfg {
    algorithm: String,
    secret: String,
}

#[derive(Serialize, Deserialize)]
struct Cipher {
    configurations: HashMap<String, Cfg>,
}

#[derive(Serialize, Deserialize)]
struct Ciphers {
    ciphers: HashMap<String, Cipher>,
}

#[allow(dead_code)]
type CipherLoader = fn(&mut Config, &str) -> CryptResult<()>;

#[allow(dead_code)]
pub fn get_cipher_loader(version: &str) -> CipherLoader {
    if version.starts_with("1.0") {
        cipher_loader_1_0
    } else {
        cipher_loader_unknown
    }
}

#[allow(dead_code)]
fn cipher_loader_unknown(_config: &mut Config, _data: &str) -> CryptResult<()> {
    Err(CryptError::UnsupportedConfigVersion())
}

#[allow(dead_code)]
fn cipher_loader_1_0(config: &mut Config, data: &str) -> CryptResult<()> {
    let ciphers: Ciphers = serde_json::from_str(data)?;

    for (field, cipher) in ciphers.ciphers {
        if !config.is_cipher_exist(&field) {
            config.insert_cipher(field.clone(), Box::new(CipherData::new()));
        }

        for (version, cfg) in cipher.configurations {
            if config.is_cipher_version_exist(&field, &version) {
                return Err(CryptError::DuplicationCipherConfigVersion(version));
            }

            is_algorithm_supported(&cfg.algorithm)?;

            let secret = base64::decode(&cfg.secret)?;

            config.add_cipher_version(
                &field,
                &version,
                Box::new(CipherConfig::new(cfg.algorithm, secret)),
            );
        }
    }

    Ok(())
}

fn is_algorithm_supported(algorithm: &str) -> CryptResult<()> {
    match algorithm {
        "aes_cbc" => Ok(()),
        "aes_cfb1" => Ok(()),
        "aes_ecb" => Ok(()),
        _ => Err(CryptError::UnsupportedCipherAlgorithm(
            algorithm.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use crate::config::get_config_version;
    use crate::config::Config;

    use super::get_cipher_loader;

    fn get_test_data_path(fname: &str) -> PathBuf {
        let mut path = PathBuf::from(file!());
        path.pop();
        path.pop();
        path.pop();
        path.pop();
        path.push("test_data");
        path.push(fname);
        path
    }

    #[test]
    fn load_configuration() {
        let mut config = Config::new();

        let path = get_test_data_path("config.json");
        let content = fs::read_to_string(path).unwrap();

        let version = get_config_version(&content).unwrap();
        let cipher_loader = get_cipher_loader(&version);

        cipher_loader(config.as_mut(), &content).unwrap();

        assert!(config.is_cipher_exist("email"));
        assert_eq!("2.1", config.get_cipher_latest_version("email"));
        assert!(config.is_cipher_version_exist("email", "1.0"));
        assert!(config.is_cipher_version_exist("email", "1.1"));
        assert!(config.is_cipher_version_exist("email", "2.1"));
    }
}
