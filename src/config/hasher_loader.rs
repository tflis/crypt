extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::{Config, HasherConfig, HasherData};
use crate::error::{CryptError, CryptResult};

#[derive(Serialize, Deserialize)]
struct Cfg {
  algorithm: String,
  rounds:    u32,
  salt:      String
}

#[derive(Serialize, Deserialize)]
struct Hasher {
  configurations: HashMap<String, Cfg>
}

#[derive(Serialize, Deserialize)]
struct Hashers {
  hashers: HashMap<String, Hasher>
}

#[allow(dead_code)]
type HasherLoader = fn(&mut Config, &str) -> CryptResult<()>;

#[allow(dead_code)]
pub fn get_hasher_loader(version: &str) -> HasherLoader {
  if version.starts_with("1.0") {
    hasher_loader_1_0
  } else {
    hasher_loader_unknown
  }
}

#[allow(dead_code)]
fn hasher_loader_unknown(_config: &mut Config, _data: &str) -> CryptResult<()> {
  Err(CryptError::UnsupportedConfigVersion())
}

#[allow(dead_code)]
fn hasher_loader_1_0(config: &mut Config, data: &str) -> CryptResult<()> {
  let hashers: Hashers = serde_json::from_str(data)?;

  for (field, hasher) in hashers.hashers {
    if !config.is_hasher_exist(&field) {
      config.insert_hasher(field.clone(), Box::new(HasherData::new()));
    }

    for (version, cfg) in hasher.configurations {
      if config.is_hasher_version_exist(&field, &version) {
        return Err(CryptError::DuplicationHasherConfigVersion(version));
      }

      if cfg.rounds <= 0 {
        return Err(CryptError::BadIterationCount());
      }

      is_algorithm_supported(&cfg.algorithm)?;

      let salt = base64::decode(&cfg.salt)?;

      config.add_hasher_version(&field, &version, Box::new(HasherConfig::new(cfg.algorithm, cfg.rounds, salt)));
    }
  }

  Ok(())
}

fn is_algorithm_supported(algorithm: &str) -> CryptResult<()> {
  match algorithm {
    "bcrypt" => Ok(()),
    "pbkdf2" => Ok(()),
    _ => Err(CryptError::UnsupportedHasherAlgorithm(algorithm.to_string()))
  }
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::path::PathBuf;

  use crate::config::get_config_version;
  use crate::config::Config;

  use super::get_hasher_loader;

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
    let hasher_loader = get_hasher_loader(&version);

    hasher_loader(&mut config, &content).unwrap();

    assert!(config.is_hasher_exist("email"));
    assert_eq!("2.0", config.get_hasher_latest_version("email"));
    assert!(config.is_hasher_version_exist("email", "1.0"));
    assert!(config.is_hasher_version_exist("email", "2.0"));
  }
}
