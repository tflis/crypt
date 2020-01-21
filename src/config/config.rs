extern crate notify;

use notify::{op, raw_watcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread;

use crate::cipher::ICipher;
use crate::config::{
    generate_cipher_from_config, generate_hasher_from_config, get_cipher_loader,
    get_config_version, get_hasher_loader, CipherConfig, CipherData, HasherConfig, HasherData,
};
use crate::error::CryptResult;
use crate::hasher::IHasher;

pub struct SyncedConfig {
    config: Arc<RwLock<Box<Config>>>,
}

pub struct Config {
    hashers: HashMap<String, Box<HasherData>>,
    ciphers: HashMap<String, Box<CipherData>>,
}

impl SyncedConfig {
    #[allow(dead_code)]
    pub fn new(path: PathBuf) -> Arc<SyncedConfig> {
        let config = Arc::new(RwLock::new(Box::new(Config::new())));

        let ret = Arc::new(SyncedConfig {
            config: config.clone(),
        });
        thread::spawn(move || crypt_config_watcher_and_loader(path, config));
        ret
    }

    pub fn get_config(&self) -> Arc<RwLock<Box<Config>>> {
        self.config.clone()
    }
}

impl Config {
    pub fn new() -> Config {
        Config {
            hashers: HashMap::new(),
            ciphers: HashMap::new(),
        }
    }

    pub fn new_from_path(path: &PathBuf) -> CryptResult<Box<Config>> {
        let content = fs::read_to_string(path)?;

        let version = get_config_version(&content)?;
        let hasher_loader = get_hasher_loader(&version);
        let cipher_loader = get_cipher_loader(&version);

        let mut config = Config::new();

        hasher_loader(&mut config, &content)?;
        cipher_loader(&mut config, &content)?;
        Ok(Box::new(config))
    }

    pub fn insert_cipher(&mut self, key: String, val: Box<CipherData>) {
        self.ciphers.insert(key, val);
    }

    pub fn insert_hasher(&mut self, key: String, val: Box<HasherData>) {
        self.hashers.insert(key, val);
    }

    pub fn is_cipher_exist(&self, field: &str) -> bool {
        self.ciphers.contains_key(field)
    }

    pub fn is_hasher_exist(&self, field: &str) -> bool {
        self.hashers.contains_key(field)
    }

    pub fn is_cipher_version_exist(&self, field: &str, version: &str) -> bool {
        self.ciphers[field].contains_configuration(version)
    }

    pub fn is_hasher_version_exist(&self, field: &str, version: &str) -> bool {
        self.hashers[field].contains_configuration(version)
    }

    pub fn add_cipher_version(&mut self, field: &str, version: &str, val: Box<CipherConfig>) {
        let cipher = self.ciphers.get_mut(field).unwrap();
        cipher.insert_configuration(version, val);
    }

    pub fn add_hasher_version(&mut self, field: &str, version: &str, val: Box<HasherConfig>) {
        let hasher = self.hashers.get_mut(field).unwrap();
        hasher.insert_configuration(version, val);
    }

    pub fn get_hasher_latest_version(&self, key: &str) -> &str {
        if let Some(hasher_data) = self.hashers.get(key) {
            hasher_data.get_latest_version()
        } else {
            "0"
        }
    }

    pub fn get_hasher(&self, version: &str, key: &str) -> Option<Box<dyn IHasher>> {
        if let Some(hasher_data) = self.hashers.get(key) {
            if let Some(hasher_config) = hasher_data.get_config(version) {
                match generate_hasher_from_config(&hasher_config) {
                    Ok(hasher) => Some(hasher),
                    Err(err) => {
                        println!(
                            "[crypt-config][ERROR] Error occured during generate hasher: {}",
                            err
                        );
                        None
                    }
                }
            } else {
                println!("[crypt-config][ERROR] Error occured during generate hasher: Hasher for given config not found.");
                None
            }
        } else {
            None
        }
    }

    pub fn get_cipher_latest_version(&self, key: &str) -> &str {
        if let Some(cipher_data) = self.ciphers.get(key) {
            cipher_data.get_latest_version()
        } else {
            "0"
        }
    }

    pub fn get_cipher(&self, version: &str, key: &str) -> Option<Box<dyn ICipher>> {
        if let Some(cipher_data) = self.ciphers.get(key) {
            if let Some(cipher_config) = cipher_data.get_config(version) {
                match generate_cipher_from_config(&cipher_config) {
                    Ok(cipher) => Some(cipher),
                    Err(err) => {
                        println!(
                            "[crypt-config][ERROR] Error occured during generate cipher: {}",
                            err
                        );
                        None
                    }
                }
            } else {
                println!("[crypt-config][ERROR] Error occured during generate cipher: Cipher for given config not found.");
                None
            }
        } else {
            None
        }
    }
}

fn crypt_config_watcher_and_loader(path: PathBuf, config: Arc<RwLock<Box<Config>>>) {
    load_new_configuration(&path, &config);

    loop {
        let (tx, rx) = mpsc::channel();
        if let Ok(mut watcher) = raw_watcher(tx) {
            if watcher.watch(&path, RecursiveMode::NonRecursive).is_ok() {
                loop {
                    match rx.recv() {
                        Ok(event) => match event.op {
                            Ok(operation) => {
                                let path = event.path.unwrap_or(path.clone());
                                if operation.contains(op::CREATE) {
                                    println!("[crypt-config][INFO] Create event on file {:?} was occured - loading new configuration", path);
                                    load_new_configuration(&path, &config);
                                } else if operation.contains(op::WRITE) {
                                    println!("[crypt-config][INFO] Write event on file {:?} was occured - loading new configuration", path);
                                    load_new_configuration(&path, &config);
                                } else if operation.contains(op::CLOSE_WRITE) {
                                    // Ignore close write - this is a followed event after write
                                } else {
                                    println!(
                                        "[crypt-config][INFO] {:?} event was occured on file {:?} - no action was taken",
                                        &event.op, &path
                                    );
                                    break;
                                }
                            }
                            Err(err) => {
                                println!("[crypt-config][WARNING] Event error occured: {}", err);
                            }
                        },
                        Err(e) => {
                            println!("watch error: {:?}", e);
                            break;
                        }
                    }
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn load_new_configuration(path: &PathBuf, config: &Arc<RwLock<Box<Config>>>) {
    match Config::new_from_path(path) {
        Ok(cfg) => {
            let mut c = config.write().unwrap();
            *c = cfg;
        }
        Err(err) => println!(
            "[crypt-config][ERROR] Error occured during parsing config file: {:?}",
            err
        ),
    };
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::PathBuf;
    use std::thread;
    use std::time;

    use crate::convert::{decrypt_document, encrypt_document};

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

    fn write_to_empty_file(fname: &str, content: &[u8]) {
        let path = get_test_data_path(fname);
        let mut file = File::create(path).unwrap();
        file.write_all(content).unwrap();
    }

    static EMPTY_CONFIG: &'static str = r#"{
    "version": "1.0.0",
    "ciphers": {},
    "hashers": {}
}"#;

    static EMAIL_HASHER: &'static str = r#"{
    "version": "1.0.0",
    "ciphers": {},
    "hashers": {
        "email": {
            "configurations": {
                "1.0": {
                    "algorithm": "bcrypt",
                    "rounds": 5,
                    "salt": "zj4aY4M8BQCfIxllyg6pTw=="
                }
            }
        }
    }
}"#;

    static EMAIL_CIPHER: &'static str = r#"{
    "version": "1.0.0",
    "ciphers": {
        "email": {
            "configurations": {
                "1.0": {
                    "algorithm": "aes_cbc",
                    "secret": "zj4aY4M8BQCfIxllyg6pTw=="
                }
            }
        }
    },
    "hashers": {}
}"#;

    #[test]
    fn empty_configuration() {
        let path = get_test_data_path("empty1.json");
        let config = super::SyncedConfig::new(path);

        let one_sec = time::Duration::from_secs(1);
        thread::sleep(one_sec);

        let json = r#"{"email":"johny.bravo@cn.com"}"#;

        let config = config.get_config();
        let encrypted_json = encrypt_document(&config, json).unwrap();

        assert_eq!(json, encrypted_json);
    }

    #[test]
    fn autoloaded_configuration() {
        let path = get_test_data_path("empty2.json");
        let config = super::SyncedConfig::new(path);

        let sec = time::Duration::from_secs(1);
        thread::sleep(sec);

        write_to_empty_file("empty2.json", EMAIL_HASHER.as_bytes());

        thread::sleep(sec);
        thread::sleep(sec);

        let json = r#"{"email":"johny.bravo@cn.com"}"#;

        let config = config.get_config();
        let encrypted_json = encrypt_document(&config, json).unwrap();
        let decrypted_json = decrypt_document(&config, &encrypted_json).unwrap();

        assert_ne!(json, encrypted_json);
        assert_eq!(encrypted_json, decrypted_json);

        write_to_empty_file("empty2.json", EMPTY_CONFIG.as_bytes());
    }

    #[test]
    fn autoloaded_cipher_configuration() {
        let path = get_test_data_path("empty3.json");
        let config = super::SyncedConfig::new(path);

        let sec = time::Duration::from_secs(1);
        thread::sleep(sec);

        let json = r#"{"email":"johny.bravo@cn.com"}"#;

        let config = config.get_config();
        let encrypted_json = encrypt_document(&config, json).unwrap();
        assert_eq!(json, encrypted_json);

        write_to_empty_file("empty3.json", EMAIL_CIPHER.as_bytes());

        thread::sleep(sec);
        thread::sleep(sec);

        let encrypted_json = encrypt_document(&config, json).unwrap();
        let decrypted_json = decrypt_document(&config, &encrypted_json).unwrap();

        assert_ne!(json, encrypted_json);
        assert_eq!(json, decrypted_json);

        write_to_empty_file("empty3.json", EMPTY_CONFIG.as_bytes());
    }
}
