extern crate openssl;

use openssl::symm::{decrypt, encrypt, Cipher};

use crate::cipher::{generate_salt, ICipher};
use crate::error::CryptResult;

pub struct CBCCipher {
    secret: Vec<u8>,
    salt: Vec<u8>,
    cipher: Cipher,
}

impl CBCCipher {
    #[allow(dead_code)]
    fn new(secret: &[u8], salt: &[u8]) -> CBCCipher {
        let mut secret = secret.to_vec();
        let mut salt = salt.to_vec();
        let cipher = match secret.len() {
            16 => Cipher::aes_128_cbc(),
            24 => Cipher::aes_192_cbc(),
            32 => Cipher::aes_256_cbc(),
            _ => {
                println!("[WARNING] incorrect secret length. Expected 16, 24 or 32, got {}. Secret will be resized to 32 with value 0.", secret.len());
                secret.resize(32, 0);
                Cipher::aes_256_cbc()
            }
        };

        if salt.is_empty() {
            salt = generate_salt();
        }

        salt.resize(secret.len(), 0);

        CBCCipher {
            secret: secret,
            salt: salt,
            cipher: cipher,
        }
    }
}

impl ICipher for CBCCipher {
    fn encrypt(&self, data: &str) -> CryptResult<Vec<u8>> {
        Ok(encrypt(
            self.cipher,
            &self.secret,
            Some(&self.salt),
            data.as_bytes(),
        )?)
    }

    fn encrypt_with_salt(&self, data: &str, salt: &[u8]) -> CryptResult<Vec<u8>> {
        Ok(encrypt(
            self.cipher,
            &self.secret,
            Some(salt),
            data.as_bytes(),
        )?)
    }

    fn decrypt(&self, data: &[u8]) -> CryptResult<String> {
        let plain = decrypt(self.cipher, &self.secret, Some(&self.salt), data)?;
        Ok(String::from_utf8(plain)?)
    }

    fn decrypt_with_salt(&self, data: &[u8], salt: &[u8]) -> CryptResult<String> {
        let plain = decrypt(self.cipher, &self.secret, Some(salt), data)?;
        Ok(String::from_utf8(plain)?)
    }

    fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }
}
