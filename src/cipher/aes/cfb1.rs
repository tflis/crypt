extern crate openssl;

use openssl::symm::{decrypt, encrypt, Cipher};

use crate::cipher::{generate_salt, ICipher};
use crate::error::CryptResult;

pub struct CFB1Cipher {
    secret: Vec<u8>,
    salt: Vec<u8>,
    cipher: Cipher,
}

impl CFB1Cipher {
    #[allow(dead_code)]
    pub fn new(secret: &[u8], salt: &[u8]) -> CFB1Cipher {
        let mut secret = secret.to_vec();
        let mut salt = salt.to_vec();
        let cipher = match secret.len() {
            16 => Cipher::aes_128_cfb1(),
            24 => Cipher::aes_192_cfb1(),
            32 => Cipher::aes_256_cfb1(),
            _ => {
                println!("[crypt-config][WARNING] incorrect secret length. Expected 16, 24 or 32, got {}. Secret will be resized to 32 with value 0.", secret.len());
                secret.resize(32, 0);
                Cipher::aes_256_cfb1()
            }
        };

        if salt.is_empty() {
            salt = generate_salt();
        }

        salt.resize(16, 0);

        CFB1Cipher {
            secret: secret,
            salt: salt,
            cipher: cipher,
        }
    }
}

impl ICipher for CFB1Cipher {
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

    fn get_salt(&self) -> &Vec<u8> {
        &self.salt
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher::ICipher;
    use rand::Rng;

    #[test]
    fn cfb1_encrypt_decrypt_128() {
        let secret = rand::thread_rng().gen::<[u8; 16]>();
        let salt = rand::thread_rng().gen::<[u8; 16]>();

        let data = "this is a data that will be encrypted";

        let cipher = super::CFB1Cipher::new(&secret, &salt);
        let crypted_data = cipher.encrypt(data).unwrap();
        let uncrypted_data = cipher.decrypt(&crypted_data).unwrap();

        assert_eq!(data, uncrypted_data);
    }

    #[test]
    fn cfb1_encrypt_decrypt_192() {
        let secret = rand::thread_rng().gen::<[u8; 24]>();
        let salt = rand::thread_rng().gen::<[u8; 24]>();

        let data = "this is a data that will be encrypted";

        let cipher = super::CFB1Cipher::new(&secret, &salt);
        let crypted_data = cipher.encrypt(data).unwrap();
        let uncrypted_data = cipher.decrypt(&crypted_data).unwrap();

        assert_eq!(data, uncrypted_data);
    }

    #[test]
    fn cfb1_encrypt_decrypt_256() {
        let secret = rand::thread_rng().gen::<[u8; 32]>();
        let salt = rand::thread_rng().gen::<[u8; 32]>();

        let data = "this is a data that will be encrypted";

        let cipher = super::CFB1Cipher::new(&secret, &salt);
        let crypted_data = cipher.encrypt(data).unwrap();
        let uncrypted_data = cipher.decrypt(&crypted_data).unwrap();

        assert_eq!(data, uncrypted_data);
    }

    #[test]
    fn cfb1_encrypt_decrypt_other() {
        let secret = rand::thread_rng().gen::<[u8; 30]>();
        let salt = rand::thread_rng().gen::<[u8; 10]>();

        let data = "this is a data that will be encrypted";

        let cipher = super::CFB1Cipher::new(&secret, &salt);
        let crypted_data = cipher.encrypt(data).unwrap();
        let uncrypted_data = cipher.decrypt(&crypted_data).unwrap();

        assert_eq!(data, uncrypted_data);
    }
}
