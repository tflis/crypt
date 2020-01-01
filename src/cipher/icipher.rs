use crate::error::CryptResult;
use rand::Rng;

pub fn generate_salt() -> Vec<u8> {
    rand::thread_rng().gen::<[u8; 32]>().to_vec()
}

pub trait ICipher {
    fn encrypt(&self, data: &str) -> CryptResult<Vec<u8>>;
    fn encrypt_with_salt(&self, data: &str, salt: &[u8]) -> CryptResult<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> CryptResult<String>;
    fn decrypt_with_salt(&self, data: &[u8], salt: &[u8]) -> CryptResult<String>;

    fn set_salt(&mut self, salt: &[u8]);
}
