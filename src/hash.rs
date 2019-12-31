pub trait IHasher {
    fn encrypt(&self, password: &str) -> Vec<u8>;
    fn verify(&self, encrypted: &[u8], password: &str) -> bool;
    fn set_salt(&mut self, salt: &[u8]);
}
