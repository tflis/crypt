extern crate crypto;

use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;
use crypto::sha2::Sha256;

use crate::hasher::IHasher;

pub struct Pbkdf2Hasher {
    rounds: u32,
    salt: Vec<u8>,
}

impl IHasher for Pbkdf2Hasher {
    fn encrypt(&self, password: &str) -> Vec<u8> {
        let mut output = vec![0u8; 32];
        let mut mac = Hmac::new(Sha256::new(), password.as_bytes());

        pbkdf2(&mut mac, &self.salt, self.rounds, &mut output);

        output.to_vec()
    }

    fn verify(&self, encrypted: &[u8], password: &str) -> bool {
        let mut output = vec![0u8; 32];
        let mut mac = Hmac::new(Sha256::new(), password.as_bytes());

        pbkdf2(&mut mac, &self.salt, self.rounds, &mut output);

        output == encrypted
    }

    fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }
}

impl Pbkdf2Hasher {
    #[allow(dead_code)]
    pub fn new(rounds: u32, salt: &[u8]) -> Pbkdf2Hasher {
        Pbkdf2Hasher {
            rounds: rounds,
            salt: salt.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hasher::IHasher;

    #[test]
    fn encode_verify() {
        let rounds = 10;
        let salt = [10u8, 16];

        let password = "password";
        let password2 = "password2";

        let mut hasher = super::Pbkdf2Hasher::new(rounds, &salt);

        let hash = hasher.encrypt(password);

        assert!(hasher.verify(&hash, password));
        assert!(!hasher.verify(&hash, password2));

        let salt = [11u8, 16];
        hasher.set_salt(&salt);

        assert!(!hasher.verify(&hash, password));
    }
}
