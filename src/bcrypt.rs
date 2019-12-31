extern crate crypto;

use crypto::bcrypt_pbkdf::bcrypt_pbkdf;

use crate::hash::IHasher;

pub struct BcryptHasher {
    rounds: u32,
    salt:   Vec<u8>,
}

impl BcryptHasher {
    #[warn(dead_code)]
    fn new(rounds: u32, salt: &[u8]) -> BcryptHasher {
        BcryptHasher { rounds: rounds, salt: salt.to_vec() }
    }
}

impl IHasher for BcryptHasher {
    fn encrypt(&self, password: &str) -> Vec<u8> {
        let mut output = vec![0u8; 32];
        bcrypt_pbkdf(password.as_bytes(), &self.salt, self.rounds, &mut output);

        output.to_vec()
    }

    fn verify(&self, encrypted: &[u8], password: &str) -> bool {
        let mut output = vec![0u8; 32];
        bcrypt_pbkdf(password.as_bytes(), &self.salt, self.rounds, &mut output);

        output == encrypted
    }

    fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::IHasher;

    #[test]
    fn encode_verify() {
        let rounds = 10;
        let salt = [10u8, 16];

        let password = "password";
        let password2 = "password2";

        let mut hasher = super::BcryptHasher::new(rounds, &salt);

        let hash = hasher.encrypt(password);

        assert!(hasher.verify(&hash, password));
        assert!(!hasher.verify(&hash, password2));

        let salt = [11u8, 16];
        hasher.set_salt(&salt);

        assert!(!hasher.verify(&hash, password));
    }
}
