extern crate base64;
extern crate crypto;
extern crate hex;

mod cipher;
mod config;
mod convert;
mod error;
mod hasher;

#[cfg(test)]
mod tests {
    #[test]
    fn encode_hex() {
        let hex_string = hex::encode("Hello world!");
        assert_eq!("48656c6c6f20776f726c6421", hex_string);
    }

    #[test]
    fn decode_hex() {
        let string = String::from_utf8(hex::decode("48656c6c6f20776f726c6421").unwrap()).unwrap();
        assert_eq!("Hello world!", string);
    }

    #[test]
    fn encode_base64() {
        let base64_string = base64::encode("Hello world");
        assert_eq!("SGVsbG8gd29ybGQ=", base64_string);
    }

    #[test]
    fn decode_base64() {
        let string = String::from_utf8(base64::decode("SGVsbG8gd29ybGQ=").unwrap()).unwrap();
        assert_eq!("Hello world", string);
    }

    #[test]
    fn crypto_bcrypt_encrypt() {
        let password = "very secured password";
        let salt = [0u8; 16];
        let rounds = 10;
        let mut output = vec![0u8; 32];

        crypto::bcrypt_pbkdf::bcrypt_pbkdf(password.as_bytes(), &salt, rounds, &mut output);

        assert_eq!(
            "7Dx4QJ551DqRoPToSNyMGn4yEGwSB1/kbC9MLygEZks=",
            base64::encode(&output)
        );
    }

    #[test]
    fn crypto_bcrypt_verify() {
        let hash = "7Dx4QJ551DqRoPToSNyMGn4yEGwSB1/kbC9MLygEZks=";
        let password = "very secured password";
        let salt = [0u8; 16];
        let rounds = 10;
        let mut output = vec![0u8; 32];

        crypto::bcrypt_pbkdf::bcrypt_pbkdf(password.as_bytes(), &salt, rounds, &mut output);

        assert_eq!(hash, base64::encode(&output));
    }

    #[test]
    fn crypto_pbkdf2_encrypt() {
        let password = "very secured password";
        let salt = [0u8; 16];
        let rounds = 10;
        let mut output = vec![0u8; 32];

        let mut mac = crypto::hmac::Hmac::new(crypto::sha2::Sha256::new(), password.as_bytes());
        crypto::pbkdf2::pbkdf2(&mut mac, &salt, rounds, &mut output);

        assert_eq!(
            "VcZDcja5mTzJ02mP5YBLDx88n7hVcFIuOCqj/qXBMkk=",
            base64::encode(&output)
        );
    }
}
