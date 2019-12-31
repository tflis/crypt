extern crate base64;
extern crate crypto;
extern crate hex;

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
        let salt = [0u8; 16];
        let pass = "aaaaaakjhjhkgughlhk";
        let mut output = vec![0u8; 24];
        crypto::bcrypt::bcrypt(10, &salt, pass.as_bytes(), &mut output);

        assert_eq!("rKUp6LVuRNTVnC2rTniI//jtBsSvLlYm", base64::encode(&output));
    }

    #[test]
    fn crypto_bcrypt_verify() {
    }
}
