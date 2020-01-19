extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};

use crate::error::CryptResult;

#[derive(Serialize, Deserialize)]
struct Version {
    //    #[serde(default, skip_serializing)]
    version: String,
}

#[allow(dead_code)]
pub fn get_config_version(json: &str) -> CryptResult<String> {
    let v: Version = serde_json::from_str(json)?;

    Ok(v.version)
}

#[cfg(test)]
mod tests {
    use super::get_config_version;
    #[test]
    fn version_valid() {
        let ver = "1.0.0";
        let json = r#"
        {
            "version": "1.0.0"
        }"#;

        let out = get_config_version(&json).unwrap();

        assert_eq!(ver, out);
    }

    #[test]
    fn allow_unknown_fields() {
        let ver = "1.0.0";
        let json = r#"
        {
            "version": "1.0.0",
            "unknown": "0.0.0"
        }"#;

        let out = get_config_version(&json).unwrap();

        assert_eq!(ver, out);
    }

    #[test]
    fn version_missing() {
        let json = r#"{}"#;

        let out = get_config_version(&json);

        assert!(
            out.is_err(),
            "Lack of version field in json should return error"
        )
    }
}
