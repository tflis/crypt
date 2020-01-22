use std::str::FromStr;
use std::sync::{Arc, RwLock};

use serde_json::{json, Map, Number, Value};

use crate::config::Config;
use crate::error::{CryptError, CryptResult};

pub fn encrypt_document(config: &Arc<RwLock<Box<Config>>>, json: &str) -> CryptResult<String> {
  let config = config.read().unwrap();
  let v: Value = serde_json::from_str(json)?;

  if let Value::Object(obj) = v {
    let v = encrypt_object(&config, "", obj);
    Ok(serde_json::to_string(&v)?)
  } else {
    Err(CryptError::InvalidDocument("Document is not a json object".to_string()))
  }
}

pub fn decrypt_document(config: &Arc<RwLock<Box<Config>>>, json: &str) -> CryptResult<String> {
  let config = config.read().unwrap();
  let v: Value = serde_json::from_str(json)?;

  if let Value::Object(obj) = v {
    let v = decrypt_element(&config, "", obj)?;
    Ok(serde_json::to_string(&v)?)
  } else {
    Err(CryptError::InvalidDocument("Document is not a json object".to_string()))
  }
}

pub fn modify_find_query(config: &Arc<RwLock<Box<Config>>>, query: &str) -> CryptResult<String> {
  let config = config.read().unwrap();
  let v: Value = serde_json::from_str(query)?;

  if let Value::Object(obj) = v {
    let v = modify_find_element(&config, obj)?;
    Ok(serde_json::to_string(&v)?)
  } else {
    Err(CryptError::InvalidDocument("Query is not a json object".to_string()))
  }
}

fn encrypt_object<'a>(config: &'a Config, start_point: &'a str, obj: Map<String, Value>) -> Value {
  let mut map = Map::new();
  let all_elements = join(start_point, "*");
  let hasher_version = config.get_hasher_latest_version(&all_elements);
  if let Some(hasher) = config.get_hasher(hasher_version, &all_elements) {
    let object = Value::Object(obj.clone());
    let object_serialized = serde_json::to_string(&object).unwrap();
    let hash = hasher.encrypt(&object_serialized);
    map.insert("hashed_field".to_string(), hash_value(hasher_version, &hash));
  }

  let cipher_version = config.get_cipher_latest_version(&all_elements);
  if let Some(cipher) = config.get_cipher(cipher_version, &all_elements) {
    let object = Value::Object(obj.clone());
    let object_serialized = serde_json::to_string(&object).unwrap();
    match cipher.encrypt(&object_serialized) {
      Ok(data) => map.insert("crypted_field".to_string(), crypt_value(cipher_version, cipher.get_salt(), &data)),
      Err(err) => {
        println!("[crypt-config][ERROR] Error occured during crypting {} value: {}", all_elements, err);
        None
      }
    };
  }

  if !map.is_empty() {
    map.insert("type".to_string(), json!("object"));
    Value::Object(map)
  } else {
    let mut out = Map::new();
    for (k, v) in obj {
      let key = join(start_point, k.as_str());
      match v {
        Value::Null => out.insert(key, Value::Null),
        Value::Bool(val) => out.insert(k, encrypt_bool(config, &key, val)),
        Value::Number(val) => out.insert(k, encrypt_number(config, &key, val)),
        Value::String(val) => out.insert(k, encrypt_string(config, &key, val)),
        Value::Array(arr) => out.insert(k, encrypt_array(config, &key, arr)),
        Value::Object(map) => out.insert(k, encrypt_object(config, &key, map))
      };
    }

    Value::Object(out)
  }
}

fn encrypt_bool<'a>(config: &'a Config, key: &'a str, obj: bool) -> Value {
  let mut map = Map::new();
  let hasher_version = config.get_hasher_latest_version(key);
  if let Some(hash) = hash_string(&config, hasher_version, key, &obj.to_string()) {
    map.insert("hashed_field".to_string(), hash);
  }

  let cipher_version = config.get_cipher_latest_version(key);
  if let Some(cipher) = config.get_cipher(cipher_version, key) {
    let resp = if obj { cipher.encrypt("true") } else { cipher.encrypt("false") };

    match resp {
      Ok(data) => map.insert("crypted_field".to_string(), crypt_value(cipher_version, cipher.get_salt(), &data)),
      Err(err) => {
        println!("[crypt-config][ERROR] Error occured during crypting {} value: {}", key, err);
        None
      }
    };
  }

  if !map.is_empty() {
    map.insert("type".to_string(), json!("bool"));
    Value::Object(map)
  } else {
    Value::Bool(obj)
  }
}

fn encrypt_number<'a>(config: &'a Config, key: &'a str, obj: Number) -> Value {
  let mut map = Map::new();
  let val = obj.as_f64().unwrap().to_string();
  let hasher_version = config.get_hasher_latest_version(key);
  if let Some(hash) = hash_string(&config, hasher_version, key, &val) {
    map.insert("hashed_field".to_string(), hash);
  }

  let cipher_version = config.get_cipher_latest_version(key);
  if let Some(cipher) = config.get_cipher(cipher_version, key) {
    match cipher.encrypt(&val) {
      Ok(data) => map.insert("crypted_field".to_string(), crypt_value(cipher_version, cipher.get_salt(), &data)),
      Err(err) => {
        println!("[crypt-config][ERROR] Error occured during crypting {} value: {}", key, err);
        None
      }
    };
  }

  if !map.is_empty() {
    map.insert("type".to_string(), json!("number"));
    Value::Object(map)
  } else {
    Value::Number(obj)
  }
}

fn encrypt_string<'a>(config: &'a Config, key: &'a str, obj: String) -> Value {
  let mut map = Map::new();
  let hasher_version = config.get_hasher_latest_version(key);
  if let Some(hash) = hash_string(&config, hasher_version, key, &obj) {
    map.insert("hashed_field".to_string(), hash);
  }

  let cipher_version = config.get_cipher_latest_version(key);
  if let Some(cipher) = config.get_cipher(cipher_version, key) {
    match cipher.encrypt(&obj) {
      Ok(data) => map.insert("crypted_field".to_string(), crypt_value(cipher_version, cipher.get_salt(), &data)),
      Err(err) => {
        println!("[crypt-config][ERROR] Error occured during crypting {} value: {}", key, err);
        None
      }
    };
  }

  if !map.is_empty() {
    map.insert("type".to_string(), json!("string"));
    Value::Object(map)
  } else {
    Value::String(obj)
  }
}

fn hash_string<'a>(config: &'a Config, version: &'a str, key: &'a str, obj: &str) -> Option<Value> {
  if let Some(hasher) = config.get_hasher(version, key) {
    let hash = hasher.encrypt(&obj);
    Some(hash_value(version, &hash))
  } else {
    None
  }
}

fn encrypt_array<'a>(config: &'a Config, key: &'a str, arr: Vec<Value>) -> Value {
  let mut map = Map::new();
  let all_elements = join(key, "*");
  let hasher_version = config.get_hasher_latest_version(&all_elements);
  if let Some(hasher) = config.get_hasher(hasher_version, &all_elements) {
    let array = Value::Array(arr.clone());
    let arr_serialized = serde_json::to_string(&array).unwrap();
    let hash = hasher.encrypt(&arr_serialized);
    map.insert("hashed_field".to_string(), hash_value(hasher_version, &hash));
  }

  let cipher_version = config.get_cipher_latest_version(&all_elements);
  if let Some(cipher) = config.get_cipher(cipher_version, &all_elements) {
    let array = Value::Array(arr.clone());
    let arr_serialized = serde_json::to_string(&array).unwrap();
    match cipher.encrypt(&arr_serialized) {
      Ok(data) => map.insert("crypted_field".to_string(), crypt_value(cipher_version, cipher.get_salt(), &data)),
      Err(err) => {
        println!("[crypt-config][ERROR] Error occured during crypting {} value: {}", key, err);
        None
      }
    };
  }

  if !map.is_empty() {
    map.insert("type".to_string(), json!("array"));
    Value::Object(map)
  } else {
    let mut out = Vec::new();
    for v in arr {
      match v {
        Value::Null => out.push(Value::Null),
        Value::Bool(val) => out.push(encrypt_bool(config, &key, val)),
        Value::Number(val) => out.push(encrypt_number(config, &key, val)),
        Value::String(val) => out.push(encrypt_string(config, &key, val)),
        Value::Array(arr) => out.push(encrypt_array(config, &key, arr)),
        Value::Object(map) => out.push(encrypt_object(config, &key, map))
      };
    }

    Value::Array(out)
  }
}

fn decrypt_element<'a>(config: &'a Config, key: &'a str, obj: Map<String, Value>) -> CryptResult<Value> {
  if is_crypted(&obj) {
    if let Some(value) = obj.get("type") {
      if let Some(obj) = obj.get("crypted_field") {
        if let Value::Object(obj) = obj {
          if let Value::String(value_type) = value {
            match value_type.as_str() {
              "bool" => decrypt_bool(config, &key, obj),
              "number" => decrypt_number(config, &key, obj),
              "string" => decrypt_string(config, &key, obj),
              "array" => decrypt_array(config, &key, obj),
              "object" => decrypt_object(config, &key, obj),
              _ => {
                let message = format!("Invalid value of `{}.type`, got `{}`, expected one of: `bool`, `number`, `string`, `array`, `object`", key, value_type);
                println!("[crypt-config][ERROR] {}", message);
                Err(CryptError::InvalidDocument(message))
              }
            }
          } else {
            let message = format!("`{}.type` must be string type", key);
            println!("[crypt-config][ERROR] {}", message);
            Err(CryptError::InvalidDocument(message))
          }
        } else {
          let message = format!("`{}.crypted_fiels` must be object type", key);
          println!("[crypt-config][ERROR] {}", message);
          Err(CryptError::InvalidDocument(message))
        }
      } else {
        let message = format!("Invalid crypted field `{}`, lack of `crypted_field` object", key);
        println!("[crypt-config][ERROR] {}", message);
        Err(CryptError::InvalidDocument(message))
      }
    } else {
      let message = format!("Invalid crypted field `{}`, lack of `type` information", key);
      println!("[crypt-config][ERROR] {}", message);
      Err(CryptError::InvalidDocument(message))
    }
  } else {
    let mut out = Map::new();
    for (k, v) in obj {
      let key = join(key, k.as_str());
      match v {
        Value::Null => out.insert(key, Value::Null),
        Value::Bool(val) => out.insert(k, Value::Bool(val)),
        Value::Number(val) => out.insert(k, Value::Number(val)),
        Value::String(val) => out.insert(k, Value::String(val)),
        Value::Array(arr) => match decrypt_array_elements(config, &key, arr) {
          Ok(val) => out.insert(k, val),
          Err(err) => return Err(err)
        },
        Value::Object(map) => match decrypt_element(config, &key, map) {
          Ok(val) => out.insert(k, val),
          Err(err) => return Err(err)
        }
      };
    }

    Ok(Value::Object(out))
  }
}

fn decrypt_array_elements<'a>(config: &'a Config, key: &'a str, arr: Vec<Value>) -> CryptResult<Value> {
  let mut out = Vec::new();
  for v in arr {
    match v {
      Value::Null => out.push(Value::Null),
      Value::Bool(val) => out.push(Value::Bool(val)),
      Value::Number(val) => out.push(Value::Number(val)),
      Value::String(val) => out.push(Value::String(val)),
      Value::Array(arr) => match decrypt_array_elements(config, &key, arr) {
        Ok(val) => out.push(val),
        Err(err) => return Err(err)
      },
      Value::Object(map) => match decrypt_element(config, &key, map) {
        Ok(val) => out.push(val),
        Err(err) => return Err(err)
      }
    };
  }

  Ok(Value::Array(out))
}

fn decrypt_bool<'a>(config: &'a Config, key: &'a str, obj: &Map<String, Value>) -> CryptResult<Value> {
  let string = get_value(config, key, obj)?;
  match bool::from_str(&string) {
    Ok(boolean) => Ok(Value::Bool(boolean)),
    Err(_) => {
      let message = format!("Field `{}` is not a boolean type", key);
      println!("[crypt-config][ERROR] {}, the decrypted value is `{}`", message, string);
      Err(CryptError::InvalidDocument(message))
    }
  }
}

fn decrypt_number<'a>(config: &'a Config, key: &'a str, obj: &Map<String, Value>) -> CryptResult<Value> {
  let string = get_value(config, key, obj)?;
  if let Ok(number) = string.parse::<u64>() {
    Ok(Value::Number(Number::from(number)))
  } else if let Ok(number) = string.parse::<i64>() {
    Ok(Value::Number(Number::from(number)))
  } else if let Ok(number) = string.parse::<f64>() {
    Ok(Value::Number(Number::from_f64(number).unwrap()))
  } else {
    let message = format!("Field `{}` is not a number type", key);
    println!("[crypt-config][ERROR] {}, the decrypted value is `{}`", message, string);
    Err(CryptError::InvalidDocument(message))
  }
}

fn decrypt_string<'a>(config: &'a Config, key: &'a str, obj: &Map<String, Value>) -> CryptResult<Value> {
  let string = get_value(config, key, obj)?;
  Ok(Value::String(string))
}

fn decrypt_array<'a>(config: &'a Config, key: &'a str, obj: &Map<String, Value>) -> CryptResult<Value> {
  let key = join(key, "*");
  let string = get_value(config, &key, obj)?;
  match serde_json::from_str(&string) {
    Ok(value) => Ok(value),
    Err(err) => {
      let message = format!("Error occured during deserializing `{}`: {}", key, err);
      println!("[crypt-config][ERROR] {}", message);
      Err(CryptError::InvalidDocument(message))
    }
  }
}

fn decrypt_object<'a>(config: &'a Config, key: &'a str, obj: &Map<String, Value>) -> CryptResult<Value> {
  let key = join(key, "*");
  let string = get_value(config, &key, obj)?;
  match serde_json::from_str(&string) {
    Ok(value) => Ok(value),
    Err(err) => {
      let message = format!("Error occured during deserializing `{}`: {}", key, err);
      println!("[crypt-config][ERROR] {}", message);
      Err(CryptError::InvalidDocument(message))
    }
  }
}

fn hash_value(hasher_version: &str, data: &[u8]) -> Value {
  let mut map = Map::new();

  map.insert("data".to_string(), hash_data(data));
  map.insert("version".to_string(), Value::String(hasher_version.to_string()));

  Value::Object(map)
}

fn hash_data(data: &[u8]) -> Value {
  Value::String(base64::encode(&data))
}

fn crypt_value(cipher_version: &str, salt: &[u8], data: &[u8]) -> Value {
  let mut map = Map::new();

  map.insert("data".to_string(), Value::String(base64::encode(&data)));
  map.insert("salt".to_string(), Value::String(base64::encode(&salt)));
  map.insert("version".to_string(), Value::String(cipher_version.to_string()));

  Value::Object(map)
}

fn get_value<'a>(config: &'a Config, key: &'a str, obj: &Map<String, Value>) -> CryptResult<String> {
  if let Some((data, salt, version)) = get_data_salt_version(obj) {
    if let Some(cipher) = config.get_cipher(&version, key) {
      match cipher.decrypt_with_salt(&data, &salt) {
        Ok(string) => Ok(string),
        Err(err) => {
          println!("[crypt-config][ERROR] Unable to decrypt `{}`, error occured: {}", key, err);
          Err(err)
        }
      }
    } else {
      let message = format!("Unable to find cipher of field `{}` with version: {}", key, version);
      println!("[crypt-config][ERROR] {}", message);
      Err(CryptError::CipherNotFound(message))
    }
  } else {
    let message = format!("Invalid format of crypted_field for field `{}`, expected: `data`, `salt` and `version`", key);
    println!("[crypt-config][ERROR] {}", message);
    Err(CryptError::InvalidDocument(message))
  }
}

fn get_data_salt_version(obj: &Map<String, Value>) -> Option<(Vec<u8>, Vec<u8>, &String)> {
  let data = obj.get("data").and_then(|data| if let Value::String(string) = data { base64::decode(string).ok() } else { None });
  let salt = obj.get("salt").and_then(|salt| if let Value::String(string) = salt { base64::decode(string).ok() } else { None });
  let version = obj.get("version").and_then(|version| if let Value::String(string) = version { Some(string) } else { None });
  if data.is_some() && salt.is_some() && version.is_some() {
    Some((data.unwrap(), salt.unwrap(), version.unwrap()))
  } else {
    None
  }
}

fn is_crypted(obj: &Map<String, Value>) -> bool {
  obj.contains_key("crypted_field") && obj.contains_key("type")
}

fn join<'a>(a: &'a str, b: &'a str) -> String {
  if a.is_empty() {
    b.to_string()
  } else {
    String::from(a) + "." + &String::from(b)
  }
}

fn modify_find_element(config: &Config, obj: Map<String, Value>) -> CryptResult<Value> {
  let mut out = Map::new();
  for (key, val) in obj {
    if config.is_hasher_exist(&key) {
      let hashed_key = key.clone() + ".hashed_field.data";
      let versions = config.get_all_hasher_versions(&key);
      if versions.is_empty() {
        out.insert(key, val);
      } else {
        match val {
          Value::Null => out.insert(hashed_key, Value::Null),
          Value::Bool(val) => out.insert(hashed_key, hash_all_versions(&config, &versions, &key, val.to_string(), "$in")),
          Value::Number(val) => {
            let val = val.as_f64().unwrap().to_string();
            out.insert(hashed_key, hash_all_versions(&config, &versions, &key, val, "$in"))
          }
          Value::String(val) => out.insert(hashed_key, hash_all_versions(&config, &versions, &key, val, "$in")),
          Value::Array(arr) => out.insert(hashed_key, Value::Array(arr)),
          Value::Object(map) => match hash_operation(config, &versions, &key, map) {
            Ok(val) => out.insert(hashed_key, val),
            Err(err) => return Err(err)
          }
        };
      }
    } else {
      if let Value::Object(obj) = val {
        let res = modify_find_element(config, obj);
        if let Ok(val) = res {
          out.insert(key.clone(), val);
        } else {
          return res;
        }
      } else {
        out.insert(key.clone(), val);
      }
    }
  }

  Ok(Value::Object(out))
}

fn hash_all_versions(config: &Config, versions: &Vec<&String>, key: &str, string: String, op: &str) -> Value {
  if versions.len() == 1 {
    let ver = versions.get(0).unwrap().as_str();
    let hasher = config.get_hasher(ver, key).unwrap();
    let hash = hasher.encrypt(&string);
    hash_data(&hash)
  } else {
    let vec = versions
      .iter()
      .map(|ver| {
        let hasher = config.get_hasher(ver, key).unwrap();
        let hash = hasher.encrypt(&string);
        hash_data(&hash)
      })
      .collect();

    let mut obj = Map::new();
    obj.insert(op.to_string(), Value::Array(vec));
    Value::Object(obj)
  }
}

fn hash_operation(cfg: &Config, vers: &Vec<&String>, key: &String, obj: Map<String, Value>) -> CryptResult<Value> {
  let mut out = Map::new();
  for (op, val) in obj {
    match op.as_str() {
      "$eq" => match val {
        Value::Null => {
          out.insert(op.clone(), Value::Null);
        }
        Value::Bool(val) => {
          let val = hash_all_versions(&cfg, &vers, &key, val.to_string(), "$in");
          match val {
            Value::Object(map) => {
              out.extend(map.into_iter());
            }
            _ => {
              out.insert(op.clone(), val);
            }
          };
        }
        Value::Number(val) => {
          let val = val.as_f64().unwrap().to_string();
          let val = hash_all_versions(&cfg, &vers, &key, val, "$in");
          match val {
            Value::Object(map) => {
              out.extend(map.into_iter());
            }
            _ => {
              out.insert(op.clone(), val);
            }
          };
        }
        Value::String(val) => {
          let val = hash_all_versions(&cfg, &vers, &key, val, "$in");
          match val {
            Value::Object(map) => {
              out.extend(map.into_iter());
            }
            _ => {
              out.insert(op.clone(), val);
            }
          };
        }
        _ => {
          out.insert(op.clone(), val);
        }
      },
      "$ne" => match val {
        Value::Null => {
          out.insert(op.clone(), Value::Null);
        }
        Value::Bool(val) => {
          let val = hash_all_versions(&cfg, &vers, &key, val.to_string(), "$nin");
          match val {
            Value::Object(map) => {
              out.extend(map.into_iter());
            }
            _ => {
              out.insert(op.clone(), val);
            }
          };
        }
        Value::Number(val) => {
          let val = val.as_f64().unwrap().to_string();
          let val = hash_all_versions(&cfg, &vers, &key, val, "$nin");
          match val {
            Value::Object(map) => {
              out.extend(map.into_iter());
            }
            _ => {
              out.insert(op.clone(), val);
            }
          };
        }
        Value::String(val) => {
          let val = hash_all_versions(&cfg, &vers, &key, val, "$nin");
          match val {
            Value::Object(map) => {
              out.extend(map.into_iter());
            }
            _ => {
              out.insert(op.clone(), val);
            }
          };
        }
        _ => {
          out.insert(op.clone(), val);
        }
      },
      "$in" | "$nin" => match val {
        Value::Array(arr) => {
          let mut out_arr = Vec::new();
          for val in arr {
            let hashed_val = match val {
              Value::Null => Value::Null,
              Value::Bool(val) => hash_all_versions(&cfg, &vers, &key, val.to_string(), "op"),
              Value::Number(val) => {
                let val = val.as_f64().unwrap().to_string();
                hash_all_versions(&cfg, &vers, &key, val, "op")
              }
              Value::String(val) => hash_all_versions(&cfg, &vers, &key, val, "op"),
              _ => val
            };
            match hashed_val {
              Value::Object(map) => {
                if let Value::Array(arr) = map.get("op").unwrap() {
                  out_arr.extend_from_slice(arr);
                }
              }
              _ => out_arr.push(hashed_val)
            };
          }
          out.insert(op.clone(), Value::Array(out_arr));
        }
        _ => return Err(CryptError::InvalidQuery(format!("`$in` operation requires object as a value")))
      },
      "$not" => match val {
        Value::Object(obj) => match hash_operation(cfg, vers, &key, obj) {
          Ok(val) => {
            out.insert(op.clone(), val);
          }
          Err(err) => return Err(err)
        },
        _ => return Err(CryptError::InvalidQuery(format!("`$not` operation requires object as a value")))
      },
      _ => return Err(CryptError::OperationNotImplemented(key.clone()))
    };
  }
  Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, RwLock};

  use crate::config::Config;
  use crate::config::{CipherConfig, CipherData, HasherConfig, HasherData};

  static JSON: &'static str = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":25,"email":"jonny.bravo@cn.com","empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

  #[test]
  fn hash_single_array_field() {
    let mut config = Config::new();
    let salt = [15u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 7, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("1", hash_config);
    config.insert_hasher("series.*".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":25,"email":"jonny.bravo@cn.com","empty":null,"name":"John","series":{"hashed_field":{"data":"giAS02dOap4MHEx9m5Cl0xIdL37f/QobI29TDyBN0JY=","version":"1"},"type":"array"},"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);
  }

  #[test]
  fn hash_single_bool_field() {
    let mut config = Config::new();
    let salt = [12u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 10, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("1", hash_config);
    config.insert_hasher("active".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":{"hashed_field":{"data":"IkG35GNCWPPOnXYFLQ64zTNIwBadyLvlHi1JWvAXlfU=","version":"1"},"type":"bool"},"address":{"city":"New York","country":"USA"},"age":25,"email":"jonny.bravo@cn.com","empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);
  }

  #[test]
  fn hash_single_number_field() {
    let mut config = Config::new();
    let salt = [15u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 5, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("2", hash_config);
    config.insert_hasher("age".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":{"hashed_field":{"data":"/6TDu9lIIcx5ux5K1Zyo40K2MsYJ+gZe2LU0HZVp3jA=","version":"2"},"type":"number"},"email":"jonny.bravo@cn.com","empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);
  }

  #[test]
  fn hash_single_string_field() {
    let mut config = Config::new();
    let salt = [10u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 10, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("1", hash_config);
    config.insert_hasher("email".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":25,"email":{"hashed_field":{"data":"zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE=","version":"1"},"type":"string"},"empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);
  }

  #[test]
  fn hash_single_object_field() {
    let mut config = Config::new();
    let salt = [14u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 8, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("5", hash_config);
    config.insert_hasher("address.*".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"hashed_field":{"data":"8Gur9ZcF3bgukZQP3mtvQEst0uTG2D50VqlMOyOHTPM=","version":"5"},"type":"object"},"age":25,"email":"jonny.bravo@cn.com","empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);
  }

  #[test]
  fn hash_two_fields() {
    let mut config = Config::new();

    let salt = [18u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 9, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("1", hash_config);
    config.insert_hasher("email".to_string(), hasher);

    let salt = [16u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 8, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("1", hash_config);
    config.insert_hasher("address.*".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"hashed_field":{"data":"WBlBT6nFvqWJ+1bxbtPAX+H0K/FMAq3FfC9kaZq/CIg=","version":"1"},"type":"object"},"age":25,"email":{"hashed_field":{"data":"rCknP8kn627oZ96uTiR7d+hZTyS8QZImUazpF8ryIxs=","version":"1"},"type":"string"},"empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);
  }

  #[test]
  fn crypt_single_array_field() {
    let mut config = Config::new();
    let secret = [19u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_cbc".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("1", cipher_config);
    config.insert_cipher("series.*".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn crypt_single_bool_field() {
    let mut config = Config::new();
    let secret = [21u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_cfb1".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("4", cipher_config);
    config.insert_cipher("active".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn crypt_single_number_field() {
    let mut config = Config::new();
    let secret = [22u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_ecb".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("3", cipher_config);
    config.insert_cipher("age".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn crypt_single_string_field() {
    let mut config = Config::new();
    let secret = [22u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_ecb".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("2", cipher_config);
    config.insert_cipher("email".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn crypt_single_object_field() {
    let mut config = Config::new();
    let secret = [22u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_ecb".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("2", cipher_config);
    config.insert_cipher("address.*".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn crypt_two_fields() {
    let mut config = Config::new();

    let secret = [22u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_ecb".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("2", cipher_config);
    config.insert_cipher("address.*".to_string(), cipher);

    let secret = [23u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_cbc".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("7", cipher_config);
    config.insert_cipher("email".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn crypt_and_hash_same_field() {
    let mut config = Config::new();

    let secret = [22u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_ecb".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("2", cipher_config);
    config.insert_cipher("address.*".to_string(), cipher);

    let salt = [24u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 8, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("4", hash_config);
    config.insert_hasher("address.*".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn crypt_and_hash_other_fields() {
    let mut config = Config::new();

    let secret = [23u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_cbc".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("2", cipher_config);
    config.insert_cipher("address.*".to_string(), cipher);

    let salt = [25u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 8, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("4", hash_config);
    config.insert_hasher("email".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();

    assert_ne!(JSON, encrypted_json);
  }

  #[test]
  fn encrypt_decrypt_single_array_field() {
    let mut config = Config::new();
    let secret = [28u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_cfb1".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("5", cipher_config);
    config.insert_cipher("series.*".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let decrypted_json = super::decrypt_document(&config, &encrypted_json).unwrap();

    assert_eq!(JSON, decrypted_json);
  }

  #[test]
  fn encrypt_decrypt_single_bool_field() {
    let mut config = Config::new();
    let secret = [21u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_cfb1".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("4", cipher_config);
    config.insert_cipher("active".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let decrypted_json = super::decrypt_document(&config, &encrypted_json).unwrap();

    assert_eq!(JSON, decrypted_json);
  }

  #[test]
  fn encrypt_decrypt_single_number_field() {
    let mut config = Config::new();
    let secret = [26u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_ecb".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("2", cipher_config);
    config.insert_cipher("age".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let decrypted_json = super::decrypt_document(&config, &encrypted_json).unwrap();

    assert_eq!(JSON, decrypted_json);
  }

  #[test]
  fn encrypt_decrypt_single_string_field() {
    let mut config = Config::new();
    let secret = [27u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_ecb".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("2", cipher_config);
    config.insert_cipher("address.city".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let decrypted_json = super::decrypt_document(&config, &encrypted_json).unwrap();

    assert_eq!(JSON, decrypted_json);
  }

  #[test]
  fn encrypt_decrypt_single_object_field() {
    let mut config = Config::new();
    let secret = [27u8; 32].to_vec();
    let cipher_config = Box::new(CipherConfig::new("aes_cbc".to_string(), secret));
    let mut cipher = Box::new(CipherData::new());
    cipher.insert_configuration("5", cipher_config);
    config.insert_cipher("address.*".to_string(), cipher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let decrypted_json = super::decrypt_document(&config, &encrypted_json).unwrap();

    assert_eq!(JSON, decrypted_json);
  }

  #[test]
  fn eq_query_single_string_field() {
    let mut config = Config::new();
    let salt = [10u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 10, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("1", hash_config);
    config.insert_hasher("email".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":25,"email":{"hashed_field":{"data":"zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE=","version":"1"},"type":"string"},"empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);

    let query = r#"{"email": "jonny.bravo@cn.com"}"#;
    let new_query = super::modify_find_query(&config, &query).unwrap();

    assert_eq!(r#"{"email.hashed_field.data":"zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE="}"#, new_query);

    let query = r#"{"email": { "$eq": "jonny.bravo@cn.com"}}"#;
    let new_query = super::modify_find_query(&config, &query).unwrap();

    assert_eq!(r#"{"email.hashed_field.data":{"$eq":"zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE="}}"#, new_query);
  }

  #[test]
  fn ne_query_single_number_field() {
    let mut config = Config::new();
    let salt = [10u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 10, salt));
    let mut hasher = Box::new(HasherData::new());
    hasher.insert_configuration("2", hash_config);
    config.insert_hasher("age".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":{"hashed_field":{"data":"ONSmub8QuVOyJSCaSLBPuG6AIvE/nzZ3QUhCrJ9bJKs=","version":"2"},"type":"number"},"email":"jonny.bravo@cn.com","empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);

    let query = r#"{"age": {"$ne": 25}}"#;
    let new_query = super::modify_find_query(&config, &query).unwrap();

    assert_eq!(r#"{"age.hashed_field.data":{"$ne":"ONSmub8QuVOyJSCaSLBPuG6AIvE/nzZ3QUhCrJ9bJKs="}}"#, new_query);
  }

  #[test]
  fn in_query_single_string_field_two_versions() {
    let mut config = Config::new();
    let mut hasher = Box::new(HasherData::new());

    let salt = [10u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 10, salt));
    hasher.insert_configuration("1", hash_config);

    let salt = [12u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 5, salt));
    hasher.insert_configuration("2", hash_config);

    config.insert_hasher("email".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":25,"email":{"hashed_field":{"data":"S64dayjXpy3SBhgmirr9Umanb3VWT4u3JYkRKNamJAA=","version":"2"},"type":"string"},"empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);

    let query = r#"{"email": {"$in":["jonny.bravo@cn.com", "jonny.bravo@cn2.com"]}}"#;
    let new_query = super::modify_find_query(&config, &query).unwrap();

    // {"email.hashed_field.data":{"$in":["zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE=","S64dayjXpy3SBhgmirr9Umanb3VWT4u3JYkRKNamJAA=","EXzdYiTBuBjW2bmiPlCBkQnmVUpzkKTbM4HN9SDSXsI=","WoGwQEvQWrIvdC0EfVSiyvdmcC5kKT+OzpeEI2wOb9U="]}}
    assert!(new_query.starts_with(r#"{"email.hashed_field.data":{"$in":["#));
    assert!(new_query.contains("zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE="));
    assert!(new_query.contains("S64dayjXpy3SBhgmirr9Umanb3VWT4u3JYkRKNamJAA="));
    assert!(new_query.contains("EXzdYiTBuBjW2bmiPlCBkQnmVUpzkKTbM4HN9SDSXsI="));
    assert!(new_query.contains("WoGwQEvQWrIvdC0EfVSiyvdmcC5kKT+OzpeEI2wOb9U="));
  }

  #[test]
  fn eq_query_single_string_field_two_versions() {
    let mut config = Config::new();
    let mut hasher = Box::new(HasherData::new());

    let salt = [10u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 10, salt));
    hasher.insert_configuration("1", hash_config);

    let salt = [12u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 5, salt));
    hasher.insert_configuration("2", hash_config);

    config.insert_hasher("email".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":25,"email":{"hashed_field":{"data":"S64dayjXpy3SBhgmirr9Umanb3VWT4u3JYkRKNamJAA=","version":"2"},"type":"string"},"empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);

    let query = r#"{"email": {"$eq":"jonny.bravo@cn.com"}}"#;
    let new_query = super::modify_find_query(&config, &query).unwrap();

    assert_eq!(r#"{"email.hashed_field.data":{"$in":["zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE=","S64dayjXpy3SBhgmirr9Umanb3VWT4u3JYkRKNamJAA="]}}"#, new_query);
  }

  #[test]
  fn ne_query_single_string_field_two_versions() {
    let mut config = Config::new();
    let mut hasher = Box::new(HasherData::new());

    let salt = [10u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("bcrypt".to_string(), 10, salt));
    hasher.insert_configuration("1", hash_config);

    let salt = [12u8; 16].to_vec();
    let hash_config = Box::new(HasherConfig::new("pbkdf2".to_string(), 5, salt));
    hasher.insert_configuration("2", hash_config);

    config.insert_hasher("email".to_string(), hasher);

    let config = Arc::new(RwLock::new(Box::new(config)));
    let encrypted_json = super::encrypt_document(&config, JSON).unwrap();
    let expected_json = r#"{"active":true,"address":{"city":"New York","country":"USA"},"age":25,"email":{"hashed_field":{"data":"S64dayjXpy3SBhgmirr9Umanb3VWT4u3JYkRKNamJAA=","version":"2"},"type":"string"},"empty":null,"name":"John","series":[1,2,3],"surname":"Bravo"}"#;

    assert_eq!(expected_json, encrypted_json);

    let query = r#"{"email": {"$ne":"jonny.bravo@cn.com"}}"#;
    let new_query = super::modify_find_query(&config, &query).unwrap();

    assert_eq!(r#"{"email.hashed_field.data":{"$nin":["zzzknrIcELaK5xDZnDWNnT4JSCseusMX0h2WdBdgTfE=","S64dayjXpy3SBhgmirr9Umanb3VWT4u3JYkRKNamJAA="]}}"#, new_query);
  }
}
