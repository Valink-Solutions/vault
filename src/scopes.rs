use std::collections::HashMap;

use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct Scopes {
    pub data: HashMap<String, String>,
}

impl Scopes {
    pub fn new() -> Self {
        let initial_scopes = vec![
            (
                "world:read".to_string(),
                "allows client to view users worlds".to_string(),
            ),
            (
                "world:write".to_string(),
                "allows client to create/modify/delete users worlds".to_string(),
            ),
            (
                "backup:read".to_string(),
                "allows client to view users backups".to_string(),
            ),
            (
                "backup:write".to_string(),
                "allows client to create/modify/delete users backups".to_string(),
            ),
            (
                "user:read".to_string(),
                "allows client to view users account info".to_string(),
            ),
            (
                "user:write".to_string(),
                "allows client to modify users account info".to_string(),
            ),
        ];
        let data: HashMap<_, _> = initial_scopes.into_iter().collect();
        Self { data }
    }

    pub fn vec_as_str(&self, keys: Vec<String>) -> String {
        let mut result = Vec::new();
        for key in keys {
            result.push(key);
        }
        result.join(",")
    }

    pub fn as_str(&self) -> String {
        let mut result = Vec::new();
        for (key, _) in self.data.iter() {
            result.push(key.clone());
        }
        result.join(",")
    }

    pub fn as_vec(&self) -> Vec<String> {
        let mut result = Vec::new();
        for (key, _) in self.data.iter() {
            result.push(key.clone());
        }
        result
    }

    pub fn validated_keys_vec(&self, keys: Vec<String>) -> Vec<String> {
        let mut validated_keys = Vec::new();
        for key in keys {
            if self.data.contains_key(&key) {
                validated_keys.push(key);
            }
        }
        validated_keys
    }

    pub fn validated_keys_hashmap(&self, keys: Vec<String>) -> HashMap<String, String> {
        let mut validated_keys = HashMap::new();
        for key in keys {
            if let Some(value) = self.data.get(&key) {
                validated_keys.insert(key, value.clone());
            }
        }
        validated_keys
    }
}
