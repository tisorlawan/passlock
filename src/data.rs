use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub type PasswordStore = IndexMap<String, Vec<Account>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub fields: IndexMap<String, String>,
}

pub fn example_store() -> PasswordStore {
    let mut store = IndexMap::new();

    store.insert(
        "github.com".to_string(),
        vec![
            Account {
                name: "work".to_string(),
                fields: IndexMap::from([
                    ("username".to_string(), "work-user".to_string()),
                    ("password".to_string(), "work-pass".to_string()),
                    ("api_token".to_string(), "ghp_work123".to_string()),
                ]),
            },
            Account {
                name: "personal".to_string(),
                fields: IndexMap::from([
                    ("username".to_string(), "personal-user".to_string()),
                    ("password".to_string(), "personal-pass".to_string()),
                ]),
            },
        ],
    );

    store.insert(
        "aws".to_string(),
        vec![Account {
            name: "prod".to_string(),
            fields: IndexMap::from([
                ("access_key".to_string(), "AKIAIOSFODNN7EXAMPLE".to_string()),
                (
                    "secret_key".to_string(),
                    "wJalrXUtnFEMI/K7MDENG".to_string(),
                ),
            ]),
        }],
    );

    store
}

pub fn serialize(store: &PasswordStore) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(store).map_err(|e| e.to_string())
}

pub fn deserialize(data: &[u8]) -> Result<PasswordStore, String> {
    serde_json::from_slice(data).map_err(|e| e.to_string())
}
