/// This file is used to store and retrieve user accounts from the database
///
/// Tasks todo: - Log stuff whenever required
///             - Potential improvements
use crate::user::{UserAccount, UserRole};
use lazy_static::lazy_static;
use rustbreak::{deser::Ron, FileDatabase};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

lazy_static! {
    static ref DB: FileDatabase<Database, Ron> =
        FileDatabase::load_from_path_or_default("db.ron").unwrap();
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Database {
    data: HashMap<String, UserAccount>,
}

impl Database {
    pub fn insert(user: &UserAccount) -> Result<(), Box<dyn Error>> {
        DB.write(|db| db.data.insert(user.username().to_string(), user.clone()))?;
        Ok(DB.save()?)
    }

    pub fn get(username: &str) -> Result<Option<UserAccount>, Box<dyn Error>> {
        Ok(match DB.borrow_data()?.data.get(username) {
            Some(user) => Some(user.clone()),
            None => None,
        })
    }

    pub fn values() -> Result<Vec<UserAccount>, Box<dyn Error>> {
        Ok(DB.borrow_data()?.data.values().cloned().collect())
    }
}

impl Default for Database {
    fn default() -> Self {
        let mut db = Database {
            data: HashMap::new(),
        };

        let u1 = UserAccount::new(
            "default_user".to_string(),
            "default_pass".to_string(),
            "0784539872".to_string(),
            UserRole::StandardUser,
        );

        let u2 = UserAccount::new(
            "default_hr".to_string(),
            "default_pass".to_string(),
            "0793175289".to_string(),
            UserRole::HR,
        );

        db.data.insert(u1.username().to_string(), u1);
        db.data.insert(u2.username().to_string(), u2);

        db
    }
}
