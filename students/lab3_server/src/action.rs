/// This file is used to execute the various actions submitted by the clients
///
/// Tasks todo: - Improve the authentication & access controls
///             - Input/output validation
///             - Log stuff whenever required
///             - Potential improvements
use crate::connection::Connection;
use crate::crypto::{generate_hash, generate_salt, verify_hash};
use crate::database::Database;
use crate::user::{UserAccount, UserRole};
use crate::validate_inputs::{validate_password, validate_phone, validate_username};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::error::Error;
use strum_macros::{EnumIter, EnumString};
use crate::access::verify_action;

#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Action {
    #[strum(serialize = "Show users", serialize = "1")]
    ShowUsers,
    #[strum(serialize = "Change my phone number", serialize = "2")]
    ChangeOwnPhone,
    #[strum(serialize = "Show someone's phone number", serialize = "3")]
    ChangePhone,
    #[strum(serialize = "Add user", serialize = "4")]
    AddUser,
    #[strum(serialize = "Login", serialize = "5")]
    Login,
    #[strum(serialize = "Logout", serialize = "6")]
    Logout,
    #[strum(serialize = "Exit", serialize = "7")]
    Exit,
}

/// The individual actions are implemented with three main steps:
///     1. Read client inputs if required
///     2. Execute various server code
///     3. Send a result
impl Action {
    pub fn perform(&self, u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let res = match self {
            Action::ShowUsers => Action::show_users(u),
            Action::ChangeOwnPhone => Action::change_own_phone(u),
            Action::ChangePhone => Action::change_phone(u),
            Action::AddUser => Action::add_user(u),
            Action::Login => Action::login(u),
            Action::Logout => Action::logout(u),
            Action::Exit => Err("Client disconnected")?,
        };

        res
    }

    pub fn show_users(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Check permissions
        let res = match verify_action(u, &Action::ShowUsers) {
            Ok(true) => {
                let users = Database::values()?;
                info!("Users sent");
                Ok(users)
            },
            _ => Err("You can't do this action"),
        };

        u.conn().send(&res)
    }

    pub fn change_own_phone(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let phone = u.conn().receive::<String>()?;

        // Check permissions
        let res = match verify_action(u, &Action::ChangeOwnPhone) {
            Ok(true) => {
                if !validate_phone(&phone) {
                    warn!("Invalid phone format from user {}", u.username());
                    Err("Invalid phone format")
                } else {
                    let mut user = u.user_account()?;
                    user.set_phone_number(phone.clone());
                    Database::insert(&user)?;
                    info!("Phone number changed for user {}", u.username());
                    Ok(())
                }
            },
            _ => Err("You can't do this action"),
        };

        u.conn().send(&res)
    }

    pub fn change_phone(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?;
        let phone = u.conn().receive::<String>()?;
        let target_user = Database::get(&username)?;

        // Check permissions
        let res = match verify_action(u, &Action::ChangePhone) {
            Ok(true) => {
                if !validate_username(&username) {
                    warn!("Invalid username format from user {}", u.username());
                    Err("Invalid username format")
                } else if !validate_phone(&phone) {
                    warn!("Invalid phone format from user {}", u.username());
                    Err("Invalid phone format")
                }else if target_user.is_none() {
                    warn!("Target user not found from user {}", u.username());
                    Err("Target user not found")
                } else {
                    let mut target_user = target_user.unwrap();
                    target_user.set_phone_number(phone);
                    Database::insert(&target_user)?;
                    info!("Phone number changed for user {} from user {}", username, u.username());
                    Ok(())
                }
            },
            _ => Err("You can't do this action"),
        };

        u.conn().send(&res)
    }

    pub fn add_user(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?;
        let password = u.conn().receive::<String>()?;
        let phone = u.conn().receive::<String>()?;
        let role = u.conn().receive::<UserRole>()?;

        // Check permissions
        let res = match verify_action(u, &Action::AddUser) {
            Ok(true) => {
                if !validate_username(&username) {
                    warn!("Invalid username format from user {}", u.username());
                    Err("Invalid username format")
                }else if !validate_password(&password) {
                    warn!("Invalid password format from user {}", u.username());
                    Err("Invalid password format")
                }else if !validate_phone(&phone) {
                    warn!("Invalid phone format from user {}", u.username());
                    Err("Invalid phone format")
                }else if Database::get(&username)?.is_some() {
                    warn!("User already exists ({}) from user {}", username, u.username());
                    Err("User already exists")
                } else {
                    let salt = generate_salt();
                    let hash_password = generate_hash(&password, &salt);
                    let user = UserAccount::new(username, hash_password, phone, role);
                    info!("User added in database from user {}", u.username());
                    Ok(Database::insert(&user)?)
                }
            },
            _ => Err("You can't do this action"),
        };

        u.conn.send(&res)
    }

    pub fn login(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?;
        let password = u.conn().receive::<String>()?;

        // Check permissions
        let res = match verify_action(u, &Action::Login) {
            Ok(true) => {
                if !validate_username(&username) {
                    warn!("Invalid username format");
                    Err("Invalid username format")
                } else if !validate_password(&password) {
                    warn!("Invalid password format");
                    Err("Invalid password format")
                } else {
                    let user = Database::get(&username)?;
                    if let Some(user) = user {
                        if verify_hash(&user.password().to_string(), &password) {
                            u.set_username(&username);
                            info!("{} has logged in", u.username());
                            Ok(())
                        } else {
                            warn!("Invalid inputs for username : {}", username);
                            Err("Invalid inputs")
                        }
                    } else {
                        warn!("Invalid inputs for username : {}", username);
                        Err("Invalid inputs")
                    }
                }
            },
            _ => Err("You can't do this action"),
        };

        u.conn.send(&res)
    }

    pub fn logout(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Check permissions
        let res = match verify_action(u, &Action::Logout) {
            Ok(true) => {
                info!("{} has logged out", u.username());
                u.logout();
                Ok(())
            },
            _ => Err("You can't do this action"),
        };

        u.conn.send(&res)
    }
}

/// Used to represent a connected user for the actions
pub struct ConnectedUser {
    username: Option<String>,
    conn: Connection,
}

impl ConnectedUser {
    pub fn anonymous(conn: Connection) -> ConnectedUser {
        ConnectedUser {
            username: None,
            conn,
        }
    }

    pub fn username(&mut self) -> String {
        self.username.as_ref().unwrap().clone()
    }

    pub fn conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn set_username(&mut self, username: &str) {
        self.username = Some(username.to_string());
    }

    pub fn is_anonymous(&self) -> bool {
        return self.username.is_none();
    }

    pub fn logout(&mut self) {
        self.username = None;
    }

    pub fn user_account(&mut self) -> Result<UserAccount, Box<dyn Error>> {
        Ok(Database::get(&self.username())?.expect("User logged in but not in DB"))
    }
}
