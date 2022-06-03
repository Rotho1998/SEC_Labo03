/// This file is used to execute the various actions submitted by the clients
///
/// Tasks todo: - Improve the authentication & access controls
///             - Input/output validation
///             - Log stuff whenever required
///             - Potential improvements
use crate::connection::Connection;
use crate::database::Database;
use crate::user::{UserAccount, UserRole};
use serde::{Deserialize, Serialize};
use std::error::Error;
use strum_macros::{EnumIter, EnumString};

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
        let users = Database::values()?;
        let res: Result<Vec<UserAccount>, &str> = Ok(users);
        u.conn().send(&res)
    }

    pub fn change_own_phone(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let phone = u.conn().receive::<String>()?;

        // Check permissions
        let res = if u.is_anonymous() {
            Err("Anonymous not allowed to change phone")
        } else {
            let mut user = u.user_account()?;
            user.set_phone_number(phone);
            Database::insert(&user)?;
            Ok(())
        };

        u.conn().send(&res)
    }

    pub fn change_phone(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?;
        let phone = u.conn().receive::<String>()?;
        let target_user = Database::get(&username)?;

        // Check permissions
        let res = if u.is_anonymous() {
            Err("Anonymous not allowed to change phone numbers")
        } else if let UserRole::StandardUser = u.user_account()?.role() {
            Err("Standard users not allowed to change other phone numbers")
        } else if target_user.is_none() {
            Err("Target user not found")
        } else {
            let mut target_user = target_user.unwrap();
            target_user.set_phone_number(phone);
            Database::insert(&target_user)?;
            Ok(())
        };

        u.conn().send(&res)
    }

    pub fn add_user(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?;
        let password = u.conn().receive::<String>()?;
        let phone = u.conn().receive::<String>()?;
        let role = u.conn().receive::<UserRole>()?;

        let res = if u.is_anonymous() {
            Err("Anonymous not allowed to add users")
        } else if let UserRole::HR = u.user_account()?.role() {
            if Database::get(&username)?.is_some() {
                Err("User already exists")
            } else {
                let user = UserAccount::new(username, password, phone, role);
                Ok(Database::insert(&user)?)
            }
        } else {
            Err("Only HR is allowed to add users")
        };

        u.conn.send(&res)
    }

    pub fn login(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?;
        let password = u.conn().receive::<String>()?;

        let res = if !u.is_anonymous() {
            Err("You are already logged in")
        } else {
            let user = Database::get(&username)?;
            if let Some(user) = user {
                if user.password() == password {
                    u.set_username(&username);
                    Ok(())
                } else {
                    Err("Invalid password")
                }
            } else {
                Err("User does not exist")
            }
        };

        u.conn.send(&res)
    }

    pub fn logout(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let res: Result<(), &str>;

        // Check permissions
        res = if u.is_anonymous() {
            Err("You are not logged in")
        } else {
            u.logout();
            Ok(())
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
