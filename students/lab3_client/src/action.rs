/// This file is used to execute the various actions sent to the server
///
/// Tasks todo: - Some client-side input/output validation
use std::error::Error;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString, Display};
use read_input::prelude::*;

use crate::connection::Connection;

type EmptyResult = Result<(), String>;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserAccount {
    username: String,
    password: String,
    phone_number: String,
    role: UserRole,
}

#[derive(Serialize, Deserialize, Clone, Debug, Display, EnumString, EnumIter)]
enum UserRole {
    #[strum(serialize = "StandardUser")]
    StandardUser,
    #[strum(serialize = "HR")]
    HR,
}

#[derive(Serialize, Deserialize, Display, EnumString, EnumIter)]
pub enum Action {
    #[strum(serialize = "Show users", serialize = "1")]
    ShowUsers,
    #[strum(serialize = "Change my phone number", serialize = "2")]
    ChangeOwnPhone,
    #[strum(serialize = "Change someone's phone number", serialize = "3")]
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

impl Action {
    pub fn display() {
        let mut actions = Action::iter();
        for i in 1..=actions.len() { println!("{}.\t{}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        connection.send(self)?;

        let res = match self {
            Action::ShowUsers => Action::show_users(connection),
            Action::ChangeOwnPhone => Action::change_own_phone(connection),
            Action::ChangePhone => Action::change_phone(connection),
            Action::AddUser => Action::add_user(connection),
            Action::Login => Action::login(connection),
            Action::Logout => Action::logout(connection),
            Action::Exit => Err("Client disconnected")?
        };

        res
    }

    pub fn show_users(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let res: Result<Vec<UserAccount>, String> = connection.receive()?;
        match res {
            Ok(users) => {
                for u in users {
                    println!("{} - {}", u.username, u.phone_number);
                }
            }
            Err(e) => {println!("Error while showing users: {}", e)}
        }

        Ok(())
    }

    pub fn change_own_phone(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let phone_number = input::<String>().msg("Please enter your new phone number: ").get();
        connection.send(&phone_number)?;

        let res = connection.receive::<EmptyResult>()?;
        if let Err(e) = res {
            println!("Error while changing phone: {}", e);
        }

        Ok(())
    }

    pub fn change_phone(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let username = input::<String>().msg("Please enter the username: ").get();
        let phone_number = input::<String>().msg("Please enter the new phone number: ").get();
        connection.send(&username)?;
        connection.send(&phone_number)?;

        let res = connection.receive::<EmptyResult>()?;
        if let Err(e) = res {
            println!("Error while changing phone: {}", e);
        }

        Ok(())
    }

    pub fn add_user(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let username = input::<String>().msg("Please enter the username: ").get();
        let password = input::<String>().msg("Please enter the password: ").get();
        let phone_number = input::<String>().msg("Please enter the phone number: ").get();
        let role = input::<UserRole>().msg("Please enter the role (HR/StandardUser): ").get();
        connection.send(&username)?;
        connection.send(&password)?;
        connection.send(&phone_number)?;
        connection.send(&role)?;

        let res = connection.receive::<EmptyResult>()?;
        if let Err(e) = res {
            println!("Error while adding user: {}", e);
        }

        Ok(())
    }

    pub fn login(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let username = input::<String>().msg("Please enter the username: ").get();
        let password = input::<String>().msg("Please enter the password: ").get();
        connection.send(&username)?;
        connection.send(&password)?;

        let res = connection.receive::<EmptyResult>()?;
        if let Err(e) = res {
            println!("Error during login: {}", e);
        }

        Ok(())
    }

    pub fn logout(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let res = connection.receive::<EmptyResult>()?;
        if let Err(e) = res {
            println!("{}", e);
        }

        Ok(())
    }
}
