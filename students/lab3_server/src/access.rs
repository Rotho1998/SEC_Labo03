use std::error::Error;
use casbin::CoreApi;
use casbin::prelude::Enforcer;
use crate::{Action, ConnectedUser, UserRole};
use log::warn;

#[tokio::main]
pub async fn verify_action(u: &mut ConnectedUser, action: &Action) -> Result<bool, Box<dyn Error>> {
    let mut e = Enforcer::new("access/access.conf", "access/access.csv")
        .await
        .expect("Cannot read model or policy");
    e.enable_log(true);

    let sub = if u.is_anonymous() {
        "anonymous"
    } else {
        match u.user_account()?.role() {
            UserRole::StandardUser => "standard",
            UserRole::HR => "hr",
        }
    };

    let obj = match action {
        Action::ShowUsers => "show_users",
        Action::ChangeOwnPhone => "change_own_phone",
        Action::ChangePhone => "change_phone",
        Action::AddUser => "add_user",
        Action::Login => "login",
        Action::Logout => "logout",
        Action::Exit => "exit",
    };

    if let Ok(authorized) = e.enforce((sub, obj)) {
        if authorized {
            Ok(true)
        } else {
            let user = if u.is_anonymous() {
                "An anonymous user".to_string()
            } else {
                u.username()
            };
            warn!("{} tried to access a non-authorized action: {:?}", user, action);
            Ok(false)
        }
    } else {
        warn!("Error with the access verification");
        Err("Error with the access verification".into())
    }
}