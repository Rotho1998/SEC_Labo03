extern crate zxcvbn;

use regex::Regex;
use zxcvbn::zxcvbn;

static REGEX_USERNAME: &str = r"^([[:alpha:]]){1}([[:alnum:].-_]){2,20}$";
static REGEX_PHONE: &str = r"^(0)(\d{9})$";

/**
Parameter: username - username to validate
Return: Bool - Result of the validation
 **/
pub fn validate_username(username: &str) -> bool {
    Regex::new(REGEX_USERNAME).unwrap().is_match(&username)
}

/**
Parameter: password - password to validate
Return: Bool - Result of the validation
 **/
pub fn validate_password(password: &str) -> bool {
    const MIN_SCORE: u8 = 3;
    const MIN_CHAR: usize = 8;
    const MAX_CHAR: usize = 64;
    let estimate = zxcvbn(password, &[]).unwrap();
    estimate.score() >= MIN_SCORE && password.len() >= MIN_CHAR && password.len() <= MAX_CHAR
}

/**
Parameter: phone - phone to validate
Return: Bool - Result of the validation
 **/
pub fn validate_phone(phone: &str) -> bool {
    Regex::new(REGEX_PHONE).unwrap().is_match(&phone)
}
