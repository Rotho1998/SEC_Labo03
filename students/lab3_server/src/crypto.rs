use argon2::{self};
use rand::{thread_rng, Rng};

/**
Parameter: None
Return: Vec<u8> - Salt generated
 **/
pub fn generate_salt() -> Vec<u8> {
    let salt: [u8; 32] = thread_rng().gen();
    salt.to_vec()
}

/**
Parameters: password - password to hash
            salt     - salt used to hash the password
Return: String - Hashed password
 **/
pub fn generate_hash(password: &String, salt: &Vec<u8>) -> String {
    argon2::hash_encoded(&password.as_bytes(), &salt.to_vec(), &Default::default()).unwrap()
}

/**
Parameters: hash     - hash of the password to verify
            password - plain password to verify
Return: Bool - Result of the verification
 **/
pub fn verify_hash(hash: &String, password: &String) -> bool {
    argon2::verify_encoded(&hash, password.as_ref()).unwrap()
}