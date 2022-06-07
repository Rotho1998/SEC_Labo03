use argon2::{self};
use rand::{thread_rng, Rng};

pub fn generate_salt() -> Vec<u8> {
    let salt: [u8; 32] = thread_rng().gen();
    salt.to_vec()
}

pub fn generate_hash(password: &String, salt: &Vec<u8>) -> String {
    argon2::hash_encoded(&password.as_bytes(), &salt.to_vec(), &Default::default()).unwrap()
}
