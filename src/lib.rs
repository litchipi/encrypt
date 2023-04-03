use orion::aead;
use orion::errors::UnknownCryptoError;
use orion::hash::{digest, Digest};
use orion::kdf::{Password, Salt, SecretKey};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const DEFAULT_ITER: u32 = 3;
const DEFAULT_MEM: u32 = 1 << 16;

type KdfOpt = (u32, u32);

#[derive(Debug)]
pub enum Errcode {
    OrionError(orion::errors::UnknownCryptoError),
    IoError(std::io::Error),
    BinarySerialization(bincode::Error),
}

impl From<bincode::Error> for Errcode {
    fn from(err: bincode::Error) -> Errcode {
        Errcode::BinarySerialization(err)
    }
}

impl From<std::io::Error> for Errcode {
    fn from(err: std::io::Error) -> Errcode {
        Errcode::IoError(err)
    }
}

impl From<orion::errors::UnknownCryptoError> for Errcode {
    fn from(err: orion::errors::UnknownCryptoError) -> Errcode {
        Errcode::OrionError(err)
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    pub pwd_hint: String,
    salt: orion::kdf::Salt,
    ciphertext: Vec<u8>,
    checksum: Digest,
}

impl EncryptedData {
    fn derive_key(
        salt: &Salt,
        pwd: &Password,
        kdf_opt: Option<KdfOpt>,
    ) -> Result<SecretKey, UnknownCryptoError> {
        let (it, mm) = if let Some((it, mm)) = kdf_opt {
            (it, mm)
        } else {
            (DEFAULT_ITER, DEFAULT_MEM)
        };

        orion::kdf::derive_key(pwd, salt, it, mm, 32)
    }

    pub fn decrypt<T: ToString, F: Write>(
        &self,
        pwd: T,
        outf: &mut F,
        kdf_opt: Option<KdfOpt>,
    ) -> Result<(), Errcode> {
        let user_password = Password::from_slice(pwd.to_string().as_bytes())?;
        let derived_key = Self::derive_key(&self.salt, &user_password, kdf_opt)?;
        let decrypted_data = aead::open(&derived_key, &self.ciphertext)?;
        if digest(&decrypted_data)? != self.checksum {
            panic!("Error while decrypting data: Wrong checksum");
        }
        let nwrote = outf.write(&decrypted_data)?;
        if nwrote == 0 {
            println!("WARN: No data wrote to output file");
        }
        Ok(())
    }

    pub fn encrypt<T: ToString, F: Read>(
        pwd: T,
        pwd_hint: String,
        inf: &mut F,
        kdf_opt: Option<KdfOpt>,
    ) -> Result<Self, Errcode> {
        let user_password = Password::from_slice(pwd.to_string().as_bytes())?;
        let salt = Salt::default();
        let derived_key = Self::derive_key(&salt, &user_password, kdf_opt)?;
        let mut plain_data = Vec::new();
        inf.read_to_end(&mut plain_data)?;
        let checksum = digest(&plain_data)?;
        let ciphertext = aead::seal(&derived_key, &plain_data)?;
        Ok(EncryptedData {
            salt,
            pwd_hint,
            ciphertext,
            checksum,
        })
    }
}

pub fn get_password(hint: &String) -> String {
    println!("Password hint: {}", hint);
    rpassword::prompt_password("Enter your password: ").expect("Error while getting password")
}

pub fn create_password() -> (String, String) {
    let pwd = loop {
        let pwd = rpassword::prompt_password("Enter your password: ")
            .expect("Error while getting password");
        let confirm = rpassword::prompt_password("Confirm your password: ")
            .expect("Error while getting password");
        if pwd == confirm {
            break pwd;
        }
    };
    println!("Enter a hint to remember it:");
    let mut pwd_hint = String::new();
    let stdin = std::io::stdin();
    stdin
        .read_line(&mut pwd_hint)
        .expect("Error while getting hint");
    (pwd, pwd_hint)
}
