use nix::sys::termios::{tcgetattr, tcsetattr, SetArg};
use orion::aead;
use orion::errors::UnknownCryptoError;
use orion::hash::{digest, Digest};
use orion::kdf::{Password, Salt, SecretKey};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;

const DEFAULT_ITER: u32 = 3;
const DEFAULT_MEM: u32 = 1 << 16;

type KdfOpt = (u32, u32);

#[derive(Debug)]
pub enum Errcode {
    WeakPassword,
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

fn get_kdf_opt(opt: Option<KdfOpt>) -> KdfOpt {
    if let Some((t, m)) = opt {
        (t, m)
    } else {
        (DEFAULT_ITER, DEFAULT_MEM)
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    pub pwd_hint: String,
    salt: orion::kdf::Salt,
    ciphertext: Vec<u8>,
    checksum: Digest,
    pub kdf_opt: KdfOpt,
}

impl EncryptedData {
    fn derive_key(
        salt: &Salt,
        pwd: &Password,
        kdf_opt: Option<KdfOpt>,
    ) -> Result<SecretKey, UnknownCryptoError> {
        let (it, mm) = get_kdf_opt(kdf_opt);
    orion::kdf::derive_key(pwd, salt, it, mm, 32)
    }

    pub fn decrypt<T: ToString, F: Write>(&self, pwd: T, outf: &mut F) -> Result<(), Errcode> {
        let user_password = Password::from_slice(pwd.to_string().as_bytes())?;
        let derived_key = Self::derive_key(&self.salt, &user_password, Some(self.kdf_opt))?;
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
            kdf_opt: get_kdf_opt(kdf_opt),
        })
    }
}

fn set_sig_handler() {
    let stdin_fd = std::io::stdin().as_raw_fd();
    let termios = tcgetattr(stdin_fd).unwrap();
    ctrlc::set_handler(move || {
        println!("Interrupted");
        tcsetattr(stdin_fd, SetArg::TCSANOW, &termios).unwrap();
        std::process::exit(1);
    })
    .unwrap();
}

fn check_password_strength(pwd: &String) -> Result<(), Errcode> {
    let mut flag = pwd.len() < 6;
    flag = flag || false; // TODO        Check entropy of the password
    if flag {
        Err(Errcode::WeakPassword)
    } else {
        Ok(())
    }
}

pub fn get_password(hint: &String) -> Result<String, Errcode> {
    set_sig_handler();
    println!("Password hint: {}", hint);
    let pwd =
        rpassword::prompt_password("Enter your password: ").expect("Error while getting password");
    check_password_strength(&pwd)?;
    Ok(pwd)
}

pub fn create_password() -> Result<(String, String), Errcode> {
    set_sig_handler();
    let pwd = loop {
        let pwd = rpassword::prompt_password("Enter your password: ")
            .expect("Error while getting password");
        let confirm = rpassword::prompt_password("Confirm your password: ")
            .expect("Error while getting password");
        if pwd == confirm {
            break pwd;
        } else {
            println!("Passwords doesn't match");
            println!();
        }
    };
    check_password_strength(&pwd)?;
    println!("Enter a hint to remember it:");
    let mut pwd_hint = String::new();
    let stdin = std::io::stdin();
    stdin
        .read_line(&mut pwd_hint)
        .expect("Error while getting hint");
    Ok((pwd, pwd_hint))
}
