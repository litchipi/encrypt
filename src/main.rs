use orion::hash::{digest, Digest};
use orion::aead;
use orion::kdf::{Password, SecretKey, Salt};
use orion::errors::UnknownCryptoError;
use serde::{Serialize, Deserialize};
use std::io::{Read, Write};
use clap::Parser;

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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    output: std::path::PathBuf,

   #[arg(short, long)]
    decrypt: Option<std::path::PathBuf>,

   #[arg(short='c', long)]
    encrypt: Option<std::path::PathBuf>,
}

impl Args {
    fn start(&self) -> Result<(), Errcode> {
        if let Some(ref dec_file) = self.decrypt {
            assert!(self.encrypt.is_none());
            let mut encdata_file = std::fs::File::open(dec_file)?;
            let mut encdata_buf = Vec::new();
            encdata_file.read_to_end(&mut encdata_buf)?;
            let encdata : EncryptedData = bincode::deserialize(&encdata_buf)?;
            let pwd = get_password(&encdata.pwd_hint);
            let mut outf = std::fs::File::create(&self.output)?;
            encdata.decrypt(pwd, &mut outf)?;
            println!("Decryption finished successfully");

        } else if let Some(ref enc_file) = self.encrypt {
            assert!(self.decrypt.is_none());
            let (pwd, hint) = create_password();
            let mut plaintext_file = std::fs::File::open(enc_file).expect("Input file doesn't exist");
            let encdata = EncryptedData::encrypt(pwd, hint, &mut plaintext_file)?;
            let mut outf = std::fs::File::create(&self.output)?;
            let encdata_bin = bincode::serialize(&encdata)?;
            outf.write(&encdata_bin)?;
            println!("Encryption finished successfully");

        } else {
            println!("Expected encrypt or decrypt arg");
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    salt: orion::kdf::Salt,
    pwd_hint: String,
    ciphertext: Vec<u8>,
    checksum: Digest,
}

impl EncryptedData {
    fn derive_key(salt: &Salt, pwd: &Password) -> Result<SecretKey, UnknownCryptoError> {
        orion::kdf::derive_key(pwd, salt, 3, 1<<16, 32)
    }

    fn decrypt<T: ToString, F: Write>(&self, pwd: T, outf: &mut F) -> Result<(), Errcode> {
        let user_password = Password::from_slice(pwd.to_string().as_bytes())?;
        let derived_key = Self::derive_key(&self.salt, &user_password)?;
        let decrypted_data = aead::open(&derived_key, &self.ciphertext)?;
        if digest(&decrypted_data)? != self.checksum {
            panic!("Error while decrypting data: Wrong checksum");
        }
        outf.write(&decrypted_data)?;
        Ok(())
    }

    fn encrypt<T: ToString, F: Read>(pwd: T, pwd_hint: String, inf: &mut F) -> Result<Self, Errcode> {
        let user_password = Password::from_slice(pwd.to_string().as_bytes())?;
        let salt = Salt::default();
        let derived_key = Self::derive_key(&salt, &user_password)?;
        let mut plain_data = Vec::new();
        inf.read_to_end(&mut plain_data)?;
        let checksum = digest(&plain_data)?;
        let ciphertext = aead::seal(&derived_key, &plain_data)?;
        Ok(EncryptedData { salt, pwd_hint, ciphertext, checksum })
    }
}

fn get_password(hint: &String) -> String {
    println!("Password hint: {}", hint);
    rpassword::prompt_password("Enter your password: ").expect("Error while getting password")
}

fn create_password() -> (String, String) {
    let pwd = loop {
        let pwd = rpassword::prompt_password("Enter your password: ").expect("Error while getting password");
        let confirm = rpassword::prompt_password("Confirm your password: ").expect("Error while getting password");
        if pwd == confirm {
            break pwd;
        }
    };
    println!("Enter a hint to remember it:");
    let mut pwd_hint = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut pwd_hint).expect("Error while getting hint");
    (pwd, pwd_hint)
}

fn main() {
    let args = Args::parse();
    if let Err(e) = args.start() {
        println!("Error: {:?}", e);
    }
}
