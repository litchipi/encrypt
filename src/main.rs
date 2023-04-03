use std::io::{Read, Write};
use clap::Parser;

use encryptf::{
    Errcode,
    EncryptedData,
    get_password,
    create_password,
};

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

fn main() {
    let args = Args::parse();
    if let Err(e) = args.start() {
        println!("Error: {:?}", e);
    }
}
