use std::fs::File;
use std::io::Read;

use anyhow::Result;
use clap::Parser;
use rsa_toolkit::rsa;
use rsa_toolkit::rsa_key::RSAKey;

#[derive(Parser, Debug)]
#[clap(name = "rsa_decrypt", version = "0.1.0", about = "RSA decoder")]
struct Args {

    #[clap(short, long)]
    key: String,

    #[clap(short, long)]
    input: String,

    #[clap(short, long)]
    output: String,
}


fn main() -> Result<()> {

    let args: Args = Args::parse();
    let key = RSAKey::read(&args.key)?;

    let mut file = File::open(args.input)?;
    let mut contents = vec![];
    
    file.read_to_end(&mut contents)?;
    let decoded = rsa::rsa_decode_message(&contents, &key.key(), &key.n());

    std::fs::write(args.output, decoded)?;
    
    Ok(())
}