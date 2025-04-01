use anyhow::Result;
use clap::Parser;
use rsa_toolkit::{rsa, rsa_key::RSAKey};

#[derive(Parser, Debug)]
#[clap(name = "rsa_encrypt", version = "0.1.0", about = "RSA encoder")]
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
    
    let contents = std::fs::read_to_string(args.input)?;
    let encoded = rsa::rsa_encode_message(&contents, &key.key(), &key.n());

    //println!("{:?}", encoded);

    std::fs::write(args.output, encoded)?;
    
    Ok(())
}