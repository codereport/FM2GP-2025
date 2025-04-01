use anyhow::Result;
use clap::Parser;
use rsa_toolkit::{rsa::rsa_keygen, rsa_key::RSAKey};

#[derive(Parser, Debug)]
#[clap(name = "rsa_keygen", version = "0.1.0", about = "RSA key generator")]
struct Args {

    #[clap(short, long, default_value = "64")]
    key_size: u32,

    #[clap(long)]
    pubkey: String,

    #[clap(long)]
    prvkey: String,
}



fn main() -> Result<()> {

    let args: Args = Args::parse();
    let key_size = args.key_size as usize;
    let (n, pubkey, prvkey) = rsa_keygen(key_size);
    println!("n: {}", n);
    println!("pubkey: {}", pubkey);
    println!("prvkey: {}", prvkey);

    let pubk = RSAKey::new(n.clone(), pubkey.clone());
    pubk.write(&args.pubkey)?;

    let prvk = RSAKey::new(n.clone(), prvkey.clone());
    prvk.write(&args.prvkey)?;
    
    Ok(())
}