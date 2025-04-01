use std::{fs::File, io::{BufReader, BufWriter}};

use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Serialize, Deserialize, Debug)]
pub struct RSAKey {
    n: String,
    key: String,
}

impl RSAKey {
    pub fn new(n: num_bigint::BigInt, key: num_bigint::BigInt) -> Self {
        RSAKey { n: n.to_string(), key: key.to_string() }
    }

    pub fn n(&self) -> num_bigint::BigInt {
        num_bigint::BigInt::parse_bytes(self.n.as_bytes(), 10).unwrap()
    }

    pub fn key(&self) -> num_bigint::BigInt {
        num_bigint::BigInt::parse_bytes(self.key.as_bytes(), 10).unwrap()
    }

    pub fn write(&self, filename: &str) -> Result<()> {
        let file = File::create(filename)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, self)?;

        Ok(())
    }

    pub fn read(filename: &str) -> Result<Self> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let key = serde_json::from_reader(reader)?;

        Ok(key)
    }
}