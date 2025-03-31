use num::{BigInt, BigUint};

use num::Integer as NumInteger;
use num::bigint::{RandomBits, ToBigInt, UniformBigUint};
use num::traits::{One, Zero};
use rand::distributions::Distribution;
use rand::distributions::uniform::UniformSampler;
use std::fmt::Display;

pub trait Integer: NumInteger + Clone + Display {}

impl Integer for BigInt {}
impl Integer for BigUint {}

pub fn two<I: Integer>() -> I {
    I::one() + I::one()
}

pub fn half<I: Integer>(x: I) -> I {
    x.div(two())
}

/// Semigroup operation with associated domain
/// Given the operation definition `op` we can define exponentiation
/// of the operatoin
pub trait SemiGroupOp {
    /// The domain of the operation
    type Dom: Clone + Eq;

    // required to be defined
    // Precondition: op is associative
    fn op(&self, x: &Self::Dom, y: &Self::Dom) -> Self::Dom;

    // implementations using op
    /// Computes op(r, a^n) using the semigroup operation
    /// Precondition n >= 0
    /// Note: `r` must be a valid value in the domain e.g. already reduced for
    /// modular arithmetic
    fn power_acc_semigrp<I: Integer>(&self, r: &Self::Dom, a: &Self::Dom, n: I) -> Self::Dom {
        let mut n = n.clone();
        let mut r = r.clone();
        let mut a = a.clone();
        if n == I::zero() {
            return r;
        }
        loop {
            if n.is_odd() {
                r = self.op(&r, &a);
                if n == I::one() {
                    return r;
                }
            }

            n = half(n);
            a = self.op(&a, &a);
        }
    }

    /// Computes a^n using op.
    /// Precondition n > 0
    fn power_semigrp<I: Integer>(&self, a: &Self::Dom, n: I) -> Self::Dom {
        let mut a = a.clone();
        let mut n = n;
        while !n.is_odd() {
            a = self.op(&a, &a);
            n = half(n);
        }

        if n == I::one() {
            return a;
        }

        self.power_acc_semigrp(&a, &self.op(&a, &a), half(n - I::one()))
    }
}

/// Modular multiplication operation
struct ModMult<I: Integer> {
    modulus: I,
}

impl<I: Integer> ModMult<I> {
    pub fn new(n: I) -> Self {
        Self { modulus: n }
    }
}

impl SemiGroupOp for ModMult<BigUint> {
    type Dom = BigUint;

    fn op(&self, x: &Self::Dom, y: &Self::Dom) -> Self::Dom {
        (x * y) % &self.modulus
    }
}

// Extended GCD and helpers

/// Returns the largest doubling of `b` less than `a` i.e. the largest
/// number of the form `b' = 2^k * b` where `b' < a`.
/// Precondition: b != 0
pub fn largest_doubling(a: &BigUint, b: &BigUint) -> BigUint {
    let mut b = b.clone();
    while *a > b && a - &b >= b {
        b <<= 1;
    }
    b
}

/// Returns the quotient and remainder `(q, r)` of `a` divided by `b`
/// where `a = q * b + r` and `0 <= r < b`.
/// Precondition: b > 0
pub fn quot_rem(a: &BigUint, b: &BigUint) -> (BigUint, BigUint) {
    let mut a = a.clone();
    if a < *b {
        return (BigUint::zero(), a.clone());
    }

    let mut c = largest_doubling(&a, &b);
    let mut n = BigUint::one();
    a -= &c;

    while c != *b {
        c >>= 1;
        n <<= 1;
        if c <= a {
            a -= &c;
            n += BigUint::one();
        }
    }

    (n, a)
}

/// Computes the gcd of `a` and `b` as well as the Bezout coefficient for
/// `a`. Returns (s, d) where `d = gcd(a, b)` and `d = s * a + t * b`
/// (`t` can be computed from `s` and `d` as `t = (d - s * a) / b`).
pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigInt, BigUint) {
    let mut r0 = a.clone();
    let mut r1 = b.clone();
    let mut s0 = BigInt::one();
    let mut s1 = BigInt::zero();

    while r1 != BigUint::zero() {
        let (q, r) = quot_rem(&r0, &r1);
        let s2 = s0 - q.to_bigint().unwrap() * &s1;
        s0 = s1;
        s1 = s2;
        r0 = r1;
        r1 = r;
    }
    (s0, r0)
}

/// Computes the multiplicative inverse of `a` mod `n`, if it exists.
/// Return `Some(inv)` if the inverse exits, otherwise `None`.
pub fn multiplicative_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let (inv, gcd) = extended_gcd(a, n);
    if gcd != BigUint::one() {
        return None;
    }
    if inv < BigInt::zero() {
        let inv = inv + n.to_bigint().unwrap();
        return Some(inv.to_biguint().unwrap());
    }
    Some(inv.to_biguint().unwrap())
}

/// Returns the factorization of n as 2^k * q where
/// q is odd. The returned value is the pair (k, q).
pub fn pow2_factor(n: &BigUint) -> (BigUint, BigUint) {
    let mut k = BigUint::zero();
    let mut q = n.clone();
    while q.is_even() {
        q >>= 1;
        k += BigUint::one();
    }

    (k, q)
}

/// Performs 100 Miller-Rabin tests on `n` with random
/// witnesses. Returns `true` if all succeed, `false` otherwise.
pub fn miller_rabin_test(n: &BigUint) -> bool {
    if n.is_even() {
        return false;
    }

    let n_pred = n - BigUint::one();
    let (k, q) = pow2_factor(&n_pred);
    let mut rng = rand::thread_rng();
    let sampler = UniformBigUint::new(BigUint::zero(), n.clone());
    for _ in 0..100 {
        let w = sampler.sample(&mut rng);
        if !miller_rabin_test_internal(n, &q, &k, &w) {
            return false;
        }
    }
    true
}

/// Perform the Miller-Rabin test to determine if n is probably prime.
/// Precondition: n > 1 and n - 1 = 2^k * q and q is odd
fn miller_rabin_test_internal(n: &BigUint, q: &BigUint, k: &BigUint, w: &BigUint) -> bool {
    let mult: ModMult<_> = ModMult::new(n.clone());
    let mut x = mult.power_semigrp(w, q.clone());
    let one = BigUint::one();
    let neg_one = n - &one;

    if &x == &one || &x == &neg_one {
        return true;
    }

    let mut k = k.clone();
    while k > BigUint::zero() {
        x = mult.op(&x, &x);
        if &x == &neg_one {
            return true;
        }
        if &x == &one {
            return false;
        }
        k -= &one;
    }

    false
}

/// Generate a prime with `bits` bits
pub fn gen_prime(bits: u64) -> BigUint {
    let mut rng = rand::thread_rng();
    let sampler = RandomBits::new(bits);
    loop {
        let p = sampler.sample(&mut rng);
        if miller_rabin_test(&p) {
            return p;
        }
    }
}

/// Generate a number with `bits` bits coprime with `n`
pub fn gen_coprime(bits: u64, n: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    let sampler = RandomBits::new(bits);
    loop {
        let p: BigUint = sampler.sample(&mut rng);
        if p.gcd(n) == BigUint::one() {
            return p;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Pubkey {
    key: BigUint,
    n: BigUint,
    bits: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Privkey {
    key: BigUint,
    n: BigUint,
    bits: usize,
}

/// Generate a public, private key pair, by generating two primes
/// with `bits` bits.
pub fn rsa_keygen(bits: u64) -> (Pubkey, Privkey) {
    let p = gen_prime(bits);
    let q = gen_prime(bits);
    let n = &p * &q;
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());

    let pubkey = gen_coprime(bits, &phi);
    let privkey = multiplicative_inverse(&pubkey, &phi).unwrap();
    (
        Pubkey {
            key: pubkey,
            n: n.clone(),
            bits: bits as usize,
        },
        Privkey {
            key: privkey,
            n,
            bits: bits as usize,
        },
    )
}

/// Perform RSA encryption or decryption on `msg_block` using `key`.
/// Precondition: `msg_block.len()` is less the the number of bits use to generate `key`
fn rsa_code(msg_block: &[u8], key: &BigUint, n: &BigUint) -> Vec<u8> {
    let msg = BigUint::from_bytes_le(msg_block);
    let mult: ModMult<_> = ModMult::new(n.clone());
    let res = mult.power_semigrp(&msg, key.clone());
    res.to_bytes_le()
}

/// Encrypt `msg` using public key `key`. `msg` is broken into blocks
/// of length `key.bits / 8` to ensure each block can be encoded as an
/// integer `mod key.n`. If `msg` can not be evenly broken into blocks
/// of this length, then the final block is padded with the letter `x`.
pub fn rsa_encrypt(msg: &str, key: &Pubkey) -> Vec<Vec<u8>> {
    let block_size = key.bits / 8;
    let mut encrypted = Vec::new();

    let msg_chunks = msg.as_bytes().chunks_exact(block_size);
    let rem = msg_chunks.remainder();
    for block in msg_chunks {
        encrypted.push(rsa_code(&block, &key.key, &key.n));
    }

    // pad the message if needed
    if rem.len() > 0 {
        let padding = "x".repeat(block_size - rem.len());
        let msg = {
            let mut m = Vec::from(rem);
            m.extend(padding.as_bytes());
            m
        };

        encrypted.push(rsa_code(&msg, &key.key, &key.n));
    }

    encrypted
}

/// Decrypt `msg` using  private key `key`.
/// Precondition: The `Vec<u8>` blocks in `msg` can be encoded as
/// numbers `mod key.n`.
pub fn rsa_decrypt(msg: &[Vec<u8>], key: &Privkey) -> String {
    let mut decrypted = String::new();
    for block in msg {
        decrypted.push_str(&String::from_utf8(rsa_code(&block, &key.key, &key.n)).unwrap());
    }

    decrypted
}

pub fn main() {
    let bits = 256;
    let (alice_pub, alice_priv) = rsa_keygen(bits);
    let (bob_pub, bob_priv) = rsa_keygen(bits);

    let alice_msg = concat!(
        "Hey Bob! Have you heard of Curry's paradox?",
        "What can you conclude from this statement? 'If this sentence is true, then Germany borders China.'"
    );

    let alice_msg_encrypt = rsa_encrypt(&alice_msg, &bob_pub);
    let alice_msg_decrypt = rsa_decrypt(&alice_msg_encrypt, &bob_priv);
    println!("Alice Message Plaintext: {}", &alice_msg,);
    println!("Alice Message Decrypted: {}", &alice_msg_decrypt);

    let bob_msg = concat!(
        "Hi Alice, I have not. If I assume the hypothesis, then 'this sentence' is true, which means ",
        "'If this sentence is true, then Germany borders China' is true. So, 'this sentence is true' ",
        "is true. From this we conclude, 'Germany borders China'."
    );

    let bob_msg_encrypt = rsa_encrypt(&bob_msg, &alice_pub);
    let bob_msg_decrypt = rsa_decrypt(&bob_msg_encrypt, &alice_priv);
    println!("Bob Message Plaintext: {}", &bob_msg,);
    println!("Bob Message Decrypted: {}", &bob_msg_decrypt);
}
