use num_bigint::BigInt;
use num_bigint::RandBigInt;
use num_bigint::Sign;
use num_traits::Signed;


use crate::semigroup::{power, Integer};

impl Integer for BigInt {
    fn half(&self) -> Self {
        self.clone() >> 1
    }

    fn odd(&self) -> bool {
        self.bit(0)
    }

    fn zero() -> Self {
        BigInt::ZERO
    }

    fn one() -> Self {
        num_traits::One::one()
    }

    fn inc(&self) -> Self {
        self.clone() + 1u32
    }

    fn dec(&self) -> Self {
        self.clone() - 1u32
    }
}

fn modulo_multiply_fn(modulus: &BigInt) -> impl Fn(&BigInt, &BigInt) -> BigInt {
    let modulus = modulus.clone();

    move |a: &BigInt, b: &BigInt| (a * b) % &modulus
}

// fermat inverse modulo p (p is prime)
pub fn multiplicative_inverse_fermat(a: &BigInt, p: &BigInt) -> BigInt {
    power(a.clone(), p - 2u32, modulo_multiply_fn(&p))
}

// fermat test for prime
pub fn fermat_test(p: &BigInt, witness: &BigInt) -> bool {
    let remainder = power(witness.clone(), p - 1u32, modulo_multiply_fn(&p));
    remainder == BigInt::from(1u32)
}

// miller rabin test for prime
fn miller_rabin_test(p: &BigInt, q: &BigInt, k: &BigInt, w: &BigInt) -> bool {
    let mut x = power(w.clone(), q.clone(), modulo_multiply_fn(p));
    if x == BigInt::from(1u32) || x == p - 1u32 {
        return true;
    }

    let mut i = k.clone();
    while i > BigInt::ZERO {
        i = i.dec();
        x = power(x.clone(), x.clone(), modulo_multiply_fn(p));
        if x == p - 1u32 {
            return true;
        }
        if x == BigInt::from(1u32) {
            return false;
        }
    }
    false
}

pub fn primality_test(p: &BigInt) -> bool {
    let mut rng = rand::thread_rng();
    let w = rng.gen_bigint(p.bits()).abs();
    let mut q = p - 1u32;
    let mut k = BigInt::from(1u32);
    while q.even() {
        q = q.half();
        k = k.inc();
    }

    miller_rabin_test(p, &q, &k, &w)
}

pub fn random_prime(bits: usize) -> BigInt {
    let mut rng = rand::thread_rng();
    let mut p = rng.gen_bigint(bits as u64).abs();

    while !primality_test(&p) {
        p = p + 1u32;
    }

    p
}

pub fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let mut x = a.clone();
    let mut y = b.clone();
    while y != BigInt::from(0u32) {
        let t = y.clone();
        y = x % y;
        x = t;
    }
    x
}

// Returns (x, gcd(a, b)) such that x*a + y*b = gcd(a, b)
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt) {
    let mut u = BigInt::one();
    let mut v = BigInt::zero();

    let mut a = a.clone();
    let mut b = b.clone();

    while b != BigInt::zero() {

        let q = &a / &b;
        let r = &a % &b;

        let m = &u - &q * &v;

        a = b;
        b = r;
        u = v;
        v = m;
        //println!("a: {}, b: {}, u: {}, v: {}", a, b, u, v);
    }

    (u, a)
}

fn multiplicative_inverse(a: &BigInt, n: &BigInt) -> BigInt {
    let (x, g) = extended_gcd(a, n);

    if g != BigInt::one() {
        BigInt::zero()
    } else if x < BigInt::zero() {
        x + n
    } else {
        x
    }
}

fn random_coprime(n: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let mut e = rng.gen_bigint(n.bits()).abs() % n;
    while gcd(&e, n) != BigInt::from(1u32) {
        e = e + 1u32 % n;
    }
    e
}

pub fn rsa_keygen(bits: usize) -> (BigInt, BigInt, BigInt) {
    let p1 = random_prime(bits);
    let p2 = random_prime(bits);
    let n = p1.clone() * p2.clone();
    let phi = (p1 - 1u32) * (p2 - 1u32);
    let pubkey = random_coprime(&phi);
    let prvkey = multiplicative_inverse(&pubkey, &phi);
    (n, pubkey, prvkey)
}

pub fn rsa_encode(m: &BigInt, pubkey: &BigInt, n: &BigInt) -> BigInt {
    power(m.clone(), pubkey.clone(), modulo_multiply_fn(n))
}

pub fn rsa_decode(c: &BigInt, prvkey: &BigInt, n: &BigInt) -> BigInt {
    power(c.clone(), prvkey.clone(), modulo_multiply_fn(n))
}

pub fn rsa_encode_message(message: &str, pubkey: &BigInt, n: &BigInt) -> Vec<u8> {

    //println!("Encoding message: {:?}", message.len());
    // TODO: fix chunk size and padding
    let enc = message.as_bytes().chunks(8).map(|chunk|  {
        let m = BigInt::from_bytes_be(Sign::Plus, chunk);
        assert!(&m < n);
        let c = rsa_encode(&m, pubkey, n);
        let (s,v) = c.to_bytes_be();

        assert!(s == Sign::Plus);

        let pad = vec![0u8; 16 - v.len()];
        pad.into_iter().chain(v.into_iter())
        
    }).flatten().collect::<Vec<_>>();

    //println!("Encoded message: {:?}", enc.len());

    enc

}

pub fn rsa_decode_message(message: &Vec<u8>, prvkey: &BigInt, n: &BigInt) -> String {
    message.chunks(16).map(|chunk| {
        let c = BigInt::from_bytes_be(Sign::Plus, chunk);
        assert!(&c < n);
        let m = rsa_decode(&c, prvkey, n);
        let s = String::from_utf8(m.to_bytes_be().1).unwrap();
      //  println!("Decoded chunk: {:?}", s);
        s
    }).collect::<Vec<_>>().join("")
}

#[cfg(test)]
mod test {

    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn test_multiplicative_inverse_fermat() {
        let a = 3u32.to_bigint().unwrap();
        let p = 11u32.to_bigint().unwrap();
        assert_eq!(
            multiplicative_inverse_fermat(&a, &p),
            4u32.to_bigint().unwrap()
        );
    }

    #[test]
    fn test_fermat_test() {
        let p = 11u32.to_bigint().unwrap();
        let witness = 2u32.to_bigint().unwrap();
        assert_eq!(fermat_test(&p, &witness), true);
    }

    #[test]
    fn test_rabin_miller_test() {
        let p = 11u32.to_bigint().unwrap();
        let q = 5u32.to_bigint().unwrap();
        let k = 2u32.to_bigint().unwrap();
        let w = 2u32.to_bigint().unwrap();
        assert_eq!(miller_rabin_test(&p, &q, &k, &w), true);
    }

    #[test]
    fn test_rabin_miller_test_false() {
        let p = 2793u32.to_bigint().unwrap();
        let q = 349u32.to_bigint().unwrap();
        let k = 2u32.to_bigint().unwrap();
        let w = 150u32.to_bigint().unwrap();
        assert_eq!(miller_rabin_test(&p, &q, &k, &w), false);
    }

    #[test]
    fn test_random_prime() {
        let p = random_prime(512);
        println!("Random prime: {}", p);
        assert_eq!(primality_test(&p), true);
    }

    #[test]
    fn test_extended_gcd() {
        let a = 240u32.to_bigint().unwrap();
        let b = 46u32.to_bigint().unwrap();
        let (x, g) = extended_gcd(&a, &b);
        assert_eq!(x, -9u32.to_bigint().unwrap());
        assert_eq!(g, 2u32.to_bigint().unwrap());
    }

    #[test]
    fn test_multiplicative_inverse() {
        let a = 3u32.to_bigint().unwrap();
        let n = 10u32.to_bigint().unwrap();
        assert_eq!(multiplicative_inverse(&a, &n), 7u32.to_bigint().unwrap());
    }

    #[test]
    fn test_rsa_keygen() {
        let (n, pubkey, prvkey) = rsa_keygen(16);
        println!("n: {}", n);
        println!("pubkey: {}", pubkey);
        println!("prvkey: {}", prvkey);
    }

    #[test]
    fn test_rsa_encode_decode() {
        let m = 1234567890u32.to_bigint().unwrap();
        let (n, pubkey, prvkey) = rsa_keygen(64);
        println!("n: {}", n);
        println!("pubkey: {}", pubkey);
        println!("prvkey: {}", prvkey);

        let c = rsa_encode(&m, &pubkey, &n);
        let m2 = rsa_decode(&c, &prvkey, &n);
        assert_eq!(m, m2);
    }

    #[test]
    fn test_rsa_message_encode_decode() {
        let msg = "Hello, World!";
        let (n, pubkey, prvkey) = rsa_keygen(64);
        println!("n: {}", n);
        println!("pubkey: {}", pubkey);
        println!("prvkey: {}", prvkey);

        let enc = rsa_encode_message(msg, &pubkey, &n);

        println!("Encrypted message: {:?}", enc);
        let dec = rsa_decode_message(&enc, &prvkey, &n);
        assert_eq!(msg, dec);
    }
}
