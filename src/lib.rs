//! # Proof of Work
//!
//! The classic proof of work system based on a cryptogarphic hash function,
//! in this case Blake3. To be explicit, a proof of work for some `bytes : &[u8]`
//! and `cost : u32` is a `nonce : [u8; NONCE_SIZE]` such that the Blake3
//! hash of `nonce` appended to `bytes` has at least `cost` leading zeros.
//!
//! This crate provides functionality for `search`ing and `verify`ing this
//! sort of proof of work.

pub const NONCE_SIZE: usize = 10usize;

/// Errors which can occur in searching for a proof of work.
#[derive(Debug)]
pub enum Error {
    Rand(rand::Error),
    MeterOverdrawn,
}

impl From<rand::Error> for Error {
    fn from(error: rand::Error) -> Error {
        Error::Rand(error)
    }
}

/// # Proof search
///
/// Searches through random `nonce`s by guessing random length `NONCE_SIZE`
/// arrays and checking if the hash of the `nonce` appended to `bytes` has a
/// Blake3 hash with at least `cost` leading zeros. In other words, this
/// searches for a valid proof of work for the given `bytes` at the given
/// `cost`.
///
/// If we search through `meter` `nonce`s, we return an `Error::MeterOverdrawn`
/// error.
pub fn search(bytes: &[u8], cost: u32, meter: u32) -> Result<[u8; NONCE_SIZE], Error> {
    use rand::Fill;
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; NONCE_SIZE];
    let mut counter = 0;
    loop {
        nonce.try_fill(&mut rng)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&nonce);
        hasher.update(bytes);
        let hash = hasher.finalize();
        if leading_zeros(hash.as_bytes()) >= cost {
            break;
        }
        counter += 1;
        if counter > meter {
            return Err(Error::MeterOverdrawn);
        }
    }
    Ok(nonce)
}

/// # Proof verification
///
/// This checks that the hash of the `nonce` appended to the `bytes` has
/// a Blake3 hash with `cost` or more leading zeros. In other words, it verifies
/// wheher or not this nonce constitutes a valid proof of work for this cost
/// and input.
pub fn verify(bytes: &[u8], nonce: [u8; NONCE_SIZE], cost: u32) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&nonce);
    hasher.update(bytes);
    let hash = hasher.finalize();
    leading_zeros(hash.as_bytes()) >= cost
}

/// Compute the number of leading zeros of the given byte array.
pub fn leading_zeros(bytes: &[u8]) -> u32 {
    let mut count = 0;
    let mut ptr = bytes;
    loop {
        if ptr.len() == 0 {
            break;
        } else {
            let lz = ptr[0].leading_zeros();
            ptr = &ptr[1..];
            count += lz;
            if lz < 8 {
                break;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn leading_zeros_works() {
        assert_eq!(leading_zeros(b"\x4f"), 1);
        assert_eq!(leading_zeros(b"\x2f"), 2);
        assert_eq!(leading_zeros(b"\x1f"), 3);
        assert_eq!(leading_zeros(b"\x0f"), 4);
        assert_eq!(leading_zeros(b"\x06"), 5);
        assert_eq!(leading_zeros(b"\x02"), 6);
        assert_eq!(leading_zeros(b"\x01"), 7);
        assert_eq!(leading_zeros(b"\x00"), 8);
        assert_eq!(leading_zeros(b"\x00\x4f"), 9);
        assert_eq!(leading_zeros(b"\x00\x01"), 15);
        assert_eq!(leading_zeros(b"\x00\x00"), 16);
        assert_eq!(leading_zeros(&[0; 10000]), 10000 * 8);
        assert_eq!(leading_zeros(&[255; 10000]), 0);
    }

    #[test]
    fn search_works() -> Result<(), Error> {
        let cost = 20;
        let meter = 100000000;
        let bytes = b"124124125124214121";
        let nonce = search(bytes, cost, meter)?;
        assert!(verify(bytes, nonce, cost));
        for _i in 1..5 {
            let nonce = search(bytes, cost, meter)?;
            assert!(verify(bytes, nonce, cost));
        }
        Ok(())
    }
}
