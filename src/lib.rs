//! # Proof of Work
//!
//! A basic proof of work construction using the Blake3 cryptographic
//! hash function. The problem is, given an array of bytes, to come up
//! with a nonce of ten bytes such that the hash of these strings
//! concatenated has cost leading zeros.
//!
//! This crate can be used to increase the cost of using your API without
//! increasing the cost very much on the server side. Especially if you
//! have unwanted bots hitting your endpoints constantly, you might want
//! to do something like this rather than try to identify and stop them.

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
/// A single threaded nonce searcher. Using a thread local RNG, it repeatedly
/// randomizes a `NONCE_SIZE` size array of bytes, searching for one which,
/// when concatenated with the `bytes`, has a hash with at least as many leading
/// zeros as the `cost`. If we try more than `meter` nonces, we return
/// `Error::MeterOverdrawn`, and if the random generator fails we return `Error::Rand`
/// with whatever error caused the dysfunction.
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

/// Check if the nonce is a proof of work of sufficient cost for the given bytes.
pub fn satisfies(bytes: &[u8], nonce: [u8; NONCE_SIZE], cost: u32) -> bool {
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
        // assert_eq!(leading_zeros(b"\x02"), 2);
        // assert_eq!(leading_zeros(b"\x06"), 3);
        assert_eq!(leading_zeros(b"\x0f"), 4);
        // assert_eq!(leading_zeros(b"\x1f"), 5);
        assert_eq!(leading_zeros(b"\x01"), 7);
        assert_eq!(leading_zeros(b"\x00"), 8);
        assert_eq!(leading_zeros(b"\x00\x01"), 15);
        assert_eq!(leading_zeros(b"\x00\x00"), 16);
    }

    #[test]
    fn search_works() -> Result<(), Error> {
        let cost = 20;
        let meter = 100000000;
        let bytes = b"124124125124214121";
        let nonce = search(bytes, cost, meter)?;
        assert!(satisfies(bytes, nonce, cost));
        for _i in 1..5 {
            let nonce = search(bytes, cost, meter)?;
            assert!(satisfies(bytes, nonce, cost));
        }
        Ok(())
    }
}
