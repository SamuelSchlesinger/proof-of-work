mod proof_of_work {
    pub const NONCE_SIZE: usize = 10usize;

    pub fn pow(bytes: &[u8], cost: u32) -> [u8; NONCE_SIZE] {
        use rand::Fill;
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; NONCE_SIZE];
        loop {
            nonce
                .try_fill(&mut rng)
                .expect("Should be able to fill nonce with random data");
            let mut hasher = blake3::Hasher::new();
            hasher.update(&nonce);
            hasher.update(bytes);
            let hash = hasher.finalize();
            if leading_zeros(hash.as_bytes()) >= cost {
                break;
            }
        }
        nonce
    }

    fn leading_zeros(bytes: &[u8]) -> u32 {
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
    #[test]
    fn leading_zeros_works() {
        assert_eq!(leading_zeros(b"\x00"), 8);
        assert_eq!(leading_zeros(b"\x0f"), 4);
        assert_eq!(leading_zeros(b"\x01"), 7);
        assert_eq!(leading_zeros(b"\x00\x00"), 16);
    }
}

#[cfg(test)]
mod tests {
    use super::proof_of_work::*;

    #[test]
    fn it_works() {
        println!("{:?}", pow(b"1241", 22));
    }
}
