# Proof of Work

A simple proof of work algorithm using the Blake3 cryptographic hash function.

```rust
let cost = 22;
let bytes = b"Hello, world!";
let meter = 10000000;
let nonce = proof_of_work::single_threaded(bytes, cost, meter);
assert!(proof_of_work::verify(bytes, nonce, cost));
```

The main point is: we present some `bytes` and we say that a "proof of work"
for some `cost` is a `nonce : [u8; NONCE_SIZE]` such that the hash of `nonce`
concatenated to `bytes` has `cost` leading zeros.

To `verify` such a proof, we compute the hash and check if it has `cost` leading
zeros. To `search` for such a proof, we continually generate random `nonce`s until
we guess one which constitutes a proof of work. That is to say, we randomly
guess until we get it right. Given that this could go on forever, we pass in a
`meter : u32` in order to stop after a certain number of attempts.

## Use Cases

When you want to expose functionality to the outside world without allowing
bots to take advantage of it at any frequency, you must meter usage somehow. By
requesting that API calls come affixed with a proof of costly work associated with
the particular request, you can acheive this in a stateless way.

## Why Blake3?

- Efficient on consumer hardware
- No known ASIC implementations
- Awesome team behind it
- Inverting seems incredibly hard to me, though that hardly counts as a security review

## References

- [Hashcash](http://www.hashcash.org/)
- [Bitcoin](https://bitcoin.org/en/)
- [Blake3](https://github.com/BLAKE3-team/BLAKE3)
