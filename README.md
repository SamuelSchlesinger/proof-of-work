# Proof of Work

A simple proof of work algorithm using the Blake3 cryptographic hash function.

```rust
let cost = 22;
let bytes = b"Hello, world!";
let nonce = proof_of_work::single_threaded(bytes, cost, 100000);
assert!(proof_of_work::satisfies(bytes, nonce, cost));
```

See the crate documentation for more details.
