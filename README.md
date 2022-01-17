# Proof of Work

A simple proof of work algorithm using the Blake3 cryptographic hash function.

```rust
let cost = 22;
let bytes = b"Hello, world!";
let nonce = proof_of_work::single_threaded(bytes, cost, 100000);
assert!(proof_of_work::satisfies(bytes, nonce, cost));
```

## Use Cases

When you want to expose functionality to the outside world without allowing
bots to take advantage of it at any frequency, you must meter usage somehow. By
requesting that API calls come affixed with a proof of costly work associated with
the particular request, you can acheive this in a stateless way.

## References

- [Hashcash](http://www.hashcash.org/)
- Bitcoin
