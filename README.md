# Merkle Proof Web Service API

## Usage

Use `cargo run` to start the server. The server runs on http://0.0.0.0:3000.

* GET `/root`: returns the root of the Merkle tree as a hex string, beginning
with `0x`.
* GET `/proof/:id`: returns the Merkle proof for the user with user ID `id`.
The response has the following format:
```json
{
    "balance": BALANCE_OF_USER,
    "proof": [
        [LEFT_OR_RIGHT, HEX_HASH],
        ...
    ]
}
```
where `BALANCE_OF_USER` is the user's balance in integers. `LEFT OR RIGHT`
is either the integer 0 (left node) or 1 (right node), and `HEX_HASH`
is a hex string containing the node's hash value (again, begining with `0x`).

If the user with ID `id` does not exist, a 404 NOT FOUND is returned.

## External Libraries

I used the following external libraries (Rust crates):

* [sha2](https://docs.rs/sha2/latest/sha2/): for the SHA256 hash;
* [data-encoding](https://crates.io/crates/data-encoding): to encode byte arrays/vectors as hex strings;
* [serde](https://serde.rs/) and serde_json: to serialize data (particularly Merkle proof) as JSON;
* [axum](https://crates.io/crates/axum): web framework;
* [tokio](https://tokio.rs/): asynchronous Rust runtime required by Axum.

I have confirmed that all of them are actively maintained.

## Design

I tried to be as generic as possible in my design, using the full power of
Rust's type system.

The Merkle tree implementation is generic over the hashing algorithm used.
Since different hashing algorithms result in hashes of different lengths,
that is also taken care of by a constant `HASH_SIZE` associated with the
`HashAlgorithm` trait. New hashing algorithms and hashing schemes
can be supported simply by implementing the trait.

Initially I tried implementing the Merkle tree as a single sequence (Rust
`Vector`), as the Merkle tree we build is always a complete binary tree and
it is well-known that complete binary trees are representable as arrays.
However, I soon realized that to efficiently and concisely implement Merkle
proof and Merkle proof verification, a layered representation (each layer
of the tree is a sequence i.e. Rust `Vector`, and the tree is represented
as a sequence of layers) is much easier to work with while adding very little
extra indirection (only `O(log(n))` more memory accesses, essentially), so
I decided that this is more desirable.

Since the tree is not incremental, no mutative methods are exposed, although
I use mutation internally to build the tree efficiently.

For the purposes of this task, we use an in-memory implementation for
the database. However, in production, the database is very large, and
might be stored, e.g. in a file, in a SQL or NoSQL database, or
even on the cloud. Also, should the addition of new users become frequent,
one may want to switch to an incremental Merkle tree implementation.
Therefore, the database implementation is generic, and so is the associated
Merkle tree implementation.

For our task, however, we just use a hash table as the database, and the
regular, in-memory Merkle tree implementation described above is used.
Practically, for a tree with `n` leaves, the Merkle tree will have
approximately `2 * n` nodes, which means storing the Merkle tree will take up
`64 * n` bytes of space. For a practical value of `n`, it is generally viable
to store the tree in-memory using my implementation.

The web API is implemented as an Axum app. I handled the non-existent user
case manually.