# ReallyMe Crypto Poseidon2

This crate hashes byte preimages with the BN254 Poseidon2 parameters used by
ReallyMe ZK's Noir circuits. The fixed permutation has width 4, rate 3,
S-box exponent 5, 8 full rounds, and 56 partial rounds. Each input byte is
absorbed as one field element. The capacity element starts at the input byte
count multiplied by 2^64. A final permutation runs for every input length,
including zero and multiples of three. The output is a 32-byte canonical,
big-endian BN254 field element.

Inputs are limited to 515 bytes, the largest reviewed byte-preimage bound in
the ZK circuits. Callers retain ownership of input buffers and should zeroize
private preimages after use. The output wrapper zeroizes its bytes on drop.

The test vectors were produced by the pinned `bn254_blackbox_solver` oracle in
`reallyme/zk` (`crates/noir-witness-core/src/bin/poseidon2-bounded-fixture.rs`,
Noir revision `75061fab15986eedee4e7d9104ff87dd9fa4ca10`). They cover full
and partial sponge blocks and the maximum accepted preimage.
