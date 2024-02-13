# Validator
This libary package cointains the components neccessary to validate that an Arweave block was produced by Proof-of-work consensus and met or exceeded the difficulty setting of the network at the time it was produce.

Because Arweave uses a "Proof-of-useful-work" mechanisim where the hashes computed to produce a block are calcuated from Arweaves historical data, thes steps for validaing consensus are more elaborate then simply comparing a hash.

## Validation Tests

To validate an Arweave block header you need the block header currently being validated, and the previous block header.

The steps are as follows

https://github.com/ThePeopleOfTheNetwork/arweave_rs/blob/ee2fa244de829b78a02517784abb161247790cb5/validator/src/lib.rs#L18-L157

Huge thanks to [janekolszak](https://github.com/janekolszak) for his [go work](https://github.com/warp-contracts/syncer/blob/main/src/utils/arweave/block.go#L17) on computing the `block_hash` for validation. 
Also to [CalebEverett](https://github.com/CalebEverett) for the merkle tree building blocks which I borrowed from [arloader](https://github.com/CalebEverett/arloader). Both were insturmental in completing the validation steps.

## Merkle Proofs
There are two merkle proofs in a block header. The `tx_path` and the `data_path`.  The `tx_path` is the path though a merkle tree composed of all the `data_roots` of all the transactions in the block. It proves that the transaction the chunk belongs to was part of the block. 
The `data_path` is the path though the merkle tree composed of all the chunks in the transaction. It maps the path from the transactions `data_root` to a specific chunk. In thise case, the chunk provided as part of the `poa` or `poa2` data.
