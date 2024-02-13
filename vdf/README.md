# VDF Validation
Arweave uses a VDF as a cryptographic clock that limits the speed at which hashes may be produced.

In order to prove the block producer followed the speed limit set by the VDF the checkpoints for the VDF are included in the block.

These checkpoints allow a block recipient to verify the VDF steps are accurate by computing all the checkpoints in parallel across multiple cores.

## Validation
There are two phases to VDF step validation. When a miner recieves a block they validate the "last step checkpoints" which takes a few milliseconds and serve as a quick pre-validation.

Depending on the block time, it may take 30 or more seconds to fully validate the checkpoints a 2+ minute VDF in parallel.

This package implements both the pre-validation and full validation of the VDF checkpoings.
