# arweave_rs
Rust based implementation of the Arweave mining software (WIP)

This project makes use of git submodules.

The first time you compile, or perhaps after a big update after a git pull, you need to update the submodules:

```bash
git submodule update --init --recursive
```
Then compile using:
```bash 
cargo build
```
