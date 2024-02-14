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
## MacOS Build
The above instructions should be sufficient.

## Windows Build
There are a few dependencies to build on Windows.

`openssl-sys` - In [vendored mode](https://docs.rs/openssl/latest/openssl/) `open ssl` is compiled and statically linked. To compile it you will need to have `perl` and `perl-core` installed. Installing the latest version of [strawberry perl](https://strawberryperl.com/releases.html) will suffice. Note: The first time this dependency is built on Windows it can take several minutes.

`randomX` - You will need Visual Studio 2019 with the "Desktop developmennt with C++" Workload selected. Make sure `C++ Build tools and core features` are installed. Specifically the `C++ CMake tools for Windows`.

## License
This project is licensed under either of

    MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
    Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)

at your option.
