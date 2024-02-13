## Project Goals

The goals for `arweave_rs` are two fold:  to be a building block for Arweave based projects in production and to educate developers about the underlying consensus rules of the protocol. 
## Communication Guidelines

When writing pull requests, filing issues, commenting or giving feedback use the following rules of thumb:

- Be objective - minimize emotional language.
- Be as precise and concise as possible - respect peoples time.
- Value plain language over technical terms - write for a broad audience.

Most of all, be kind and patient.
## Code Contributions

As the project grows, there will be an increasing number of projects that depend on it. Strive to minimize changes to public interfaces that would force projects that depend on `arweave_rs` to refactor. Whenever possible, propose changes to public interfaces early and get strong consensus from the community before applying them.

Code should value readability above most considerations. Agonize over variable names. Strive for self-documenting code that also happens to be well-documented and littered with examples.

The [rustdoc](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html) book has a good introduction to writing documentation.

## Versioning

As many crates in the rust ecosystem, the `arweave-rs` crates follow [semantic versioning]. This means bumping PATCH version on bug fixes that don't break backwards compatibility, MINOR version on new features and MAJOR version otherwise (MAJOR.MINOR.PATCH). Versions < 1.0 are considered to have the format 0.MAJOR.MINOR, which means bumping MINOR version for all non-breaking changes.

For checking whether a change is SemVer-breaking, please refer to https://doc.rust-lang.org/cargo/reference/semver.html.

Bumping versions should be done in a separate PR from regular code changes PR.

[semantic versioning]: https://semver.org/

