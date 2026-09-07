# EROR: Efficient Repliable Onion Routing with Strong Provable Privacy

This repository contains the code for the prototype implementation of EROR from our PETS 2027 paper.

> [!note]
> There is a separate `ARTIFACT-APPENDIX.md` file for the PETS artifact review.

## Requirements

* Rust nightly
* Python with `matplotlib` and `cbor2`

## Usage

Print onion sizes:

```bash
cargo run +nightly --example=onion_sizes
```

Run benchmarks:

```bash
cargo +nightly criterion
```

Generate graphs:

```bash
jupyter nbconvert --to notebook --execute --inplace --allow-errors Benchmarks.ipynb
```

## License

Our code is licensed under the MIT license, see `LICENSE` for more information.

The `sphinx/` directory contains a vendored copy of Nym's Sphinx implementation
(https://github.com/nymtech/sphinx). It is licensed under the Apache 2 license.
The original README and LICENSE have been preserved.
