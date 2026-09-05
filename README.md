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
