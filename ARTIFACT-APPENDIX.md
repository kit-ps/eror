# Artifact Appendix

Paper title: **EROR: Efficient Repliable Onion Routing with Strong Provable Privacy**

Requested Badge(s):
  - [X] **Available**
  - [X] **Functional**
  - [X] **Reproduced**

## Description

This artifact belongs to the PETS 2027 paper

> EROR: Efficient Repliable Onion Routing with Strong Provable Privacy
> (Andrey Bozhko, Michael Klooß, Andy Rupp, Daniel Schadt, Thorsten Strufe, Christiane Weis)

It contains the prototype implementation of EROR as we used it in our paper for
benchmarks, as well as the graph generation code.

### Security/Privacy Issues and Ethical Concerns (Required for all badges)

Our artifact does not pose any risk to the reviewer's machine.

## Basic Requirements

For both sections below, if you are giving reviewers remote access to special
hardware (e.g., Intel SGX v2.0) or proprietary software (e.g., Matlab R2025a)
for the purpose of the artifact evaluation, do not provide these instructions
here but rather in the corresponding submission field on HotCRP.

### Hardware Requirements

Can run on a laptop (No special hardware requirements).

The results in the paper were produced on a laptop with

* AMD Ryzen 5 5625U (6x 3.40 GHz)
* 16 GiB RAM

### Software Requirements (Required for Functional and Reproduced badges)

* Fedora Linux 44
* git 2.55.0 (via `dnf install git`)
* rustup 1.29.0 (via https://rustup.rs/)
* Rust `rustc 1.100.0-nightly (908501772 2026-08-30)` (via rustup)
* Python 3.14.7 (via `dnf install python3`)
* python-virtualenv (via `dnf install python3-virtualenv`)
* cargo-criterion 1.1.0 (via `cargo install cargo-criterion`)

The list of Rust dependencies is listed in `Cargo.toml`, and the list of Python
packages in `requirements.txt`.

We provide a `Dockerfile`, in which case the only requirement on the host is a
Docker-compatible container environment.

### Estimated Time and Storage Consumption (Required for Functional and Reproduced badges)

30s + 10min

- Human time: 5 min
- Compute time: 15 min
- Disk space: 1.5 GiB

## Environment


### Accessibility

We host our artifact on Github at https://github.com/kit-ps/eror

You can clone the repository via `git`:

```bash
git clone https://github.com/kit-ps/eror.git
```

### Set Up the Environment

We suggest to use the `Dockerfile` to quickly set up a correct environment:

```bash
git clone https://github.com/kit-ps/eror.git
cd eror
docker build -t eror .

# We assume that all commands below are run in a container started like this:
docker run --rm -ti -v "$(pwd):/eror" -w /eror -p 8888:8888 eror
```

If you want to run the artifact without Docker, we suggest to set up a virtual
environment for the Python packages:

```bash
git clone https://github.com/kit-ps/eror.git
cd eror
virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Testing the Environment

Within the Docker container (or a properly set up host), run the following
command:

```bash
cargo +nightly test
```

## Artifact Evaluation


### Main Results and Claims


#### Main Result 1: EROR incurs a linear overhead in onion size

When increasing either the path length or the payload size, the size of EROR
onions grows linearly. This is shown in Figure 9, and reproduced by Experiment
1.


#### Main Result 2: EROR processes onions fast

Overall, onion operations (creation & processing) take less than 1ms. There is
a linear increase in processing time when increasing the path length, and a
very small linear increase when increasing the payload size. Compared to
Sphinx, EROR onion processing is about twice as fast, but onion creation is 50%
slower. These results are shown in Figures 7 and 8, and reproduced by
Experiment 2.

### Experiments

#### Experiment 1: Onion sizes

- Time: 30 seconds compute / 1 min human

In this experiment, we examine the onion sizes of EROR and Sphinx under various
parameters. We vary the path length and the payload size, and output the size
of the resulting onion.

We expect a linear increase in the output size when increasing either the path
length or the payload size.

The experiment can be run using the following command and will print the sizes
on the console:

```bash
./onion_sizes.sh
```

Output:

```
Path length | Payload size [bytes] | EROR Onion size [bytes] | Sphinx Onion size [bytes]
============+======================+=========================+==========================
1           | 0                    | 304                     | 233                      
1           | 128                  | 560                     | 361                      
1           | 256                  | 816                     | 489                      
1           | 512                  | 1328                    | 745                      
1           | 1024                 | 2352                    | 1257                     
1           | 2048                 | 4400                    | 2281                     
1           | 4096                 | 8496                    | 4329
[...]
```

#### Experiment 2: Benchmarks

- Time: 15 minutes compute / 1 min human

In this experiment, we benchmark various routines of the EROR and Sphinx
formats to see their computational cost.

You can run the benchmarks via

```bash
cargo +nightly criterion
```

The timings will be output to the console. Additionally, the values will be
saved in a machine-readable format, which is later used by the graph generation
code.

#### Wrap-up: Graph generation

- Time: 3 minutes

We provide the Jupyter notebook that we have used to generate the graphs in the
paper.

The notebook has the values of Experiment 1 hardcoded (see Section "Comparison
with Sphinx"). The values correspond to the values of path length 5 and payload
sizes 0, 128, 256, 512, 1024.

The notebook automatically loads the values of Experiment 2.

The notebook generates

- Figure 7 (saved as `Images/benchmark-proc-onion.pdf`)
- Figure 8 (left side as `Images/benchmark-form-onion.pdf`, right side as `Images/benchmark-form-onion-hops.pdf`)
- Figure 9 (left side as `Images/packet-sizes.pdf`, right side as `Images/packet-sizes-path.pdf`)

You can either run and explore the notebook interactively:

```bash
jupyter notebook --allow-root --ip 0.0.0.0 "Benchmark Graphs.ipynb"
```

> [!note]
> The `--allow-root` and `--ip` options are needed inside the container. You
> can omit them if running directly on the host.

Or simply generate all graphs with one command:

```bash
jupyter nbconvert --to notebook --execute --inplace --allow-errors Benchmarks.ipynb
```

## Limitations

Benchmark results are dependent on the hardware and may show fluctuations.

## Notes on Reusability

Our prototype is implemented as a standard Rust crate and may be reused by
other works or prototypes.
