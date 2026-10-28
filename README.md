# Securing Digital Devices with Physical Unclonable Functions

Research software accompanying the PhD thesis *Securing Digital Devices with Physical Unclonable Functions* by Edoardo Liberati, Sapienza University of Rome.

This repository contains C implementations of cryptographic constructions based on Physical Unclonable Functions (PUFs), together with experimental programs for evaluating their correctness and performance.

## Projects

### [Fuzzy Extractors](fuzzy-extractors/)

Implementations of fuzzy extractors for deriving reproducible cryptographic keys from noisy inputs.

The project includes:

- **X-Lock (2024):** the original XOR-based fuzzy extractor.
- **X-Lock (2026):** a revised implementation of X-Lock.
- **Sample-then-Lock (STL):** an implementation of the construction by Canetti et al. used for comparison.

Both X-Lock implementations are preserved. The experimental results reported in the thesis refer to the original implementation.

See the [Fuzzy Extractors documentation](fuzzy-extractors/README.md) for further details.

### [PUF Combiner](puf-combiner/)

Implementation of a PUF combiner based on polynomial interpolation, designed to reproduce an enrolled key in the presence of faulty PUF candidates.

The project provides three reconstruction strategies:

- **Hashing:** identification and replacement of erroneous interpolation points.
- **Enumeration:** reconstruction through candidate point subsets.
- **Berlekamp–Welch:** algebraic error correction.

See the [PUF Combiner documentation](puf-combiner/README.md) for further details.

## Requirements

The projects target Unix-like systems and require:

- A C11-compatible compiler, such as GCC or Clang
- GNU Make
- OpenSSL development libraries
- Standard C math library (`libm`), required by Fuzzy Extractors

Optional development tools include `clang-format` for source formatting and compiler support for AddressSanitizer and UndefinedBehaviorSanitizer.

Alternatively, the provided Docker environment includes the dependencies required to build and test both projects.

## Build

Both projects can be compiled from the repository root:

```bash
make
```

Alternatively, each project can be compiled independently:

```bash
make -C fuzzy-extractors
make -C puf-combiner
```

The resulting executables are generated in the respective `bin/` directories.

Additional build targets, including `release`, `debug`, `check`, and `clean`, are available. Run `make help` for the complete list.

Build options, command-line parameters, and usage examples are documented in the individual projects.

## Docker

A [Dockerfile](Dockerfile) based on Ubuntu 24.04 is provided to simplify environment setup and improve reproducibility across different systems.

The container includes the required build dependencies and `clang-format`. Both projects are compiled during image creation.

Build the image from the repository root:

```bash
docker build -t puf-research .
```

Display the available commands:

```bash
docker run --rm puf-research
```

Run the predefined experimental checks:

```bash
docker run --rm puf-research make check
```

The container runs as an unprivileged user.
No local installation of the compiler, OpenSSL development libraries, or other build dependencies is required when using Docker.

## Experimental Scope and Security

The applications use synthetically generated inputs and simulated noise or faults.
In the accompanying PhD thesis, the fuzzy extractors are evaluated using both synthetic data and experimental PUF datasets, whereas the PUF Combiner is evaluated using simulated polynomial points to isolate its computational overhead.

The experimental datasets and the complete benchmarking procedures are not included in this repository.

This repository provides research prototypes intended for experimental evaluation and academic study.
The implementations have not undergone comprehensive security validation and should not be used in production systems without further analysis, appropriate parameter selection, and implementation hardening.

## Citation

If you use this repository in academic work, please cite the accompanying PhD thesis and the relevant publications associated with the implementations.

Citation metadata for the thesis is provided in [CITATION.cff](CITATION.cff). References to individual constructions are included in the corresponding project documentation.

## License

The software in this repository is licensed under the GNU General Public License v3.0 (GPL-3.0-only). See the [LICENSE](LICENSE) file for the full license text.

The accompanying PhD thesis is a separate work and remains *All rights reserved*.

