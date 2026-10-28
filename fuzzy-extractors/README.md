# Fuzzy Extractors

C implementations of fuzzy extractors for generating and reproducing cryptographic keys from noisy inputs.

This project accompanies the PhD thesis *Securing Digital Devices with Physical Unclonable Functions*.
It provides a common fuzzy-extractor interface, three implementations, supporting cryptographic utilities, and a command-line application for experimental evaluation.

## Implementations

| Implementation | CLI name | Description |
| --- | --- | --- |
| X-Lock (2024) | `xlock-2024` | Original XOR-based X-Lock construction. |
| X-Lock (2026) | `xlock-2026` | Revised X-Lock construction with separate key derivation and helper data authentication. |
| Sample-then-Lock | `stl` | Digital-locker-based fuzzy extractor used for comparison. |

The two X-Lock implementations are maintained separately to preserve the original construction and its subsequent developments.

X-Lock (2024) corresponds to the published construction and is the version used for the experimental evaluation reported in the thesis.
X-Lock (2026) incorporates subsequent improvements and is provided separately for further experimentation.

## Requirements

- A C11-compatible compiler, such as GCC or Clang
- GNU Make
- OpenSSL development libraries
- Standard C math library (`libm`)

Optional tools include `clang-format` for source formatting and compiler support for AddressSanitizer and UndefinedBehaviorSanitizer.

## Build

From the `fuzzy-extractors/` directory, build the application with:

```bash
make
```

The executable is generated at `bin/experiment`.

Additional build targets are available:

| Command | Description |
| --- | --- |
| `make release` | Build with release settings |
| `make debug` | Build with debug settings |
| `make asan` | Build with AddressSanitizer and UndefinedBehaviorSanitizer |
| `make check` | Run predefined experimental checks under sanitisers |
| `make format-check` | Check source formatting without modifying files |
| `make format` | Format C source files |
| `make clean` | Remove generated build artefacts |
| `make help` | Display available Makefile targets |

Compiler warnings can be treated as errors using `WERROR=1`:

```bash
make release WERROR=1
```

## Usage

The experimental application provides a common command-line interface for all three implementations.

Display the available options:

```bash
./bin/experiment --help
```

### X-Lock (2024)

```bash
./bin/experiment \
  --impl xlock-2024 \
  --prng xorshift32 \
  --w-len-bytes 1024 \
  --ber 7.5 \
  --trials 1000 \
  --locks-n 21 \
  --xor-n 3
```

### X-Lock (2026)

```bash
./bin/experiment \
  --impl xlock-2026 \
  --prng xorshift32 \
  --w-len-bytes 1024 \
  --ber 7.5 \
  --trials 1000 \
  --locks-n 21 \
  --xor-n 3
```

### Sample-then-Lock

```bash
./bin/experiment \
  --impl stl \
  --prng xorshift32 \
  --w-len-bytes 1024 \
  --ber 2.5 \
  --trials 1000 \
  --locks-n 51
```

### Command-line options

| Option | Description |
| --- | --- |
| `--impl` | Fuzzy-extractor implementation: `xlock-2024`, `xlock-2026`, or `stl` |
| `--prng` | Pseudorandom sampling generator |
| `--w-len-bytes` | Reference input length in bytes |
| `--ber` | Simulated bit error rate, expressed as a percentage between 0 and 100 |
| `--trials` | Number of reproduction trials |
| `--locks-n` | Number of locks |
| `--xor-n` | Number of XOR operations per lock bit (required for X-Lock only) |
| `-h`, `--help` | Display command-line help |

All numerical parameters except `--ber` must be positive integers.

Supported pseudorandom generators are:

- `xorshift32`
- `lfsr32`
- `constant`
- `markov`
- `bucket`

These generators are used for experimental sampling and are not substitutes for cryptographically secure random generators.
The reference input is generated separately using a system-backed random source.

**Note:** The `constant` generator is primarily useful for diagnostic purposes.
When multiple bit flips are requested, repeated selection of the same position can violate the expected Hamming distance and cause the experiment to terminate.
Other generators are recommended for ordinary BER experiments.

## Experimental Evaluation

The application evaluates the ability of each fuzzy extractor to reproduce an enrolled key from noisy inputs.

Each experiment follows these steps:

1. Generate a random reference input.
2. Execute the fuzzy-extractor generation procedure to obtain a key and the associated helper data.
3. Generate noisy versions of the reference input according to the specified BER.
4. Execute the reproduction procedure for each trial.
5. Compare the reproduced key with the enrolled key and collect the experimental results.

The number of bit flips per trial is computed as:

```text
round((BER / 100) * 8 * w_len_bytes)
```

For the standard sampling generators, bit positions are selected without replacement, ensuring the intended Hamming distance.

### Experimental output

The application reports:

| Output | Description |
| --- | --- |
| `bit_flips/trial` | Number of input bits modified in each trial |
| `successes` | Trials in which the reproduced key matches the enrolled key |
| `reproduce errors` | Trials in which the reproduction procedure returns an error |
| `avg input HD` | Average Hamming distance between reference and noisy inputs, in bits |

A reproduction that returns a key different from the enrolled key without reporting an error is not counted among either the successes or the reproduction errors. Consequently, these two counts are not necessarily complementary.

### Experimental scope and reproducibility

The experimental application uses synthetically generated inputs and simulated bit errors according to the specified BER.
It does not directly process experimental PUF datasets.

The accompanying PhD thesis presents a broader evaluation of X-Lock (2024), using both synthetic inputs and experimental datasets.
These datasets and the complete benchmarking procedures are not included in this repository.

The results characterise the behaviour of the implemented constructions under controlled experimental conditions. They do not independently establish cryptographic security or performance on physical PUF devices.

The command-line application does not currently support deterministic random seed configuration. Results may therefore vary between executions.

For reproducibility, record the repository revision, build configuration, execution environment, command-line parameters, and experimental outputs.

## Checks and Formatting

Run the predefined checks using:

```bash
make check
```

This target builds the application with AddressSanitizer and UndefinedBehaviorSanitizer and executes representative configurations for all three implementations.

Source formatting can be checked or applied with:

```bash
make format-check
make format
```

Both commands require `clang-format`. The `format` target modifies source files, while `format-check` does not.

The predefined checks are intended to identify common runtime problems and regressions. They do not constitute exhaustive functional testing or cryptographic security verification.

## Project Structure

```text
fuzzy-extractors/
├── app/
│   └── experiment/             # Experimental application
├── include/
│   ├── common/                 # Common utilities
│   ├── crypto/                 # Cryptographic utilities
│   └── fuzzy_extractor/        # Fuzzy-extractor interfaces
├── src/
│   ├── common/
│   ├── crypto/
│   └── fuzzy_extractor/
│       ├── core/
│       └── implementations/
│           ├── stl/
│           ├── xlock-2024/
│           └── xlock-2026/
├── Makefile
└── README.md
```

The `build/` and `bin/` directories are generated during compilation.

## References

**X-Lock**

```bibtex
@inproceedings{liberati2024xlock,
    author    = {Liberati, Edoardo and Visintin, Alessandro and
                 Lazzeretti, Riccardo and Conti, Mauro and
                 Uluagac, Selcuk},
    title     = {{X-Lock}: A Secure {XOR}-Based Fuzzy Extractor
                 for Resource Constrained Devices},
    booktitle = {Applied Cryptography and Network Security},
    series    = {Lecture Notes in Computer Science},
    volume    = {14583},
    pages     = {183--210},
    year      = {2024},
    publisher = {Springer},
    doi       = {10.1007/978-3-031-54770-6_8}
}
```

**Sample-then-Lock**

```bibtex
@inproceedings{canetti2016reusable,
    author    = {Canetti, Ran and Fuller, Benjamin and
                 Paneth, Omer and Reyzin, Leonid and
                 Smith, Adam},
    title     = {Reusable Fuzzy Extractors for Low-Entropy
                 Distributions},
    booktitle = {Advances in Cryptology -- EUROCRYPT 2016},
    series    = {Lecture Notes in Computer Science},
    volume    = {9665},
    pages     = {117--146},
    year      = {2016},
    publisher = {Springer},
    doi       = {10.1007/978-3-662-49890-3_5}
}
```

Citation metadata for the thesis is provided in [CITATION.cff](../CITATION.cff).

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0-only). See the repository's [LICENSE](../LICENSE) file for the full license text.
