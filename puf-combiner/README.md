# PUF Combiner

C implementation of a Physical Unclonable Function (PUF) combiner based on polynomial interpolation over a finite field.

This project accompanies the PhD thesis *Securing Digital Devices with Physical Unclonable Functions*.
It provides three reconstruction strategies, supporting mathematical and cryptographic utilities, and a command-line application for experimental evaluation.

## Reconstruction Strategies

| Strategy | CLI name | Description |
| --- | --- | --- |
| Hashing | `hashing` | Identifies faulty candidate responses using cryptographic hashes and replaces the corresponding interpolation points. |
| Enumeration | `enumeration` | Enumerates combinations of interpolation points and verifies the reconstructed value against a stored hash. |
| Berlekamp–Welch | `berlekamp-welch` | Uses algebraic error correction to reconstruct the polynomial from potentially corrupted points. |

During enrolment, the combiner interpolates a polynomial from `n` candidate responses.
The enrolled value is obtained by evaluating the polynomial at zero, while `m` additional interpolation points are generated to support subsequent reconstruction.

During reproduction, the selected strategy attempts to recover the enrolled value from the available interpolation points, even when some candidate responses have been corrupted.

The reconstruction capabilities and computational requirements depend on the selected strategy and the available redundancy.

## Requirements

- A C11-compatible compiler, such as GCC or Clang
- GNU Make
- OpenSSL development libraries

Optional tools include `clang-format` for source formatting and compiler support for AddressSanitizer and UndefinedBehaviorSanitizer.

## Build

From the `puf-combiner/` directory, build the application with:

```bash
make
```

The executable is generated at `bin/main`.

Additional build targets are available:

| Command | Description |
| --- | --- |
| `make release` | Build with release settings |
| `make debug` | Build with debug settings |
| `make asan` | Build with AddressSanitizer and UndefinedBehaviorSanitizer |
| `make check` | Run predefined experimental checks under sanitisers |
| `make run` | Build and execute the application |
| `make format-check` | Check source formatting without modifying files |
| `make format` | Format C source files |
| `make clean` | Remove generated build artefacts |
| `make help` | Display available Makefile targets |

Compiler warnings can be treated as errors using `WERROR=1`:

```bash
make release WERROR=1
```

## Usage

The experimental application provides a common command-line interface for all three reconstruction strategies.

Display the available options:

```bash
./bin/main --help
```

### Hashing

```bash
./bin/main \
  --strategy hashing \
  --trials 1000 \
  --n 5 \
  --m 2 \
  --t 1
```

### Enumeration

```bash
./bin/main \
  --strategy enumeration \
  --trials 1000 \
  --n 5 \
  --m 2 \
  --t 1
```

### Berlekamp–Welch

```bash
./bin/main \
  --strategy berlekamp-welch \
  --trials 1000 \
  --n 5 \
  --m 2 \
  --t 1
```

### Command-line options

| Option | Description | Default |
| --- | --- | --- |
| `--strategy` | Reconstruction strategy: `hashing`, `enumeration`, or `berlekamp-welch` | `hashing` |
| `--trials` | Number of experimental trials | `1000` |
| `--n` | Number of PUF candidates | `3` |
| `--m` | Number of additional interpolation points | `2` |
| `--t` | Number of candidate responses selected for corruption per trial | `0` |
| `-h`, `--help` | Display command-line help | — |

The `--trials` and `--n` parameters must be positive integers, while `--m` and `--t` must be non-negative integers.

The application enforces additional constraints, including `t <= n`, `n + m < P`, and `m <= n` for enumeration, where `P` is the finite-field modulus.

The maximum number of candidates is also limited by the bitmask representation used internally.
The experimental application additionally limits the total number of interpolation points (`n + m`) to 256 to bound stack memory usage.

The default parameters are defined in [`include/constants.h`](include/constants.h):

| Constant | Value | Description |
| --- | --- | --- |
| `NUM_ATTEMPTS` | `1000` | Number of experimental trials |
| `N` | `3` | Number of PUF candidates |
| `M` | `2` | Number of additional points |
| `T` | `0` | Number of faulty candidates |
| `P` | `1000000007` | Prime modulus of the finite field |
| `HASH_BYTES` | `32` | SHA-256 hash length in bytes |

The reconstruction strategy is selected at runtime. Its default value is hashing.

## Experimental Evaluation

The application evaluates the correctness and computational performance of the reconstruction strategies under simulated faults.

Each experiment follows these steps:

1. Generate synthetic candidate responses over the finite field.
2. Execute the enrolment procedure to obtain the enrolled value and additional interpolation points.
3. Select `t` candidate responses and replace their values to simulate faults.
4. Execute the selected reconstruction strategy.
5. Compare the recovered value with the enrolled value and collect the experimental results.

The hashing and enumeration strategies can recover up to `m` faulty candidate responses under the modelled assumptions. The Berlekamp–Welch strategy has a theoretical error-correction bound of `floor(m / 2)` for arbitrary errors, provided the relevant algebraic conditions hold.

These bounds describe the constructions and do not guarantee that every parameter combination accepted by the application will lead to successful reconstruction.

### Experimental output

The application prints a comma-separated record without a header:

```text
n,m,t,time_enroll,time_reconstruct,errors,attempts
```

| Field | Description |
| --- | --- |
| `n` | Number of PUF candidates |
| `m` | Number of additional interpolation points |
| `t` | Number of candidate responses selected for corruption |
| `time_enroll` | Cumulative enrolment CPU time |
| `time_reconstruct` | Cumulative reconstruction CPU time |
| `errors` | Number of unsuccessful trials |
| `attempts` | Total number of experimental trials |

An unsuccessful trial is one in which enrolment fails, reconstruction reports an error, or the reconstructed value differs from the enrolled value.

On Unix-like systems, CPU times are reported in nanoseconds and accumulated across the trials.
The measurements include user and system CPU time, rather than wall-clock time.
Trials that fail during enrolment do not contribute to the reconstruction time.

The application reports experimental failures in the `errors` field.
A nonzero error count does not, by itself, cause the executable to return a failure exit status.

### Experimental scope and reproducibility

The experimental application uses synthetically generated PUF candidate responses and simulated faults to evaluate the correctness and computational performance of the reconstruction strategies.
In accordance with the methodology described in the accompanying PhD thesis, the evaluation isolates the computational overhead of the combiner, excluding the execution of the underlying physical PUFs and individual fuzzy extractors.

The application uses the standard C `rand()` generator, initialised from system time on Unix-like systems, and does not expose deterministic random seed configuration.

For reproducibility, record:

- The repository revision
- Compiler and OpenSSL versions
- Operating system and hardware platform
- Build configuration
- Command-line parameters
- Experimental outputs

The implementation uses the prime modulus `P = 1000000007` for experimental testing and performance evaluation.
This choice allows the reconstruction strategies to be evaluated using relatively inexpensive finite-field arithmetic.

The security limitations of this configuration are acknowledged.
In particular, the resulting key contains at most approximately 30 bits of entropy, and applying SHA-256 does not increase its entropy.
These limitations concern the experimental implementation rather than the theoretical construction, which is defined over a generic finite field.
A practical deployment would require an appropriately sized field, suitable arithmetic operations, and further security validation.

## Checks and Formatting

Run the predefined checks using:

```bash
make check
```

This target builds the application with AddressSanitizer and UndefinedBehaviorSanitizer and executes representative configurations for all three reconstruction strategies.

Source formatting can be checked or applied with:

```bash
make format-check
make format
```

Both commands require `clang-format`.
The `format` target modifies source files, while `format-check` does not.

The predefined checks are intended to identify common runtime problems and regressions.
They do not constitute exhaustive functional testing or cryptographic security verification.

## Project Structure

```text
puf-combiner/
├── include/              # Headers and constants
├── src/                  # Reconstruction algorithms and utilities
├── test/
│   └── main.c            # Experimental application
├── Makefile
└── README.md
```

The `build/` and `bin/` directories are generated during compilation.

## Citation

The construction and its experimental evaluation are discussed in the accompanying PhD thesis, *Securing Digital Devices with Physical Unclonable Functions*.

Citation metadata for the thesis is provided in [CITATION.cff](../CITATION.cff).

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0-only). See the repository's [LICENSE](../LICENSE) file for the full license text.
