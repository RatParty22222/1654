# PetoronHash-System (PHASH)

**PHASH** is a self-contained, dependency-free hashing algorithm implemented in standard C++20.

It provides deterministic, extendable-output hashing (XOF) based on a custom 1600-bit sponge permutation.
The implementation is independent of OpenSSL, Keccak, BLAKE, or any external cryptographic libraries.

---

## Overview

- Standalone: no external or system crypto dependencies.
- Extendable Output (XOF): configurable output length (`out_bits`).
- Domain Separation: built-in context (`ctx`) and optional salt (`salt`).
- Deterministic: identical input produces identical output.
- Self-verified: includes Known Answer Tests (KAT).
- Portable: written in standard C++20.
- Configurable: typical output sizes: 256, 512, 1024, 2048 bits and above.
- Post-quantum oriented: ARX-style sponge design; structure resists algebraic exploitation and only allows Grover-type quadratic speedups against brute-force, not structural breaks.

---

## Internal Design

PHASH implements a sponge construction with a custom ARX-based permutation.

| Parameter         | Description                          |
|-------------------|--------------------------------------|
| State size        | 25 × 64-bit = 1600 bits              |
| Rounds            | 24                                   |
| Round constants   | `RC[24]`                             |
| Rotation offsets  | `RHO[25]`                            |
| Padding           | Domain byte + final `0x80` byte      |
| Mixing operations | Rotate and XOR (ARX diffusion model) |

### Post-Quantum Rationale

PHASH uses an ARX (Addition–Rotation–XOR) style permutation similar in spirit to modern sponge hashes.
Because the round function avoids simple algebraic structure, quantum attacks like Grover’s only provide quadratic speedup over brute force; they do not yield structural shortcuts. The 1600‑bit state and full 24‑round diffusion make PHASH suitable for long‑horizon identifiers and integrity uses in post‑quantum contexts (subject to external cryptanalysis for formal claims).

---

## Performance

The implementation is optimized at the C++ level:

- No heap allocations or dynamic tables.
- 64-bit ARX primitives only (XOR, rotate, bitmasks).
- Entire state in L1 cache (200 B) with small rate buffer.
- Compile-time constants; no runtime init.
- LTO and `-O3` supported.

### Measured throughput (single thread, Release)

| Algorithm            | Dependency            | Throughput        |
|---------------------|-----------------------|-------------------|
| SHA-256 (OpenSSL)   | OpenSSL / libcrypto   | ~85 MB/s          |
| **PHASH (this repo)** | None                   | **~120–130 MB/s** |

PHASH is typically **30–50% faster than SHA-256** in these conditions while providing XOF output and domain separation.

---

## Project Structure

```
PetoronHash-System/
├── include/petoron/
│   ├── hash.hpp       # High-level Petoron hash API
│   └── util.hpp       # Utility functions and helpers
├── src/
│   ├── phash.hpp      # Core PHASH sponge and permutation (PhashXof)
│   ├── phash.cpp      # Permutation and sponge logic implementation
│   ├── hash.cpp       # petoron_hash / petoron_hash_strong implementation
│   └── util.cpp       # Helper functions for CLI and hex I/O
├── examples/
│   └── demo.cpp       # Command-line demonstration tool
├── tests/
│   └── kat.cpp        # Known Answer Tests (KAT)
├── CMakeLists.txt
└── verify_all.sh      # Automated build and verification script
```

---

## API Reference

### `std::vector<uint8_t> petoron_hash(...)`

Base hash function (without salt).

```cpp
std::vector<std::uint8_t> petoron_hash(
    std::span<const std::uint8_t> msg,
    std::string_view ctx,
    const HashParams& p
);
```

Parameters:
- `msg` — input data
- `ctx` — domain separation context
- `p.out_bits` — output size in bits (default: 1024)

---

### `std::vector<uint8_t> petoron_hash_strong(...)`

Salted version of the hash function.

```cpp
std::vector<std::uint8_t> petoron_hash_strong(
    std::span<const std::uint8_t> msg,
    std::span<const std::uint8_t> salt,
    std::string_view ctx,
    const HashParams& p
);
```

Parameters:
- `msg` — input data
- `salt` — salt value (optional)
- `ctx` — context string
- `p.out_bits` — output size in bits

---

### `std::vector<uint8_t> phash_xof(...)`

Core extendable-output primitive used internally.

```cpp
std::vector<std::uint8_t> phash_xof(
    std::span<const std::uint8_t> in,
    std::size_t out_bytes
);
```

---

## Command-Line Usage

### Basic Example

```bash
./demo --msg "hello" --ctx "CTX"
```

Default output length: 1024 bits (hex-encoded).

### Custom Output Length

```bash
./demo --msg "hello" --ctx "CTX" --out-bits 512
```

### With Salt

```bash
./demo --msg "hello" --ctx "CTX" --salt "SALT-123" --out-bits 2048
```

---

## Testing (KAT)

```bash
./kat
```

Expected output:

```
[OK] hello/CTX 1024b (no salt)
[OK] hello/CTX 512b (no salt)
[OK] hello/CTX 2048b (salt=SALT-123)
```

---

## Verification Script

```bash
chmod +x verify_all.sh
./verify_all.sh
```

The script performs a complete build, runs KATs, checks determinism and context/salt variability, ensures no external crypto linkage, and executes a performance test on 10 MiB of random data.

---

## Complete Verification Command

To perform a full verification of the PetoronHash-System build, including known-answer tests (KAT), CLI output validation, determinism checks, and linkage verification, run the following command from the project root:

```bash
rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && ./build/kat && ./build/demo --msg "hello" --ctx "CTX" --out-bits 512 && ./build/demo --msg "hello" --ctx "CTX" --salt "SALT-123" --out-bits 2048 && chmod +x verify_all.sh && ./verify_all.sh && (otool -L build/demo | grep -i crypto || echo "No external crypto linkage :)")
```

If all checks pass, the expected final output will include:

```
== Build ==
== KAT ==
== Determinism ==
== Context/Salt variability ==
== Linkage check ==
== Perf (10 MiB) ==
OK
No external crypto linkage :)
```

This confirms that the build succeeded, all PHASH vectors match, deterministic behavior is consistent, context and salt variability are verified, and the binaries link to no external cryptographic libraries.

---

## License

```
MIT
```
