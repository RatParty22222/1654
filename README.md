# 1654 — encryption system based on PetoronHash

## Abstract

**1654** is a self-contained cryptographic vault engine designed for deterministic, dependency-free data protection.
The system implements a custom cryptographic architecture based on a **1024-bit internal state** and uses **PetoronHash** as its sole cryptographic core.

The primary design goal of 1654 is **full control over cryptographic behavior**, eliminating reliance on external libraries, opaque primitives, and third-party trust assumptions.

---

## Conceptual Model (Safe Analogy)

1654 is best understood as a **cryptographic safe**, not as a conventional encrypted file.

A physical safe:
- exists as a single sealed object
- reveals nothing about its contents without the correct key
- allows controlled operations: placing items inside, retrieving them, inspecting structure

1654 follows the same model.

A `.1654` file is a sealed vault with a defined internal structure.  
You do not manipulate ciphertext directly — you interact with the vault through explicit operations.

---

## Cryptographic Core

### PetoronHash

1654 uses **PetoronHash** as its only cryptographic primitive.

PetoronHash is responsible for:
- key material derivation
- entropy expansion
- internal state diffusion
- integrity coupling

No external cryptographic libraries are used.

PetoronHash repository:
https://github.com/01alekseev/PetoronHash-System

---

## 1024-Bit Internal State

1654 is built around a **1024-bit internal cryptographic state**.

This refers to:
- wide internal buffers
- 1024-bit diffusion layers
- wide-state transformations

The design prioritizes:
- resistance to partial-state disclosure
- strong diffusion properties
- long-term safety margin
- post-quantum research suitability

Performance is explicitly secondary to structural robustness :))

---

## Command Interface

1654 exposes an explicit command-line interface for operating on encrypted vaults.

General form:

    1654 <command> [args...]

---

## Commands

### encrypt <path>

Creates a new vault from a file or directory.

Safe analogy: manufacture a new safe and place the selected items inside.

Output:
- Produces a `.1654` vault file

---

### decrypt <vault.1654>

Restores the full contents of a vault to the host filesystem.

Safe analogy: open the safe and unload everything.

---

### view <vault.1654>

Displays the internal structure and metadata of the vault.

Safe analogy: inspect the safe’s inventory without removing items.

---

### extract <vault.1654> <paths...>

Extracts selected internal paths from the vault.

Safe analogy: retrieve specific items from the safe.

---

### add <vault.1654> <paths...>

Appends new files or directories to an existing vault.

Safe analogy: open the safe, insert new items, reseal.

---

### delete <vault.1654> <paths...>

Performs a logical deletion of selected objects.
The deletion affects the index and visibility, not necessarily immediate data erasure.

Safe analogy: cross items off the inventory list.

---

### edit <vault.1654> ...

Replaces an existing object.
Semantically equivalent to add + delete.

Safe analogy: swap an item inside the safe.

---

### stealth+ <vault.1654> <paths...>

Hides selected objects from view operations.

Safe analogy: conceal items inside the safe without removing them.

---

### stealth- <vault.1654> <paths...>

Reveals previously hidden objects.

---

### transfer ...

The transfer command represents an advanced internal mode designed around the vault-to-vault interaction model.

vault → vault, inside a cryptographic circuit
You don't lay the contents of the vault out on the table, but rather transfer items from one safe to another through a secure gateway.

Unlike traditional workflows that rely on decrypting data into the host operating system and re-encrypting it afterward, transfer is conceptually intended to operate entirely within the cryptographic domain of vaults.

---

## Verification

Integrity verification is performed automatically.
The tool produces output only in case of failure.

This minimizes unnecessary information leakage.

---

## Design Principles

- Zero external dependencies
- Deterministic behavior
- Explicit operations
- Auditable cryptographic surface
- Vault-oriented data model

---

## Summary

1654 is a deterministic, dependency-free cryptographic vault engine.

It is:
- a sealed safe, not just encryption
- built on PetoronHash
- based on a 1024-bit internal state
- designed for users who want full control and transparency


## Installation & Build (New Machine)

### Requirements

- A C++20-capable compiler (e.g., AppleClang / Clang / GCC / MSVC with C++20 enabled)
- CMake (recommended: 3.20+)

> 1654 is dependency-free by design.

### Build Steps

Example (macOS / Linux-style terminal):

```bash
cd ~/downloads/1654
rm -rf build
mkdir build && cd build
cmake ..
cmake --build .
```

### Self-test

Run the self-test binary (recommended after a fresh install):

```bash
./1654_selftest --bin ./1654
```

---

## Quickstart Example

The following example encrypts a file into a vault and then extracts it back.

### 1) Encrypt a file into a vault

```bash
./build/1654 encrypt a.txt --out ~/1654/vault.1654
```

### 2) Extract the file back

```bash
./build/1654 extract ~/1654/vault.1654 a.txt --out .
```

---

### Help menu:
- path — 1654/build
```
./1654 help
```
---

## Notes on Paths and Output

- `encrypt <path>` accepts a file or a directory.
- `--out` defines the output vault path for `encrypt`, and the destination directory for `extract`.
- `extract <vault.1654> <paths...>` accepts one or multiple internal paths.

---

Petoron | Ivan Alekseev | MIT license 
