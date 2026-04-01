# AEG — Automatic Exploit Generation

A Python reimplementation of the Automatic Exploit Generation system described in:

> Avgerinos et al., "AEG: Automatic Exploit Generation", NDSS 2011

This tool takes a vulnerable binary as input and automatically produces a working exploit payload — with **zero human guidance**.

---

## Pipeline

```
Binary
  → ASLR Check
  → Vulnerability Discovery (symbol scan + CFG fallback)
  → Symbolic Execution (angr)
  → Offset Solving (Z3)
  → NX Detection
  → Payload Synthesis (shellcode / ret2libc / ROP chain)
  → Automated Verification (pwntools)
  → Shell ✓
```

---

## Requirements

- Ubuntu 18.04 / 20.04 (32-bit support)
- Python 3.8+
- angr, pwntools

---

## Install

```bash
python3 -m venv angr-env
source angr-env/bin/activate
pip install angr
pip install pwntools
pip install capstone==4.0.2
pip install unicorn==1.0.2rc4
```

---

## Setup

```bash
# Disable ASLR (required for targets 1-8)
echo 0 > /proc/sys/kernel/randomize_va_space

# Make permanent
echo 'kernel.randomize_va_space = 0' >> /etc/sysctl.conf

# Activate virtual environment
source ~/angr-env/bin/activate
```

---

## Usage

```bash
python aeg.py <binary> [args]
```

### Examples

```bash
python aeg.py ./target           # NX off            → shellcode
python aeg.py ./target2 hello    # NX off            → shellcode
python aeg.py ./target3 Apple    # NX off            → shellcode
python aeg.py ./target4 Banana   # NX off            → shellcode
python aeg.py ./target5          # NX off            → shellcode
python aeg.py ./target6          # decoy             → rejected
python aeg.py ./target7          # NX on             → ROP chain
python aeg.py ./target8          # NX on, no system() → ROP chain
```

### Run payload manually

```bash
(cat payload_target; cat) | ./target
```

---

## Compile Targets

```bash
# Targets 1-6 — NX disabled (shellcode path)
gcc -m32 -fno-stack-protector -z execstack -o target  target.c
gcc -m32 -fno-stack-protector -z execstack -o target2 target2.c
gcc -m32 -fno-stack-protector -z execstack -o target3 target3.c
gcc -m32 -fno-stack-protector -z execstack -o target4 target4.c
gcc -m32 -fno-stack-protector -z execstack -o target5 target5.c
gcc -m32 -fno-stack-protector -z execstack -o target6 target6.c

# Target 7 — NX enabled (ROP chain path)
gcc -m32 -fno-stack-protector -o target7 target7.c

# Target 8 — NX enabled, no system() (ROP chain path)
gcc -m32 -fno-stack-protector -fno-pie -no-pie -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -o target8 target8.c

# Target 9 — ASLR bypass attempt (keep ASLR on)
gcc -m32 -fno-stack-protector -fno-pie -no-pie -o target9 target9.c
```

---

## Target Suite

| Target | Description | Technique | Offset | Result |
|--------|-------------|-----------|--------|--------|
| target1 | Simple `gets()` overflow | Shellcode | 76 | Shell ✓ |
| target2 | Overflow behind argc check | Shellcode | 76 | Shell ✓ |
| target3 | Overflow behind nested conditions | Shellcode | 76 | Shell ✓ |
| target4 | Smaller buffer | Shellcode | 44 | Shell ✓ |
| target5 | Overflow behind loop condition | Shellcode | 76 | Shell ✓ |
| target6 | Large buffer, no overflow (decoy) | — | N/A | Rejected ✓ |
| target7 | NX enabled | ROP chain | 76 | Shell ✓ |
| target8 | NX enabled, no system() | ROP chain | 76 | Shell ✓ |
| target9 | ASLR enabled, info leak | ASLR bypass | 76 | Experimental |

---

## Decision Engine

```
NX disabled?
    → Shellcode injection

NX enabled + system() in PLT?
    → ret2libc

NX enabled + no system()?
    → ROP chain (execve syscall via gadgets)
```

The tool profiles the binary automatically and selects the right technique — no human input required.

---

## Security Mitigations

| Mitigation | Targets 1-6 | Target 7-8 | Target 9 |
|------------|------------|------------|---------|
| ASLR | Disabled | Disabled | **Enabled** |
| Stack Canary | Disabled | Disabled | Disabled |
| NX | Disabled | **Enabled** | Enabled |

---

## Extensions Beyond Base Implementation

| Extension | Description |
|-----------|-------------|
| **ROP chains** | Chains gadgets from libc to call `execve` — bypasses NX without system() |
| **ret2libc** | Calls `system("/bin/sh")` via libc — bypasses NX |
| **NX auto-detection** | Reads `PT_GNU_STACK`, chooses technique automatically |
| **system() PLT detection** | Uses `objdump` to decide ret2libc vs ROP |
| **ASLR detection** | Warns and exits if ASLR is on |
| **CFG fallback scanner** | Finds dangerous calls if no `vulnerable()` symbol |
| **Exploit verification** | pwntools auto-confirms shell spawned |
| **ASLR bypass (experimental)** | Two-stage exploit: leak libc address → calculate base → exploit |

---

## Architecture

```
Analysis Layer
  ├── check_aslr()                  — ASLR detection
  ├── find_vulnerable_function()    — symbol scan + CFG fallback
  ├── is_nx_enabled()               — NX detection via readelf
  ├── is_system_available()         — system() PLT detection via objdump
  └── find_offset()                 — symbolic execution + Z3 solving

Payload Layer
  ├── build_shellcode_payload()     — NX off
  ├── build_ret2libc_payload()      — NX on + system()
  └── build_rop_payload()           — NX on, no system()

Verification Layer
  └── verify_exploit()              — automated shell confirmation

Decision Engine
  └── generate_payload()            — ties everything together
```

---

## ASLR Bypass (Experimental)

Implemented in `aslr_bypass.py` as a separate module.

**Concept:** Two-stage exploit using an info leak primitive:

```
Stage 1: puts(GOT[puts]) → leaks real runtime address of puts()
         calculate: libc_base = leaked_addr - puts_offset
Stage 2: ret2libc with real runtime addresses → shell
```

**Why it's hard:**
- Requires a binary with both overflow AND info leak primitive
- Two-stage coordination — any crash between stages fails
- libc version dependency — offset must match exactly
- Buffering issues — stdout must be unbuffered for leak to arrive

**Status:** Framework fully implemented. PLT detection issue on Ubuntu 20.04 with modern gcc prevents clean execution.

---

## Differences from Original Paper

| Feature | Original Paper | This Project |
|---------|---------------|--------------|
| Language | C++ / LLVM / KLEE | Python / angr / Z3 |
| Analysis | Source + Binary | Binary only |
| Bug types | Multiple | Stack overflow |
| NX bypass | Yes | Yes (ret2libc + ROP) |
| Verification | Manual | Automated (pwntools) |
| Search strategy | Preconditioned SE | Directed + CFG fallback |
| ASLR bypass | Attempted | Experimental |

---

## References

- Avgerinos et al., "AEG: Automatic Exploit Generation", NDSS 2011
- [angr documentation](https://docs.angr.io)
- [Z3 SMT Solver](https://github.com/Z3Prover/z3)
- [pwntools documentation](https://docs.pwntools.com)
