# AEG — Automatic Exploit Generation (Course Project)

A simplified implementation of the Automatic Exploit Generation system
described in the paper:

> Avgerinos et al., "AEG: Automatic Exploit Generation", NDSS 2011

---

## Overview

This tool takes a vulnerable binary as input and automatically produces
a working exploit payload as output — with no human guidance.

It uses **symbolic execution** (via angr) and **SMT solving** (via Z3)
to mathematically reason about program behavior and calculate the exact
input needed to hijack the instruction pointer (EIP) and spawn a shell.

---

## Pipeline
```
Binary → Find vulnerable() → Symbolic Execution → EIP Control → Offset → Payload → Shell
```

---

## Requirements

- Ubuntu 18.04 / 20.04 (32-bit support)
- Python 3.8+
- angr
- Z3

### Install
```bash
python3 -m venv angr-env
source angr-env/bin/activate
pip install angr
```

### Disable ASLR
```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

---

## Usage
```bash
python aeg.py <binary> [args]
```

### Examples
```bash
python aeg.py ./target
python aeg.py ./target2 hello
python aeg.py ./target3 Apple
python aeg.py ./target4 Banana
python aeg.py ./target5
python aeg.py ./target6
```

Then run the generated payload:
```bash
(cat payload_target; cat) | ./target
```

Type `whoami` when the shell spawns.

---

## Target Suite

| Target   | Description                          | Offset | Result   |
|----------|--------------------------------------|--------|----------|
| target1  | Simple gets() overflow               | 76     | Shell ✓  |
| target2  | Overflow behind argc check           | 76     | Shell ✓  |
| target3  | Overflow behind nested conditions    | 76     | Shell ✓  |
| target4  | Smaller buffer, different offset     | 44     | Shell ✓  |
| target5  | Overflow behind loop condition       | 76     | Shell ✓  |
| target6  | Large buffer, no overflow (decoy)    | N/A    | Rejected ✓ |

---

## Compile Targets
```bash
gcc -m32 -fno-stack-protector -z execstack -o target  target.c
gcc -m32 -fno-stack-protector -z execstack -o target2 target2.c
gcc -m32 -fno-stack-protector -z execstack -o target3 target3.c
gcc -m32 -fno-stack-protector -z execstack -o target4 target4.c
gcc -m32 -fno-stack-protector -z execstack -o target5 target5.c
gcc -m32 -fno-stack-protector -z execstack -o target6 target6.c
```

---

## Security Mitigations Disabled

This project runs in a controlled environment with the following
mitigations explicitly disabled to isolate the core AEG logic:

| Mitigation        | Status   | Disabled By                          |
|-------------------|----------|--------------------------------------|
| ASLR              | Disabled | echo 0 > /proc/sys/kernel/randomize_va_space |
| Stack Canaries    | Disabled | -fno-stack-protector                 |
| NX / Exec Stack   | Disabled | -z execstack                         |

---

## How It Works

### 1 — Vulnerability Discovery
The tool locates the `vulnerable()` function symbol in the binary
and starts symbolic execution directly there, bypassing all
conditions in `main()`.

### 2 — Exploit Predicate
Angr runs symbolically until EIP becomes attacker-controlled.
The tool constrains EIP to `0x41414141` and asks Z3 to solve
for the exact input — this gives the precise offset to the
return address on the stack.

### 3 — Payload Synthesis
The tool builds a payload:
```
[padding] [return address] [NOP sled] [shellcode]
```
The shellcode calls `execve("/bin/sh")` — spawning a shell.

---

## Differences from Original AEG Paper

| Feature         | Original Paper       | This Project              |
|-----------------|----------------------|---------------------------|
| Language        | C++ (LLVM/KLEE)      | Python (angr/Z3)          |
| Analysis        | Source + Binary      | Binary only               |
| Bug types       | Multiple             | Stack overflow only       |
| Defenses        | Attempts bypass      | Disabled                  |
| Search strategy | Preconditioned SE    | Directed (vulnerable())   |

---

## References

- Avgerinos et al., "AEG: Automatic Exploit Generation", NDSS 2011
- [angr documentation](https://docs.angr.io)
- [Z3 SMT Solver](https://github.com/Z3Prover/z3)
