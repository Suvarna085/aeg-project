# AEG — Automatic Exploit Generation

A simplified implementation of the Automatic Exploit Generation system described in:

> Avgerinos et al., "AEG: Automatic Exploit Generation", NDSS 2011

This tool takes a vulnerable binary as input and automatically produces a working exploit payload — with no human guidance.

---

## How It Works

1. **ASLR Check** — verifies ASLR is disabled before proceeding
2. **Vulnerability Discovery** — locates `vulnerable()` by symbol name; falls back to CFG scan for dangerous calls (`gets`, `strcpy`, `scanf`, etc.) if not found
3. **Symbolic Execution** — runs the binary symbolically via angr until EIP becomes attacker-controlled
4. **Offset Finding** — constrains EIP to `0x41414141` and uses Z3 to solve for the exact input
5. **NX Detection** — checks `PT_GNU_STACK` to determine if the stack is executable
6. **Payload Synthesis** — automatically selects technique:
   - NX off → shellcode injection
   - NX on → ret2libc (`system("/bin/sh")`)
7. **Exploit Verification** — launches the binary with the payload via pwntools and confirms shell access

---

## Pipeline

```
Binary → Vulnerability Discovery → Symbolic Execution → EIP Control → Offset → Payload → Verified Shell
```

---

## Requirements

- Ubuntu 18.04 / 20.04 (32-bit support)
- Python 3.8+
- angr
- pwntools

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

## Disable ASLR

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
python aeg.py ./target7        # NX enabled — uses ret2libc
```

### Run payload manually

```bash
(cat payload_target; cat) | ./target
```

---

## Compile Targets

```bash
# NX disabled (targets 1-6) — shellcode path
gcc -m32 -fno-stack-protector -z execstack -o target  target.c
gcc -m32 -fno-stack-protector -z execstack -o target2 target2.c
gcc -m32 -fno-stack-protector -z execstack -o target3 target3.c
gcc -m32 -fno-stack-protector -z execstack -o target4 target4.c
gcc -m32 -fno-stack-protector -z execstack -o target5 target5.c
gcc -m32 -fno-stack-protector -z execstack -o target6 target6.c

# NX enabled (target7) — ret2libc path
gcc -m32 -fno-stack-protector -o target7 target7.c
```

---

## Target Suite

| Target | Description | Technique | Offset | Result |
|--------|-------------|-----------|--------|--------|
| target1 | Simple `gets()` overflow | Shellcode | 76 | Shell ✓ |
| target2 | Overflow behind argc check | Shellcode | 76 | Shell ✓ |
| target3 | Overflow behind nested conditions | Shellcode | 76 | Shell ✓ |
| target4 | Smaller buffer, different offset | Shellcode | 44 | Shell ✓ |
| target5 | Overflow behind loop condition | Shellcode | 76 | Shell ✓ |
| target6 | Large buffer, no overflow (decoy) | — | N/A | Rejected ✓ |
| target7 | NX enabled, ret2libc | ret2libc | 76 | Shell ✓ |

---

## Security Mitigations

| Mitigation | Status | Method |
|------------|--------|--------|
| ASLR | Disabled | `echo 0 > /proc/sys/kernel/randomize_va_space` |
| Stack Canaries | Disabled | `-fno-stack-protector` |
| NX / Exec Stack | Disabled (t1–t6) | `-z execstack` |
| NX / Exec Stack | **Enabled (t7)** | default gcc — bypassed via ret2libc |

---

## Extensions Beyond Base Implementation

| Feature | Description |
|---------|-------------|
| ret2libc | Automatic payload synthesis for NX-enabled binaries |
| NX detection | Reads `PT_GNU_STACK` segment to choose payload type automatically |
| ASLR detection | Warns and exits if ASLR is on |
| Auto symbol scanner | Falls back to CFG scan if no `vulnerable()` symbol found |
| Exploit verification | Uses pwntools to confirm shell spawned automatically |

---

## Differences from Original AEG Paper

| Feature | Original Paper | This Project |
|---------|---------------|--------------|
| Language | C++ (LLVM/KLEE) | Python (angr/Z3) |
| Analysis | Source + Binary | Binary only |
| Bug types | Multiple | Stack overflow only |
| Payload | Shellcode + ret2libc | Shellcode + ret2libc |
| Verification | Manual | Automated (pwntools) |
| Search strategy | Preconditioned SE | Directed (vulnerable()) + CFG fallback |

---

## References

- Avgerinos et al., "AEG: Automatic Exploit Generation", NDSS 2011
- [angr documentation](https://docs.angr.io)
- [Z3 SMT Solver](https://github.com/Z3Prover/z3)
- [pwntools documentation](https://docs.pwntools.com)
