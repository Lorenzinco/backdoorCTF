#!/usr/bin/env python3
from pwn import *

#challenge info
address = ""
port = 1337

# debugging
gdb_args= """
continue
"""

e = ELF("./pizzeria_patched_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e



def conn():
    if args.REMOTE:
        r = remote(address,port)
    elif args.GDB:
        r = gdb.debug([e.path],gdb_args)
    else:
        r = process([e.path])

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()