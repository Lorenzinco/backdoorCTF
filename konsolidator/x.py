#!/usr/bin/env python3
from pwn import *

#challenge info
address = ""
port = 1337

context.terminal = ['tmux','new-window']

# debugging
gdb_args= """
continue
"""

e = ELF("./konsolidator_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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