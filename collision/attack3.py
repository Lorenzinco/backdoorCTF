import hashlib
import os
import numpy as np
from PIL import Image
import random
from multiprocessing import Pool

def collide_files(d1, d2):
    import sys
    import struct

    def comment_start(size):
        return b"\xff\xfe" + struct.pack(">H", size)

    def comment(size, s=""):
        return comment_start(size) + s + b"\0" * (size - 2 - len(s))

    def comments(s, delta=0):
        return comment(len(s) + delta, s)



    with open("jpg1.bin", "rb") as f:
        block1 = f.read()
    with open("jpg2.bin", "rb") as f:
        block2 = f.read()

    # skip the signature, split by scans (usually the biggest segments)
    c1 = d1[2:].split(b"\xff\xda")

    if max(len(i) for i in c1) >= 65536 - 8:
        print("ERROR: The first image file has a segment that is too big!" +
        "Maybe save it as progressive or reduce its size/scans.")
        sys.exit()

    ascii_art = b"".join(b"""
^^^^^^^^^^^^
/==============\\
|* JPG image  *|
|     with     |
|  identical   |
|   -prefix    |
| MD5 collision|
|              |
|  by          |
| Marc Stevens |
|  and         |
|Ange Albertini|
|  in 2018     |
|*            *|
\\==============/
vvvvvvvvvvvvvvvv""".splitlines())

    suffix = b"".join([
    # fake comment to jump over the first image chunk (typically small)
    b"\xff\xfe",
        struct.pack(">H", 0x100 + len(c1[0]) - 2 + 4),
        ascii_art, # made to fit 

    # the first image chunk
    c1[0],

    # creating a tiny intra-block comment to host a trampoline comment segment
    b"".join([
        b"".join([
            # a comment over another comment declaration
            comments(
            b"\xff\xfe" +
            # +4 to reach the next intra-block
            struct.pack(">H", len(c) + 4 + 4),
            delta=2),
            b"\xff\xda",
            c
        ]) for c in c1[1:]
        ]),

        b"ANGE", # because we land 4 bytes too far

    d2[2:]
    ])


    return b"".join([
        block1,
        suffix
    ]), b"".join([
        block2,
        suffix
    ])


def generate_random_jpg():
    image = Image.new('RGB', (50, 50))

    pixels = [
        (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        for _ in range(50 * 50)
    ]
    image.putdata(pixels)

    # return bytes
    return image.tobytes()


def solve():
    f1, f2 = collide_files(generate_random_jpg(), generate_random_jpg())

    if hashlib.sha256(f1).hexdigest()[:5] == hashlib.sha256(f2).hexdigest()[:5]:
        assert hashlib.md5(f1).hexdigest() == hashlib.md5(f2).hexdigest()
        print("SHA256 collision found!")
        with open("/tmp/collision1.jpg", "wb") as f:
            f.write(f1)
        with open("/tmp/collision2.jpg", "wb") as f:
            f.write(f2)
        print("Wrote collisions to /tmp/collision1.jpg and /tmp/collision2.jpg")
        return True
    return False

def parallel_solve(_):
    i = 0
    while True:
        if i % 1000 == 0:
            print("Iteration %d" % i)
        i += 1
        solve()

if __name__ == "__main__":
    pool = Pool()  # Create a multiprocessing pool
    pool.map(parallel_solve, range(os.cpu_count()))  # Run parallel_solve function in multiple processes