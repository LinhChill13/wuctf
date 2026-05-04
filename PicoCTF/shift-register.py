from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from sage.all import *
import owiener
from Crypto.Util.number import *
from hashlib import sha256
from pwn import *
import string


ct_hex = "21c1b705764e4bfdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9"
ct = bytes.fromhex(ct_hex)
def steplfsr(lfsr):
    b7 = (lfsr >> 7) & 1
    b5 = (lfsr >> 5) & 1
    b4 = (lfsr >> 4) & 1
    b3 = (lfsr >> 3) & 1

    feedback = b7 ^ b5 ^ b4 ^ b3
    lfsr = (feedback << 7) | (lfsr >> 1)
    return lfsr
def decrypt(ct_bytes, initial_lfsr):
    output = bytearray()
    lfsr = initial_lfsr
    for c in ct_bytes:
        lfsr = steplfsr(lfsr)
        ks = lfsr
        output.append(c ^ ks)
    return output
printable = set(string.printable.encode())
for i in range(256):
    pt = decrypt(ct, i)
    if all(byte in printable for byte in pt):
        print(f"\n[+] Khóa tìm thấy: {i}")
        print(f"[+] Bản rõ (Flag): {pt.decode('utf-8')}")