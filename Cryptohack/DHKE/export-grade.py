import json
import hashlib
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sympy.ntheory import discrete_log

host = "socket.cryptohack.org"
port = 13379
pr = connect(host, port)
pr.readuntil(": ")
line = json.loads(pr.readline().strip().decode())
payload = json.dumps({"supported": ["DH64"]})
pr.sendlineafter(":", payload.encode())
pr.readuntil(": ")
line = json.loads(pr.readline().strip().decode())
payload = json.dumps({"chosen": "DH64"})
pr.sendlineafter(":", payload.encode())
pr.readuntil(":")
line = json.loads(pr.readline().strip().decode())
p = int(line['p'], 16)
g = int(line['g'], 16)
A = int(line['A'], 16)

pr.readuntil(":")
line = json.loads(pr.readline().strip().decode())
B = int(line['B'], 16)
pr.readuntil(":")
line = json.loads(pr.readline().strip().decode())
iv = bytes.fromhex(line['iv'])
ciphertext = bytes.fromhex(line['encrypted_flag'])

b= discrete_log(p, B, g)
shared_key = pow(A, b, p)
def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))
def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

print (decrypt_flag(shared_key, iv, ciphertext))
