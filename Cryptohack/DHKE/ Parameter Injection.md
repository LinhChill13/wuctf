# [Writeup] CryptoHack - Parameter Injection
## Hint: You're in a position to not only intercept Alice and Bob's DH key exchange, but also rewrite their messages. Think about how you can play with the DH equation that they calculate, and therefore sidestep the need to crack any discrete logarithm problem.

## Ý tưởng:
- Dựa vào thông tin đề bài cho thì ta có thể "rewrite their messages". Tức là có thể thay đổi nội dung trao đổi giữa 2 người. 
- Vì thế ta có ý tưởng rằng thay vì gửi A cho Bob thì ta sẽ gửi p thay cho A
- Tương tự với B của Bob, ta cũng sẽ gửi p cho Alice.
- Do đó shared_secret key giữa hai người sẽ là 0. 
=> Dựa vào đó là sẽ tìm ra flag bằng hàm decrypt
## Mã nguồn:
```python 
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
# from sage.all import *
from Crypto.Util.number import *
from hashlib import sha256,sha1
from pwn import *
from Crypto.Util.Padding import pad, unpad
import pwn 
import json
from sympy.ntheory import discrete_log
host = 'socket.cryptohack.org'```
port = 13371
pr = pwn.connect(host,port)
pr.readuntil(": ")
line = json.loads(pr.readline().strip().decode())
p = int (line['p'],16)
g = int (line['g'],16)
A = int (line['A'],16)
payload = json.dumps({"p": hex(p), "g":hex(g),"A":hex(p)})
pr.sendlineafter(":", payload)
pr.readuntil(":")
line = json.loads(pr.readline().strip().decode())
B = int (line['B'],16)
payload1 = json.dumps({"B": hex(p)})
pr.sendlineafter(":", payload1)
pr.readuntil(":")
line = json.loads(pr.readline().strip().decode())
print (line)
iv = bytes.fromhex(line['iv'])
ciphertext = bytes.fromhex(line['encrypted_flag'])
shared_secret = 0                                                                                                                                                                                                                                                                                                                                                                                    
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

print (decrypt_flag(shared_secret, iv, ciphertext))
```
