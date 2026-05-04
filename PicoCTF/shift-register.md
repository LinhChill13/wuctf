# [Write-up] Crypto - Basic LFSR Brute-force

## 1. Đặt vấn đề
Đề bài cung cấp cho ta 2 file:
- `chall.py`: Chứa mã nguồn thực hiện việc mã hóa (Encryption).
- `output.txt`: Chứa bản mã (Ciphertext) dưới dạng chuỗi hex: `21c1b705764e4bfdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9`.

Thuật toán mã hóa được sử dụng ở đây là một dạng mã hóa luồng (Stream Cipher) kết hợp với **LFSR (Linear Feedback Shift Register)**.

## 2. Phân tích lỗ hổng (Vulnerability Analysis)

Khi đọc mã nguồn `chall.py`, ta cần chú ý đến cách khóa bí mật (Key) được sinh ra và sử dụng:

```python
key = bytes_to_long(get_random_bytes(126))
# ... (Bỏ qua hàm steplfsr) ...
def encrypt_lfsr(pt_bytes):
    output = bytearray()
    lfsr = key & 0xFF   # <--- LỖ HỔNG LÀ Ở ĐÂY
    # ...```

- việc & 0xFF tức là chỉ lấy 8 bit cuối làm key. nên ta có thể brute force được (2^8 trường hợp)
- Plaintext = Ciphertext ^ Keystream
```
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
```
