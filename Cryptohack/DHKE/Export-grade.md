# [Writeup] CryptoHack - Parameter Negotiation

## 1. Ý tưởng bài giải
Dựa vào đề bài, chúng ta đóng vai trò là kẻ đứng giữa (**Man-in-the-middle**) và có quyền can thiệp vào quá trình thương lượng các tham số mã hóa của Alice và Bob.

*   **Lỗ hổng:** Alice gửi một danh sách các tùy chọn độ dài khóa Diffie-Hellman (DH). Chúng ta sẽ can thiệp để ép cả hai sử dụng **DH64**.
*   **Tại sao lại là DH64?** Vì 64-bit là độ dài cực kỳ yếu đối với bài toán Logarit rời rạc (**Discrete Logarithm Problem**). Với các thư viện toán học hiện đại, việc tìm ra số mũ bí mật $b$ từ khóa công khai $B$ chỉ mất vài giây.
*   **Quy trình tấn công:**
    1. Chặn gói tin `supported` từ Alice, sửa danh sách chỉ còn `["DH64"]`.
    2. Chặn gói tin `chosen` từ Bob để xác nhận `DH64` được thực thi.
    3. Lấy các thông số p, g, A và B từ luồng trao đổi.
    4. Tính $b = \{discrete\_log}(p, B, g)$
    5. Tính `shared_secret` = $A^b \pmod p$
    6. Dùng `shared_secret` này để tạo khóa AES và giải mã Flag.
## 2. Mã khai thác (Python)
```python
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

# ---
