![alt text](image.png)
Đề bài cho n, e, ct nên đây là một dạng bài RSA  
![alt text](image-1.png)
Sau khi dùng tool để phân thích thành nhân tử, ta thấy 4 số nguyên tố. Do đó phi = (n1-1)* (n2-1)* (n3-1)*(n4-1)
Từ đó tìm nghịch đảo modulo d để tìm ra flag.
``` 
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from sage.all import *
import owiener
from Crypto.Util.number import *
from hashlib import sha256
from pwn import *
n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
e = 65537
ct = 2630159242114455882250729812770100011736485763047361297871782218963814793905003742546116295910618429
n1 = 9671406556917033397931773
n2 = 9671406556917033398314601
n3 = 9671406556917033398439721
n4 = 9671406556917033398454847
phi = (n1-1)*(n2-1)*(n3-1)*(n4-1)
d = inverse(e,phi)
print (long_to_bytes(pow(ct,d,n)))
```