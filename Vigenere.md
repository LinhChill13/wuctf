# Vigenere
### Phân tích 
![image](https://hackmd.io/_uploads/rk6P07PwWg.png)

ta thấy là đây flag đã được mã hóa với cú pháp picoCTF{...} cùng với đó là tiêu đề "Vigenere". Từ đây ta sẽ decode bằng mật mã Vigenere với key "CYLAB".  
 ### vigenere là gì 
 - Tổng quát: Mật mã Ceaser thì dịch chuyển cố định thì Vigenere sẽ dịch chuyển plaintext dựa vào key. 
 - Công thức toán học: 
 mã hoá: $C_i = (P_i + K_i)  mod 26$
giải mã: $P_i =(C_i -K_i + 26) mod 26$
#### Trong đó: 
$C_i$ là chữ cái trong đoạn mã hóa
$P_i$ là chữ cái trong đoạn plaintext 
$K_i$ là chữ cái trong Key và key sẽ được lặp lại cho đến khi bằng độ dài của đoạn plaintext
### Xử lí: 
![image](https://hackmd.io/_uploads/BJ3OKDvDbx.png)
Từ đây ta được flag "picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_ae82272q}"