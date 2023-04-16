
from Crypto.Cipher import AES
import hashlib

#Hashing of the password will automatically give us a 32 bit key in line with the standard length requirement of AES

password = 'SecretPassword'.encode()
key = hashlib.sha256(password).digest()
mode = AES.MODE_CBC
IV = 'This is an IVVVV' 
cipher = AES.new(key,mode,IV)
decrypted_text = cipher.decrypt(b'\x9b\xb9\xf9\xf2;\x9a\xff\xc5\xf3m\x084?E\x05\x986\x99\xe0\xdb\xf7\x1e\x9c\xe3\xa8=\xa6\x01a\xf5"\x8d')
print (decrypted_text.rstrip().decode())



