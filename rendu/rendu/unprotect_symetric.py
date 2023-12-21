import os
from Crypto.Random import get_random_bytes
from derive_password import derive_password
from derive_km import derivate_master_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import HMAC, SHA256
import sys

def decrypt(password,input,output):
    size=os.path.getsize(input)
    c_size=size-8-16-32
    with open(input,"rb") as f:
        salt=f.read(8)
        iv=f.read(16)
        cipher=f.read(c_size)
        hmac=f.read()
        
    
    km=derive_password(password,salt,8192)

    kc,ki=derivate_master_key(km)

    h = HMAC.new(key=ki, digestmod=SHA256)
    h.update(salt)
    h.update(iv)
    h.update(cipher)
    try:
        h.verify(hmac)
    except ValueError:
        print("MAC doesnt match")
        sys.exit(1)

    aes=AES.new(key=kc,mode=AES.MODE_CBC,iv=iv)
    plain=unpad(aes.decrypt(cipher),AES.block_size)    

    with open(output,"wb") as f:
        f.write(plain)
    sys.exit(0)

if len(sys.argv)==4:
    
    decrypt(sys.argv[1].encode(),sys.argv[2],sys.argv[3])
else:
    print("Usage : python3 protect_symetric.py <password> <input> <output>")