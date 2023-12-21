import os
from Crypto.Random import get_random_bytes
from derive_password import derive_password
from derive_km import derivate_master_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import HMAC, SHA256
import sys

def encrypt(password,input,output):

    #génération salt, iv, clés à partir du mot de passe
    salt=get_random_bytes(8)
    iv=get_random_bytes(16)
    km=derive_password(password,salt,8192)
    kc,ki=derivate_master_key(km)

    with open(input,"rb") as f:
        data=f.read()

    # chiffrement avec aes cbc
    aes=AES.new(kc,AES.MODE_CBC,iv=iv)
    cipher=aes.encrypt(pad(data,AES.block_size))
    
    #hmac construction salt||iv||C||h
    hmac=HMAC.new(key=ki,digestmod=SHA256)
    hmac.update(salt)
    hmac.update(iv)
    hmac.update(cipher)
    h=hmac.digest()

    with open(output,"wb") as f:
        f.write(salt+iv+cipher+h)
        
        


if len(sys.argv)==4:
    encrypt(sys.argv[1].encode(),sys.argv[2],sys.argv[3])
    
else:
    print("Usage : python3 protect_symetric.py <password> <input> <output>")