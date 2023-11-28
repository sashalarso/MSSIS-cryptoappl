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
    aes=AES.new(kc,2,iv=iv)
    cipher=aes.encrypt(pad(data,AES.block_size))
    
    #hmac construction salt||iv||C||h
    hmac=HMAC.new(key=ki,digestmod=SHA256)
    hmac.update(salt)
    hmac.update(iv)
    hmac.update(cipher)
    h=hmac.digest()

    with open(output,"wb") as f:
        f.write(salt+iv+cipher+h)
        
        

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

    aes=AES.new(key=kc,mode=2,iv=iv)
    plain=unpad(aes.decrypt(cipher),AES.block_size)    

    with open(output,"wb") as f:
        f.write(plain)

if len(sys.argv)==5:
    if sys.argv[1]=="encryption":
        encrypt(sys.argv[2].encode(),sys.argv[3],sys.argv[4])
    if sys.argv[1]=="decryption":
        decrypt(sys.argv[2].encode(),sys.argv[3],sys.argv[4])
else:
    print("Usage : python3 protect_symetric.py <mode[encryption,decryption]> <password> <input> <output>")