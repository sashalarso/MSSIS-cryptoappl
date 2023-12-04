import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import SHA256
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss


def encrypt(input,output,publickey,privatekey):

    iv=get_random_bytes(16)
    kc=get_random_bytes(32)

    with open(input,"rb") as f:
        data=f.read()

    aes=AES.new(kc,mode=2,iv=iv)
    cipher=aes.encrypt(pad(data,AES.block_size))

    key=open(publickey).read()
    pubkey=RSA.import_key(key)

    rsa=PKCS1_OAEP.new(pubkey,hashAlgo=SHA256)
    seq=rsa.encrypt(kc)

    key=open(privatekey).read()
    privkey=RSA.import_key(key)

    signature=pss.new(privkey).sign(SHA256.new(seq+iv+cipher))

    with open(output,"wb") as f:
        f.write(seq+iv+cipher+signature)
        
if len(sys.argv)==5:
    encrypt(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
    
else:
    print("Usage : python3 protect_assymetric.py encryption <password> <input> <output>")


    
    










