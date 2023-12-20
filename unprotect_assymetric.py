import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import SHA256
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss

def decrypt(input,output,publickey,privatekey):
   
    with open(input,'rb') as f:
        try:
            seq=f.read(int(RSA.importKey(open(privatekey).read()).size_in_bytes()))
        except:
            print('File not found:', privatekey)
            sys.exit(1)
        iv = f.read(16)
        cipher = f.read(16)
        
        try:
            signature = f.read(int(RSA.importKey(open(publickey).read()).size_in_bytes()))
        except:
            print(' File not found:', publickey)
            sys.exit(1)
        
   

 
    pubkey = RSA.import_key(open(publickey).read())
    h = SHA256.new(seq+iv+cipher)
    verifier = pss.new(pubkey)

    try:
        
        verifier.verify(h, signature)
        print('The signature is authentic.')

    except:
        print('The signature is not authentic.')
        sys.exit(1)
    
  
    priv_key = RSA.importKey(open(privatekey).read())
    pkcs1 = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    kc = pkcs1.decrypt(seq)


    aes = AES.new(kc, AES.MODE_CBC, iv)
    plain = unpad(aes.decrypt(cipher), AES.block_size)

    with open(output,"wb") as f:
        f.write(plain)
    sys.exit(0)

if len(sys.argv)==5:
    decrypt(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
    
else:
    print("Usage : python3 unprotect_assymetric.py <input> <output> public_key private_key")