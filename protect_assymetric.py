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
        

def decrypt(input,output,publickey,privatekey):
   
    with open(input,'rb') as f:
        try:
            seq=f.read(int(RSA.importKey(open(privatekey).read()).size_in_bytes()))
        except:
            print('[!]: File not found:', privatekey)
            sys.exit(1)
        iv = f.read(16)
        cipher = f.read(16)
        
        try:
            signature = f.read(int(RSA.importKey(open(publickey).read()).size_in_bytes()))
        except:
            print('[!]: File not found:', publickey)
            sys.exit(1)
        
   

    #  Integrity check signature
    pubkey = RSA.import_key(open(publickey).read())
    h = SHA256.new(seq+iv+cipher)
    verifier = pss.new(pubkey)

    try:
        
        verifier.verify(h, signature)
        print('[+]: The signature is authentic.')

    except:
        print('[!]: The signature is not authentic.')
        sys.exit(1)
    
    # Decryption of the symmetric key
    priv_key = RSA.importKey(open(privatekey).read())
    pkcs1 = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    kc = pkcs1.decrypt(seq)

    # Data Decryption from kc decrypted
    aes = AES.new(kc, AES.MODE_CBC, iv)
    plain = unpad(aes.decrypt(cipher), AES.block_size)

    with open(output,"wb") as f:
        f.write(plain)

    
    

encrypt("clair","chiffre","pubkey.pem","privkey.pem")
decrypt("chiffre","reclair","pubkey.pem","privkey.pem")







