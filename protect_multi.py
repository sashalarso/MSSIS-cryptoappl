import os
from Crypto.Random import get_random_bytes
from derive_password import derive_password
from derive_km import derivate_master_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Hash import HMAC, SHA256
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss


def encrypt(input,output,my_sign_priv,my_ciph_pub,users_ciph_pub):
    iv=get_random_bytes(16)
    kc=get_random_bytes(32)

    with open(input,"rb") as f:
        data=f.read()

    aes=AES.new(kc,mode=2,iv=iv)
    cipher=aes.encrypt(pad(data,AES.block_size))

    message=b""
    users_ciph_pub.insert(0,my_ciph_pub)
    for user_key in users_ciph_pub:

        key=open(user_key).read()
        ciph_pub=RSA.import_key(key)

        rsa_key_pub=PKCS1_OAEP.new(ciph_pub,hashAlgo=SHA256)
        rsa_key_pub.encrypt(kc + iv)

        hash=SHA256.new(ciph_pub)
        message=message+ b'\x00'+ hash.digest()+rsa_key_pub

    message=message+ b'\x01'+cipher

    hash=SHA256.new(message)
    my_sign_priv=open(my_sign_priv).read()
    private_key=RSA.import_key(my_sign_priv)
    signature=pss.new(private_key).sign(hash)
    message+=signature

    with open(output,"wb") as f:
        f.write(message)

    