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
        
        key=open(user_key,"rb").read()
        ciph_pub=RSA.importKey(key)

        rsa_key_pub=PKCS1_OAEP.new(ciph_pub,hashAlgo=SHA256)
        cipher_rsa=rsa_key_pub.encrypt(kc + iv)

        hash=SHA256.new(open(user_key,"rb").read())
        message=message+ b'\x00'+ hash.digest()+cipher_rsa
        

    message=message+ b'\x01'+cipher
    
    hash=SHA256.new(message)
    my_sign_priv = open(my_sign_priv, "rb").read()

    private_key=RSA.import_key(my_sign_priv)
    signature=pss.new(private_key).sign(hash)
    message+=signature
    
    with open(output,"wb") as f:
        f.write(message)
        print("Encryption done")
        sys.exit(0)

def get_sha_and_rsa(input_bytes):
    sha256 = input_bytes[1:33]
    RSA_kpub = input_bytes[33:33+256]
    return sha256, RSA_kpub, input_bytes[33+256:]
    
def get_ciphered_kc_iv(data, my_ciph_pub_key):
    h = SHA256.new(my_ciph_pub_key)
    found_RSA_kpub = b''

    while(data[0].to_bytes(1, byteorder='little') != b'\x01'):
        sha256, RSA_kpub, data = get_sha_and_rsa(data)
        if sha256 == h.digest():
            
            found_RSA_kpub = RSA_kpub
    
    return found_RSA_kpub

def decrypt(input, output, my_ciph_priv_key, my_ciph_pub_key, sender_sign_pub):
    
    with open(input,"rb") as f:
        data=f.read()

    # check integrity    

    signed=data[:-256]
    signature=data[-256:]
    
    pub_key = RSA.import_key(open(sender_sign_pub,"rb").read())
    
    h = SHA256.new(signed)
    verifier = pss.new(pub_key)

    try:
        verifier.verify(h, signature)
        print('The signature is authentic.')
    except:
        print('The signature is not authentic.')
        sys.exit(1)

    # searching for public key to check if user is legitim to decrypt

    ciphered_iv_kc= get_ciphered_kc_iv(data[:-256], open(my_ciph_pub_key,"rb").read())

    if len(ciphered_iv_kc)>1:    
        print('Ciphered kc and iv found')
    else:
        print('You are not authorized to decrypt this content')
        sys.exit(1)

    priv_key = RSA.importKey(open(my_ciph_priv_key,"rb").read())
    pkcs1 = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    kc_iv = pkcs1.decrypt(ciphered_iv_kc)
    kc = kc_iv[:32]
    iv = kc_iv[32:]

    # Data Decryption 
    aes = AES.new(kc, AES.MODE_CBC, iv)

    chain=data[:-256]
    
    plain = unpad(aes.decrypt(chain[-16:]), AES.block_size)

    with open(output,"wb") as f:
        f.write(plain)
        print("Decryption done")
        sys.exit(0)

    
if len(sys.argv) <= 1:
        print('Encryption: \nusage: multi_protect.py -e  input output my_sign_priv_key my_ciph_pub_key users_ciph_pub [users_ciph_pub ...]')
        print('Decryption: \nusage: multi_protect.py -d  input output my_ciph_priv_key my_ciph_pub_key sender_sign_pub')
else:
    if sys.argv[1] == '-e':
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6:])
    elif sys.argv[1] == '-d':
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])