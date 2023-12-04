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
    print(cipher)
    hash=SHA256.new(message)
    my_sign_priv=open(my_sign_priv).read()
    private_key=RSA.import_key(my_sign_priv)
    signature=pss.new(private_key).sign(hash)
    message+=signature
    
    with open(output,"wb") as f:
        f.write(message)
def get_params(input):
    sha256 = input[1:33]
    RSA_kpub = input[33:33+256]
    return sha256, RSA_kpub, input[33+256:]

def decrypt(input, output, my_ciph_priv_key, my_ciph_pub_key, sender_sign_pub):
    '''
    Encryption using AES-256-CBC
    Input: 0x00 || SHA256(kpub-1) || RSA_kpub-1(Kc || IV) || ... || 0x00 || SHA256(kpub-N) || RSA_kpub-N(Kc || IV) || 0x01 || C || Sign
    Output: bytes
    '''
    with open(input,"rb") as f:
        data=f.read()

    # Integrity check msg signature
    

    signed=data[:-256]
    signature=data[-256:]
    
    pub_key = RSA.import_key(open(sender_sign_pub,"rb").read())
    
    h = SHA256.new(signed)
    verifier = pss.new(pub_key)

    try:
        verifier.verify(h, signature)
        print('[+]: The signature is authentic.')
    except:
        print('[!]: The signature is not authentic.')
        sys.exit(1)


    h = SHA256.new(open(my_ciph_pub_key,"rb").read())
    
    found_sha256=b''
    found_RSA_kpub=b''
    for byte in data[:-256]:
        if byte.to_bytes()==b'\x01':
            found_sha256=data[1:33]
            found_RSA_kpub=data[33:33+256]
            rest=data[33+256+1:]
            
            if h.digest()==found_sha256:
                print("found")
                break
            


    
    print(rest[256:])
    print(rest)
    print('[+]: Public key found')
    
    priv_key = RSA.importKey(open(my_ciph_priv_key,"rb").read())
    pkcs1 = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
    plain_params = pkcs1.decrypt(found_RSA_kpub)
    kc = plain_params[:32]
    iv = plain_params[32:]

    # Data Decryption from kc decrypted
    aes = AES.new(kc, AES.MODE_CBC, iv)
    plain = unpad(aes.decrypt(rest[:-256]), AES.block_size)

    with open(output,"wb") as f:
        f.write(plain)

    
if len(sys.argv) <= 1:
        print('Encryption: \nusage: multi_protect.py -e  input output my_sign_priv_key my_ciph_pub_key users_ciph_pub [users_ciph_pub ...]')
        print('Decryption: \nusage: multi_protect.py -d  input output my_ciph_priv_key my_ciph_pub_key sender_sign_pub')
else:
    if sys.argv[1] == '-e':
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6:])
    elif sys.argv[1] == '-d':
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])