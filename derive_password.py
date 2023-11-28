from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def derive_password(password,salt,counter):
    #h0
    h0=SHA256.new()
    h0.update(password)
    h0.update(salt)
    h0.update((0).to_bytes(4,byteorder="little"))
    hash=h0.digest()
    hi=hash
    #hi
    for i in range(1,counter):
        new=SHA256.new()
        new.update(hi)
        new.update(password)
        new.update(salt)
        new.update((i).to_bytes(4,byteorder="little"))
        hi=new.digest()
    
    return hi[0:32]

