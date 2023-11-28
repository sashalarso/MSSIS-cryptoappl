from Crypto.Hash import SHA256

def derivate_master_key(km):
    h = SHA256.new()
    h.update(km[0:32])
    h.update((0).to_bytes(4, byteorder='little'))
    kc = h.digest()

    h2=SHA256.new()
    h2.update(km[0:32])
    h2.update((1).to_bytes(4, byteorder='little'))
    ki = h.digest()

    return kc,ki