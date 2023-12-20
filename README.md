Symétrique : 

Chiffrement:
python3 protect_symetric.py password input output
Dechiffrement
python3 unprotect_symetric.py password input output

Asymétrique : 

Chiffrement:
python3 protect_assymetric.py input output public_key private_key
Dechiffrement
python3 unprotect_assymetric.py input output public_key private_key

Multi user : 

Chiffrement:
python3 multi_protect.py -e input output my_sign_priv my_ciph_pub [users_ciph_pub]
Dechiffrement
python3 multi_protect.py -d input output my_ciph_priv my_ciph_pub sender_sign_pub

exemple:
python3 multi_protect.py -e plain cipher signpriv.pem cipherpub.pem
python3 multi_protect.py -d cipher exit cipherpriv.pem cipherpub.pem signpub.pem