from Crypto.Random.random import choice
import sys
import string

def generate_password(len_pass,mode="all"):
      
    if mode=="uppercase":
        char_list=list(string.ascii_uppercase)
    if mode=="numbers":
        char_list=list(string.digits)
    if mode=="all":
        char_list=list(string.ascii_letters + string.digits + string.punctuation)    
    
    password=""
    for _ in range(len_pass):
        password+=choice(char_list)
    return password


if len(sys.argv)<3:
    print(generate_password(int(sys.argv[1])))
else:
    print(generate_password(int(sys.argv[1]),sys.argv[2]))