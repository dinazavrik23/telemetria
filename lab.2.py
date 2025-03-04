import string
import hashlib
import time
import itertools
password = 'goblin' 
res = hashlib.md5(password.encode())
print (res.hexdigest())
# 62b39a8bd03262744613b0bde3e51efa
print (string.digits)
print (string.punctuation)
print (string.ascii_letters)
print (string.ascii_lowercase)
print (string.ascii_uppercase)
print (string.printable)
# 0123456789
# !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
# abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
# abcdefghijklmnopqrstuvwxyz
# ABCDEFGHIJKLMNOPQRSTUVWXYZ
# 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
def generate(alphabet, max_len):
    if max_len <= 1: return
    for c in alphabet:
        yield c
    for c in alphabet:
        for next in generate(alphabet, max_len-1):
           yield c + next
gen = generate('ab', 10)
for item in gen:
        print(item)
target_hash = "62b39a8bd03262744613b0bde3e51efa"
alphabet = string.ascii_letters
start_time = time.time()

for combination in itertools.product(alphabet, repeat=5):
    password = ''.join(combination)  
    test_hash = hashlib.md5(password.encode()).hexdigest() 
    
    if test_hash == target_hash:
        print(f"Пароль найден: {password}")
        break

finish_time = time.time()
print(f"Время подбора: {finish_time - start_time:.6f} сек")
# Время подбора: 1177.009858 сек