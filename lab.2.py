import string
import hashlib
def generate(alphabet, max_len):
    if max_len <= 1: return
    for c in alphabet:
        yield c
    for c in alphabet:
        for next in generate(alphabet, max_len-1):
           yield c + next
gen = generate('ab', 2)
for item in gen:
        print(item)

# password = 'a' 
for item in gen:
    res = hashlib.md5(item.encode())
    print (res.hexdigest())
            # .ascii_lowercase (делает заглавные буквы)
    print (string.digests) #'0123456789' 
              #  .punctuation (делает пунктуацию)