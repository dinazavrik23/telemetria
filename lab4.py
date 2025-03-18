import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate a private key.
private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())

# Extract the public key from the private key.
public_key = private_key.public_key()

# Convert the private key into bytes. We won't encrypt it this time.
private_key_bytes = private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.TraditionalOpenSSL,
       encryption_algorithm=serialization.NoEncryption()
   )

# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
   )

# Convert the private key bytes back to a key.
# Because there is no encryption of the key, there is no password.
private_key = serialization.load_pem_private_key(
      private_key_bytes,
      backend=default_backend(),
       password=None)


public_key = serialization.load_pem_public_key(
          public_key_bytes,
      backend=default_backend())




# for anything other than the practice exercise
################
def simple_rsa_encrypt(m, publickey):
# Public_numbers returns a data structure with the 'e' and 'n' parameters.
    numbers = publickey.public_numbers()
       # Encryption is(m^e) % n.
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
# Private_numbers returns a data structure with the 'd' and 'n' parameters.

    numbers = privatekey.private_numbers()
# Decryption is(c^d) % n.
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)
#### DANGER ####

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()


def text_to_number(text):
    return int.from_bytes(text.encode('utf-8'), 'big')


def number_to_text(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big').decode('utf-8')


def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)


message = "dinazavrik"
message_number = text_to_number(message)

ciphertext = simple_rsa_encrypt(message_number, public_key)
decrypted_number = simple_rsa_decrypt(ciphertext, private_key)
decrypted_message = number_to_text(int(decrypted_number))

print("Оригинальное сообщение:", message)
print("Числовое представление:", message_number)
print("Зашифрованное сообщение:", ciphertext)
print("Расшифрованное сообщение:", decrypted_message)

import time
import itertools

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()


def text_to_number(text):
    return int.from_bytes(text.encode('utf-8'), 'big')


def number_to_text(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')


def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)


message = "абвг" 
message_number = text_to_number(message)


ciphertext = simple_rsa_encrypt(message_number, public_key)
print(f"Оригинальное сообщение: {message}")
print(f"Числовое представление: {message_number}")
print(f"Зашифрованное сообщение: {ciphertext}")

def brute_force_decrypt(ciphertext, private_key, max_length):
    alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя" 
    
    start_time = time.time()

    for length in range(1, max_length + 1):
        for attempt in itertools.product(alphabet, repeat=length):
            attempt_text = ''.join(attempt)
            attempt_number = text_to_number(attempt_text)

            if attempt_number == simple_rsa_decrypt(ciphertext, private_key):
                end_time = time.time()
                return attempt_text, end_time - start_time

    return None, time.time() - start_time  

decrypted_message_4, time_4 = brute_force_decrypt(ciphertext, private_key, 4)
print(f"Расшифрованное 4-буквенное слово: {decrypted_message_4}")
print(f"Перебор 4-буквенного слова занял: {time_4:.2f} сек")

message_5 = "абвгд" 
message_number_5 = text_to_number(message_5)
ciphertext_5 = simple_rsa_encrypt(message_number_5, public_key)
print(f"\nОригинальное 5-буквенное сообщение: {message_5}")
print(f"Зашифрованное 5-буквенное сообщение: {ciphertext}")


decrypted_message_5, time_5 = brute_force_decrypt(ciphertext, private_key, 5)
print(f"Расшифрованное 5-буквенное слово: {decrypted_message_5}")
print(f"Перебор 5-буквенного слова занял: {time_5:.2f} сек")

ratio = time_5 / time_4 if time_4 > 0 else "N/A"
print(f"Перебор 5-буквенных слов дольше в {ratio:.2f} раза")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def text_to_number(text):
    return int.from_bytes(text.encode('utf-8'), 'big')


def number_to_text(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big').decode('utf-8', errors='ignore')


def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)


message = "jara" 
message_number = text_to_number(message)


ciphertext = simple_rsa_encrypt(message_number, public_key)
print(f"Оригинальное сообщение: {message}")
print(f"Числовое представление: {message_number}")
print(f"Зашифрованное сообщение: {ciphertext}")

def brute_force_decrypt(ciphertext, private_key, max_length):
    alphabet = "abcdefghilklmnopqrstyvwxuz" 
    
    start_time = time.time()

    for length in range(1, max_length + 1):
        for attempt in itertools.product(alphabet, repeat=length):
            attempt_text = ''.join(attempt)
            attempt_number = text_to_number(attempt_text)

            if attempt_number == simple_rsa_decrypt(ciphertext, private_key):
                end_time = time.time()
                return attempt_text, end_time - start_time

    return None, time.time() - start_time  

decrypted_message_4, time_4 = brute_force_decrypt(ciphertext, private_key, 4)
print(f"Расшифрованное 4-буквенное слово: {decrypted_message_4}")
print(f"Перебор 4-буквенного слова занял: {time_4:.2f} сек")

message_5 = "timer" 
message_number_5 = text_to_number(message_5)
ciphertext_5 = simple_rsa_encrypt(message_number_5, public_key)
print(f"\nОригинальное 5-буквенное сообщение: {message_5}")
print(f"Зашифрованное 5-буквенное сообщение: {ciphertext}")


decrypted_message_5, time_5 = brute_force_decrypt(ciphertext, private_key, 5)
print(f"Расшифрованное 5-буквенное слово: {decrypted_message_5}")
print(f"Перебор 5-буквенного слова занял: {time_5:.2f} сек")

ratio = time_5 / time_4 if time_4 > 0 else "N/A"
print(f"Перебор 5-буквенных слов дольше в {ratio:.2f} раза")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

'''
     код с использованием AES-GCM

    Не шифруйте файл размером более 64 ГБ, поскольку у GCM есть ограничения!!!
'''

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, sys, struct

READ_SIZE = 4096

def encrypt_file(plainpath, cipherpath, password):
    # Derive key with a random 16-byte salt
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,
                    backend=default_backend())
    key = kdf.derive(password)

    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    backend=default_backend()).encryptor()

    associated_data = iv + salt

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)
    with open(cipherpath, "wb+") as fcipher:
        # Make space for the header (12 + 16 + 16), overwritten last
        fcipher.write(b"\x00"*(12+16+16))

        # Encrypt and write the main body
        with open(plainpath, "rb") as fplain:
            for plaintext in iter(lambda: fplain.read(READ_SIZE), b''):
                ciphertext = encryptor.update(plaintext)
                fcipher.write(ciphertext)
            ciphertext = encryptor.finalize() # Always b''.
            fcipher.write(ciphertext) # For clarity

            header = associated_data + encryptor.tag
            fcipher.seek(0,0)
            fcipher.write(header)

def decrypt_file(cipherpath, plainpath, password):
    with open(cipherpath, "rb") as fcipher:
    # read the IV (12 bytes) and the salt (16 bytes)
        associated_data = fcipher.read(12+16)

        iv = associated_data[0:12]
        salt = associated_data[12:28]

    # derive the same key from the password + salt
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password)

        # get the tag. GCM tags are always 16 bytes
        tag = fcipher.read(16)

        # Construct an AES-GCM Cipher object with the given key and IV
        # For decryption, the tag is passed in as a parameter
        decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(associated_data)

        with open(plainpath, "wb+") as fplain:
            for ciphertext in iter(lambda: fcipher.read(READ_SIZE),b''):
                plaintext = decryptor.update(ciphertext)
                fplain.write(plaintext)
