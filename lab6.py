%pip install gmpy2 cryptography
import os
import time
import itertools
import gmpy2

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # Recommended size for GCM nonce

plaintext = b"Dinazavrik"
associated_data = b"Additional data"

# Encrypt
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
print(f"Ciphertext: {ciphertext}")

# Decrypt
decrypted_text = aesgcm.decrypt(nonce, ciphertext, associated_data)
print(f"Decrypted Message: {decrypted_text.decode()}")

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# Encrypting
message = b"I love my cat"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print(f"Ciphertext: {ciphertext}")

# Decrypting
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print(f"Decrypted Message: {plaintext.decode()}")

from cryptography.hazmat.primitives import serialization

# Sign data
signature = private_key.sign(
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
print(f"Signature: {signature}")

# Verify signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Signature Verified")
except Exception as e:
    print(f"Signature Verification Failed: {e}")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"Message to hash")
hash_result = digest.finalize()
print(f"SHA-256 Hash: {hash_result.hex()}")

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(b"my password")
print(f"Derived Key: {key.hex()}")

kdf = Scrypt(
    salt=os.urandom(16),
    length=32,
    n=2**14,
    r=8,
    p=1,
    backend=default_backend()
)
key = kdf.derive(b"my password")
print(f"Derived Key: {key.hex()}")

import secrets

# Сгенерируйте случайную соль в виде шестнадцатеричной строки
salt = secrets.token_hex(16)  # 16 байт случайности — распространённый выбор
print("Соль:", salt)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
aesgcm.decrypt(nonce, ct, aad)

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
aesgcm.decrypt(nonce, ct, aad)

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
data = b"a secret message"
aad = b"authenticated but unencrypted data"
key = ChaCha20Poly1305.generate_key()
chacha = ChaCha20Poly1305(key)
nonce = os.urandom(12)
ct = chacha.encrypt(nonce, data, aad)
chacha.decrypt(nonce, ct, aad)