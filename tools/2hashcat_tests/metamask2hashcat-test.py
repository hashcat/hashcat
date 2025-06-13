#!/usr/bin/env python3

from base64 import b64decode
from hashlib import pbkdf2_hmac
import json
from Crypto.Cipher import AES

import os

current_path = os.path.dirname(__file__)
file_path = os.path.join(current_path, "metamask2hashcat.json")
with open(file_path, "r") as file:
    vault = json.load(file)

password = "hashcat1"

salt = b64decode(vault["salt"])
iter = vault["keyMetadata"]["params"]["iterations"]
key = pbkdf2_hmac("sha256", password.encode(), salt, iter)

iv = b64decode(vault["iv"])
payload = b64decode(vault["data"])
ciphertext = payload[:-16]
print(f"ciphertext.hex()={ciphertext.hex()[0:128]}")
tag = payload[-16:]

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt(ciphertext)

print(plaintext.hex()[0:128])
print(str(plaintext[0:128]))

print()
try:
    cipher.verify(tag)
    print("The message is authentic:", plaintext.decode())
except ValueError:
    print("Key incorrect or message corrupted")
print()

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt(ciphertext[:32])
print("Partially encrypted message (32 bytes):", plaintext.decode())

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt(ciphertext[:450])
print("Partially encrypted message (450 bytes):", plaintext.decode())
