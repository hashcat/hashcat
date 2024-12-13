#!/usr/bin/env python3

from base64 import b64decode
from hashlib import pbkdf2_hmac

from Crypto.Cipher import AES

#TODO perhaps load the vault from tools/2hashcat_tests/metamask2hashcat.json similar as in tools/metamask2hashcat.py
vault = {"data":"R95fzGt4UQ0uwrcrVYnIi4UcSlWn9wlmer+//526ZDwYAp50K82F1u1oacYcdjjhuEvbZnWk/uBG00UkgLLlO3WbINljqmu2QWdDEwjTgo/qWR6MU9d/82rxNiONHQE8UrZ8SV+htVr6XIB0ze3aCV0E+fwI93EeP79ZeDxuOEhuHoiYT0bHWMv5nA48AdluG4DbOo7SrDAWBVCBsEdXsOfYsS3/TIh0a/iFCMX4uhxY2824JwcWp4H36SFWyBYMZCJ3/U4DYFbbjWZtGRthoJlIik5BJq4FLu3Y1jEgza0AWlAvu4MKTEqrYSpUIghfxf1a1f+kPvxsHNq0as0kRwCXu09DObbdsiggbmeoBkxMZiFq0d9ar/3Gon0r3hfc3c124Wlivzbzu1JcZ3wURhLSsUS7b5cfG86aXHJkxmQDA5urBz6lw3bsIvlEUB2ErkQy/zD+cPwCG1Rs/WKt7KNh45lppCUkHccbf+xlpdc8OfUwj01Xp7BdH8LMR7Vx1C4hZCvSdtURVl0VaAMxHDX0MjRkwmqS","iv":"h+BoIf2CQ5BEjaIOShFE7g==","salt":"jfGI3TXguhb8GPnKSXFrMzRk2NCEc131Gt5G3kZr5+s="}
password = "hashcat1"

salt = b64decode(vault["salt"])
key = pbkdf2_hmac("sha256", password.encode(), salt, 10_000)

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
