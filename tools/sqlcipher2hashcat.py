from base64 import b64encode
import sys

database = open(sys.argv[1], "rb").read(272)
salt = database[:16]

print('sqlcipher:256000:' + b64encode(salt).decode() + ':' + b64encode(database[16:272]).decode())
