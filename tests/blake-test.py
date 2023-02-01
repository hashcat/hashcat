#!/usr/bin/python3

import hashlib
import base64

# Python script to create dataset of passwords/hashes for testing

PASSWD_FILE = "500-worst-passwords.txt"
VALID_HASHES_FILE = "blake2s-valid-hashes.txt"

# Password source file : https://github.com/danielmiessler/SecLists/blob/master/Passwords/500-worst-passwords.txt

def createBlake2sDataset(inputFile, outputFile):
    # open password and hashes file
    passwd = open(inputFile, 'r')
    hashes = open(outputFile, 'wb')
    # for each password in file
    for line in passwd.readlines():
        # compute Blake2s hash
        d = hashlib.blake2s()
        d.update(line.encode())
        # encode in base64 and write it
        encodedHash = base64.b64encode(d.digest())
        hashes.write(encodedHash + b'\n')
    print("Done")

def main():
    createBlake2sDataset(PASSWD_FILE, VALID_HASHES_FILE)

# entry
if __name__ == "__main__":
    main()    
