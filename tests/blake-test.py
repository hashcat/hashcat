#!/usr/bin/python3

import hashlib

# Python script to create dataset of passwords/hashes for testing

PASSWD_FILE       = "500-worst-passwords.txt"
VALID_HASHES_FILE = "blake2s-valid-hashes.txt"
# VALID_HASHES_FILE = "blake2b-valid-hashes.txt"
BLAKE2S_HEADER    = "$BLAKE2$"  

# Password source file : https://github.com/danielmiessler/SecLists/blob/master/Passwords/500-worst-passwords.txt

def createBlake2sDataset(inputFile, outputFile):
    # open password and hashes file
    passwd = open(inputFile, 'r')
    hashes = open(outputFile, 'w')
    # for each password in file
    for line in passwd.readlines():
        # compute Blake2s hash
        d = hashlib.blake2s()
        # d = hashlib.blake2b()
        d.update(line.replace('\n', '').encode())
        # encode in base64 and write it
        formattedHash = BLAKE2S_HEADER + d.hexdigest()
        # print(formattedHash + '\n', end='')
        hashes.write(formattedHash + '\n')
    print("Done")

def main():
    createBlake2sDataset(PASSWD_FILE, VALID_HASHES_FILE)

# entry
if __name__ == "__main__":
    main()    
