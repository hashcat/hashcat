#!/usr/bin/python3

# need to install snownland-smx package : pip install snowland-smx
from pysmx.SM3 import SM3

# Python script to create dataset of passwords/hashes for testing - SM3

PASSWD_FILE = "500-worst-passwords.txt"
VALID_HASHES_FILE = "sm3-valid-hashes.txt"

# Password source file : https://github.com/danielmiessler/SecLists/blob/master/Passwords/500-worst-passwords.txt

def createSM3Dataset(inputFile, outputFile):
    # open password and hashes file
    passwd = open(inputFile, 'r')
    hashes = open(outputFile, 'w')
    # for each password in file
    for line in passwd.readlines():
        # compute SM3 hash
        d = SM3()
        d.update(line)
        # encode in hex
        formattedHash = d.hexdigest()
        hashes.write(formattedHash + '\n')
    print("Done")

def main():
    createSM3Dataset(PASSWD_FILE, VALID_HASHES_FILE)

# entry
if __name__ == "__main__":
    main()    
