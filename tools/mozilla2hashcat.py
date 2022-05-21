#!/usr/bin/env python
#
# Script to extract the "hash" from a password protected key3.db or key4.db file.
#
# This code is based on the tool "firepwd" (https://github.com/lclevy/firepwd (GPL-license)
# Although the code has been changed a bit, all credit goes to @lclevy for his initial work.
#
# Tested with Python 3.8.5 and the following libraries: PyCryptodome 3.10.1 and pyasn1 0.4.8
#
# Author:
#   https://github.com/Banaanhangwagen
#   https://github.com/mneitsabes
# License: MIT
#

import argparse
from collections import namedtuple
import enum
import binascii
import hashlib
import hmac
import os
import sqlite3
import struct
import sys

from Crypto.Cipher import AES, DES3
from pyasn1.codec.der import decoder


class MasterPasswordInfos:
    def __init__(self, mode, global_salt, entry_salt, cipher_text, no_master_password, iteration=None, iv=None):
        if mode not in ['aes', '3des']:
            raise ValueError('Bad mode')

        self.mode = mode
        self.global_salt = global_salt
        self.entry_salt = entry_salt
        self.cipher_text = cipher_text
        self.no_master_password = no_master_password
        self.iteration = iteration
        self.iv = iv


def read_bsd_db(db_filepath: str) -> {}:
    """
    Read the key3.db.

    :param db_filepath: the database filepath
    :type db_filepath: str
    :return: the dict
    :rtype: dict
    """
    with open(db_filepath, 'rb') as f:
        header = f.read(4 * 15)

        magic = struct.unpack('>L', header[0:4])[0]
        if magic != 0x61561:
            raise ValueError('Bad magic number')

        version = struct.unpack('>L', header[4:8])[0]
        if version != 2:
            raise ValueError('Bad version')

        pagesize = struct.unpack('>L', header[12:16])[0]
        nkeys = struct.unpack('>L', header[56:60])[0]

        readkeys = 0
        page = 1
        db1 = []

        while readkeys < nkeys:
            f.seek(pagesize*page)

            offsets = f.read((nkeys+1) * 4 + 2)
            offset_vals = []
            i = 0
            nval = 0
            val = 1
            keys = 0

            while nval != val:
                keys += 1
                key = struct.unpack('<H', offsets[(2+i):(2+i)+2])[0]
                val = struct.unpack('<H', offsets[(4+i):(4+i)+2])[0]
                nval = struct.unpack('<H', offsets[(8+i):(8+i)+2])[0]

                offset_vals.append(key + (pagesize * page))
                offset_vals.append(val + (pagesize * page))
                readkeys += 1
                i += 4

            offset_vals.append(pagesize * (page + 1))
            val_key = sorted(offset_vals)

            for i in range(keys * 2):
                f.seek(val_key[i])
                data = f.read(val_key[i+1] - val_key[i])
                db1.append(data)

            page += 1

        db = {}
        for i in range(0, len(db1), 2):
            db[db1[i+1]] = db1[i]

    return db


def is_decrypting_mozilla_3des_without_master_password(global_salt, entry_salt, cipher_text):
    """
    Indicate if the cipher_text can be decrypted to 'password-check\x02\x02' without a master password
    in the the "mozilla 3DES"

    :param global_salt: the global salt
    :param entry_salt: the entry salt
    :param cipher_text: the encrypted text
    :return: the decrypted text
    """
    hp = hashlib.sha1(global_salt).digest()
    pes = entry_salt + b'\x00'*(20-len(entry_salt))
    chp = hashlib.sha1(hp + entry_salt).digest()
    k1 = hmac.new(chp, pes + entry_salt, hashlib.sha1).digest()
    tk = hmac.new(chp, pes, hashlib.sha1).digest()
    k2 = hmac.new(chp, tk + entry_salt, hashlib.sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]

    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(cipher_text) == b'password-check\x02\x02'


def is_decrypting_pbe_aes_without_password(global_salt, entry_salt, iteration, iv, cipher_text):
    """
    Indicate if the cipher_text can be decrypted to password-check\x02\x02' without a master password
    in the the AES mode.

    :param global_salt: the global salt
    :param entry_salt: the entry salt
    :param iteration: the number of iteration
    :param iv: the iv
    :param cipher_text: the encrypted text
    :return: the decrypted text
    """
    k = hashlib.sha1(global_salt).digest()
    key = hashlib.pbkdf2_hmac('sha256', k, entry_salt, iteration, dklen=32)

    return AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text) == b'password-check\x02\x02'


def extract_master_password_infos(db_filepath: str, db_version: int) -> MasterPasswordInfos:
    """
    Extract the master password information from the database.

    :param db_filepath: the db filepath
    :type db_filepath: str
    :param db_version: the db_type, 3 or 4
    :type db_version: int
    :return: the infos
    :rtype: MasterPasswordInfos
    """
    if db_version not in [3, 4]:
        raise ValueError('db_version not supported')

    if db_version == 3:
        db_values = read_bsd_db(db_filepath)

        global_salt = db_values[b'global-salt']
        pwd_check = db_values[b'password-check']
        entry_salt_len = pwd_check[1]
        entry_salt = pwd_check[3: 3 + entry_salt_len]
        cipher_text = pwd_check[-16:]

        no_master_password = is_decrypting_mozilla_3des_without_master_password(global_salt, entry_salt, cipher_text)

        return MasterPasswordInfos('3des', global_salt, entry_salt, cipher_text, no_master_password)
    else:
        db = sqlite3.connect(db_filepath)
        c = db.cursor()
        c.execute('SELECT item1,item2 FROM metadata WHERE id = "password"')
        global_salt, encoded_item2 = c.fetchone()
        decoded_item2 = decoder.decode(encoded_item2)

        pbe_algo = str(decoded_item2[0][0][0])
        if pbe_algo == '1.2.840.113549.1.12.5.1.3':  # pbeWithSha1AndTripleDES-CBC
            entry_salt = decoded_item2[0][0][1][0].asOctets()
            cipher_text = decoded_item2[0][1].asOctets()

            no_master_password = is_decrypting_mozilla_3des_without_master_password(global_salt, entry_salt,
                                                                                    cipher_text)
            return MasterPasswordInfos('3des', global_salt, entry_salt, cipher_text, no_master_password)
        elif pbe_algo == '1.2.840.113549.1.5.13':  # pkcs5 pbes2
            assert str(decoded_item2[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
            assert str(decoded_item2[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
            assert str(decoded_item2[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
            assert int(decoded_item2[0][0][1][0][1][2]) == 32  # key length

            entry_salt = decoded_item2[0][0][1][0][1][0].asOctets()
            iteration = int(decoded_item2[0][0][1][0][1][1])
            iv = b'\x04\x0e' + decoded_item2[0][0][1][1][1].asOctets()
            cipher_text = decoded_item2[0][1].asOctets()

            no_master_password = is_decrypting_pbe_aes_without_password(global_salt, entry_salt, iteration, iv,
                                                                          cipher_text)
            return MasterPasswordInfos('aes', global_salt, entry_salt, cipher_text, no_master_password, iteration, iv)

def hex(b) -> str:
    """
    Returns the hexily version of the binary datas.

    :param b: binary datas
    :return: the string
    """
    return binascii.hexlify(b).decode('utf8')


def get_hashcat_string(mpinfos: MasterPasswordInfos) -> str:
    """
    Print the hashchat format string.

    :param mpinfos: the infos
    :type mpinfos: MasterPasswordInfos
    :return: the string
    :rtype: str
    """

    if mpinfos.no_master_password:
        return 'No Primary Password is set.'
    else:
        s = '$mozilla$*'

        if mpinfos.mode == '3des':
            s += f'3DES*{hex(mpinfos.global_salt)}*{hex(mpinfos.entry_salt)}*{hex(mpinfos.cipher_text)}'
        else:
            s += f'AES*{hex(mpinfos.global_salt)}*{hex(mpinfos.entry_salt)}*{mpinfos.iteration}*' \
                 f'{hex(mpinfos.iv)}*{hex(mpinfos.cipher_text)}'

        return s


if __name__ == '__main__':
    usage = 'python3 mozilla2hashcat.py <profile_directory or key3/4.db file>\n'
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, usage=usage)
    parser.add_argument('dir_or_db', help='The directory containing the key3/4.db-file or the key3/4.db-file itself')
    args = parser.parse_args()

    db_filepath = None
    db_type = None

    if os.path.isdir(args.dir_or_db):
        db3_filepath = os.path.join(args.dir_or_db, 'key3.db')
        db4_filepath = os.path.join(args.dir_or_db, 'key4.db')

        if os.path.exists(db3_filepath):
            db_filepath = db3_filepath
            db_type = 3
        elif os.path.exists(db4_filepath):
            db_filepath = db4_filepath
            db_type = 4
    elif os.path.isfile(args.dir_or_db):
        filename = os.path.basename(args.dir_or_db)
        if filename == 'key3.db':
            db_filepath = args.dir_or_db
            db_type = 3
        elif filename == 'key4.db':
            db_filepath = args.dir_or_db
            db_type = 4

    if not db_filepath:
        sys.stderr.write('key3.db or key4.db file not found\n')
        exit(-1)

    infos = extract_master_password_infos(db_filepath, db_type)
    print(get_hashcat_string(infos))
