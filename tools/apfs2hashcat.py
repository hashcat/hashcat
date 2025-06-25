#!/usr/bin/env python3

# For extracting APFS hashes to be cracked by hashcat modes 18300 ($fvde$2$) or 16700 ($fvde$1$).
# Usage: `python3 apfs2hashcat.py <apfs_image_file> -o <_apfs_container_offset>`
# The argument -o is optional. The script will attempt to read the partition table to find the location of APFS container(s). In the case that the partition table is missing or you want to specify a particular APFS container, use -o to provide the offset to the start of the container.

import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KNOWN_RECOVERY_HASHES = ['64C0C6EB-0000-AA11-AA11-00306543ECAC', 'D92A1CEC-18B6-D64E-BD8D-50F361C27507']
TAG_DICT = {'unk_80' : {'tag' : b'\x80', 'expected_len' : 1},
            'uuid' : {'tag' : b'\x81', 'expected_len' : 0x10},
            'unk_82' : {'tag' : b'\x82'},
            'wrapped_kek' : {'tag' : b'\x83', 'expected_len' : 0x28},
            'iterations' : {'tag' : b'\x84'},
            'salt' : {'tag' : b'\x85', 'expected_len' : 0x10}}
HEX_APFS_CONTAINER_GUID = '7C3457EF-0000-11AA-AA11-00306543ECAC'
AES_XTS_SECTOR_SIZE = 512
EFI_PARTITION_HEADER = b'EFI PART'

def uint_to_int(b):
    return int(b[::-1].hex(), 16)


def findall(p, s):
    i = s.find(p)
    while i != -1:
        yield i
        i = s.find(p, i+1)


def hex_to_guid(hex_str):

    guid_parts = [0] * 5
    guid_parts[0] = hex_str[0:8]
    guid_parts[1] = hex_str[8:12]
    guid_parts[2] = hex_str[12:16]
    guid_parts[3] = hex_str[16:20]
    guid_parts[4] = hex_str[20:]

    guid = ''.join([guid_parts[0][i:i+2] for i in range(0, len(guid_parts[0]), 2)][::-1])
    guid += '-'
    guid += ''.join([guid_parts[1][i:i+2] for i in range(0, len(guid_parts[1]), 2)][::-1])
    guid += '-'
    guid += ''.join([guid_parts[2][i:i+2] for i in range(0, len(guid_parts[2]), 2)][::-1])
    guid += '-'
    guid += guid_parts[3]
    guid += '-'
    guid += guid_parts[4]

    return guid.upper()


def parse_partition_entry(partition_entry):
    type_GUID = partition_entry[0:0x10]
    part_GUID = partition_entry[0x10:0x20]
    start_LBA = partition_entry[0x20:0x28]
    # end_LBA   = partition_entry[0x28:0x30]
    return part_GUID, type_GUID, start_LBA


# get main_start by multiplying apfs partition start lba by block size
def parse_partition_table(fp):

    # determine whether sector size is 0x200 or 0x1000
    sector_size = 0x0

    # look for EFI PART at start of sector 1
    fp.seek(0x200)
    signature = fp.read(0x8)
    if signature == EFI_PARTITION_HEADER:
        sector_size = 0x200

    else:
        fp.seek(0x1000)
        signature = fp.read(0x8)
        if signature == EFI_PARTITION_HEADER:
            sector_size = 0x1000

    print("[+] Identified sector size:", sector_size)

    if not sector_size:
        print(f"[!] Invalid sector size {sector_size} (not 512 or 4096 bytes). Exiting.")

    fp.seek(2 * sector_size) # go to sector 2
    partitions = []
    partition_entry = b'1'
    while any(partition_entry):
        partition_entry = fp.read(0x80)
        if any(partition_entry):
            partitions.append(partition_entry)

    partition_dict = {}
    for p in partitions:
        part_GUID, type_GUID, start = parse_partition_entry(p)
        starting_pos = uint_to_int(start) * sector_size
        partition_dict[part_GUID.hex()] = {'start':starting_pos, 'partition_type':type_GUID.hex()}

    return partition_dict


def AES_XTS_decrypt_sector(uuid, tweak, ct):

    decryptor = Cipher(
        algorithms.AES(key=uuid+uuid),
        modes.XTS(tweak=tweak),
    ).decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    return pt


def AES_decrypt(data, start_offset, block_size, uuid):
    cs_factor = block_size // 0x200 # = 8 for block_size=4096
    uno = start_offset * cs_factor
    pt = b''
    for offset in range(0, block_size, AES_XTS_SECTOR_SIZE):
        ct = data[offset:offset + AES_XTS_SECTOR_SIZE]
        tweak = hex(uno)[2:].zfill(32) # 32 so that the key is the correct length (16 bytes)
        tweak = bytearray.fromhex(tweak)[::-1]
        pt += AES_XTS_decrypt_sector(uuid, tweak, ct)
        uno += 1

    return pt


def TLV(full_kek_blob, tag, starting_index):
    # expected tag should follow if this is the correct TLV)
    if full_kek_blob[starting_index:starting_index+1] != TAG_DICT[tag]['tag']:
        return -1, starting_index
    # check for expected len for further confirmation
    length = uint_to_int(full_kek_blob[starting_index+1:starting_index+2])
    expected_len = TAG_DICT[tag].get('expected_len') # use .get() since not all tags have an expected len
    if expected_len:
        if length != expected_len:
            return -1, starting_index
    next_starting_index = starting_index+2+length
    value = full_kek_blob[starting_index+2:next_starting_index]

    return value, next_starting_index


def TLV_iterate(starting_index, pt, hash_set, volume_uuid):
    for tag in TAG_DICT:
        value, starting_index = TLV(pt, tag, starting_index)

        # i.e. if fails length check
        if value == -1:
            return starting_index + 1, hash_set
        TAG_DICT[tag]['value'] = value

    aes_type = TAG_DICT['unk_82']['value']
    wrapped_kek = TAG_DICT['wrapped_kek']['value']
    iterations = TAG_DICT['iterations']['value']
    salt = TAG_DICT['salt']['value']

    aes_type = uint_to_int(aes_type[0:4])

    # FVDE - AES128
    if aes_type == 2:
        aes_hash_value = 1
        wrapped_kek = wrapped_kek[:0x18] # shorter kek value, this removes zeros

    # APFS - AES256
    elif aes_type == 16 or aes_type == 0:
        aes_hash_value = 2

    else:
        print("[!] AES type not recognised, continuing...")
        return

    password_hash = f"$fvde${aes_hash_value}${len(salt)}${salt.hex()}${int(iterations.hex(),16)}${wrapped_kek.hex()}"
    hash_set.add(password_hash)
    print(f"\nFound password hash: {password_hash} (vol uuid: {volume_uuid.hex()})")

    kek_uuid = hex_to_guid(TAG_DICT['uuid']['value'].hex())
    if kek_uuid in KNOWN_RECOVERY_HASHES:
        print(f"[!] Warning! Recognised UUID {kek_uuid}... possible recovery hash\n")

    return starting_index, hash_set


def parse_block(block):
    nx_xid = uint_to_int(block[16:24])
    obj_type = uint_to_int(block[24:26])
    magic = block[0x20:0x24]

    return  nx_xid, obj_type, magic


def parse_apsb_block(block):
    obj_type = uint_to_int(block[24:26])
    magic = block[0x20:0x24]
    uuid = block[240:256]
    encryption = uint_to_int(block[264:272])
    name = block[704:960]

    return obj_type, magic, uuid, encryption, name


def parse_keybag_entry(uuid, pt):
    uuid_iterator = findall(uuid, pt)
    for starting_pos in uuid_iterator:
        ke_uuid, ke_tag, ke_keylen = pt[starting_pos:starting_pos+16], uint_to_int(pt[starting_pos + 16:starting_pos + 18]), uint_to_int(pt[starting_pos + 18:starting_pos + 20])
        padding = pt[starting_pos + 20:starting_pos + 24]
        keydata = pt[starting_pos + 24: starting_pos + 24 + ke_keylen]

        # only tag 3 is needed for constructing the hash
        if ke_tag == 3:
            assert padding == b'\x00\x00\x00\x00'
            volume_unlock_record = keydata
            return volume_unlock_record

    return None


def get_fs_oids(csb_body):
    max_file_systems = uint_to_int(csb_body[0x94:0x98])
    fs_oids = set()
    for fs_entry in range(max_file_systems):
        oid_start = 0x98 + 8 * fs_entry
        fs_oid = uint_to_int(csb_body[oid_start:oid_start + 8])
        if not fs_oid:
            continue
        fs_oids.add(fs_oid)

    return fs_oids


def parse_csb(csb):
    csb_body = csb[0x20:0x568]

    header = csb_body[:4] # 'NXSB'
    assert header == b'NXSB'
    block_size = uint_to_int(csb_body[4:8]) # default is 4096
    uuid = csb_body[0x28:0x38] # used as key for unwrapping
    omap_oid = uint_to_int(csb_body[0x80:0x88]) # omap_oid to locate the omap to find volume offsets
    fs_oids = get_fs_oids(csb_body)

    # locate container's keybag using nx_keylocker field
    keylocker_paddr = uint_to_int(csb_body[0x4f0:0x4f8])

    # block info for iterating to find most recent csb
    xp_desc_blocks = uint_to_int(csb_body[0x48:0x4b])
    xp_desc_base   = uint_to_int(csb_body[0x50:0x54])

    return block_size, uuid, keylocker_paddr, omap_oid, fs_oids, xp_desc_base, xp_desc_blocks


def get_offset_from_oid(oid, apfs_start, block_size):
    return apfs_start + oid * block_size


def parse_tree(tree, fs_oids, block_size):

    volume_addresses = []

    # get key data from TOC:
    table_space_offset = uint_to_int(tree[0x28:0x2a])
    table_space_len = uint_to_int(tree[0x2a:0x2c])
    start_of_key_area = table_space_offset + table_space_len + 0x38 # 0x38 = header + entries

    # b-tree structure is header (0x20 bytes) -> ToC -> keys -> free space -> values -> btree_info (0x28 bytes)
    end_of_value_area = block_size - 0x28

    tree_data = tree[0x38:]
    for m in range(len(fs_oids)):
        data_start = m * 4
        key_offset = uint_to_int(tree_data[data_start:data_start + 2]) # key offset is from the start of the key area downwards
        data_offset = uint_to_int(tree_data[data_start + 2:data_start + 4]) # data offset is from the end of the data area upwards

        # get to key area
        key_start = key_offset + start_of_key_area
        key_oid = uint_to_int(tree[key_start:key_start + 0x8])

        if key_oid not in fs_oids:
            print(f"Found key_oid {key_oid} in omap but not present in fs map. Skipping this volume")

        else:
            val_end = end_of_value_area - data_offset
            data_paddr = uint_to_int(tree[val_end + 0x8:val_end + 0x10])
            volume_addresses.append(data_paddr)

    return volume_addresses


def get_volumes(fp, block_size, apfs_start, tree, fs_oids):
    volume_addresses = parse_tree(tree, fs_oids, block_size)
    volumes_dict = dict()
    for v in volume_addresses:
        fp.seek(apfs_start + block_size * v)
        block_start = fp.read(block_size)
        obj_type, magic, uuid, encryption, name = parse_apsb_block(block_start)
        if obj_type == 13 and magic == b'APSB':
            volumes_dict[uuid] = {'start':v, 'name':name}
    print()
    print("[+] The following volumes are present:")
    for u in volumes_dict:
        print(f"{u.hex()} ({volumes_dict[u]['name'].decode()}) at {hex(volumes_dict[u]['start'] * block_size + apfs_start)}")

    return volumes_dict


def decrypt_volume_keybag(fp, volume_keybag_addr, block_size, apfs_struct_start, volume_uuid):
    volume_keybag_addr = volume_keybag_addr[:4].hex().zfill(8)
    volume_keybag_addr = bytearray.fromhex(volume_keybag_addr)[::-1]
    volume_keybag_addr = int(volume_keybag_addr.hex(),16)

    offset = block_size * volume_keybag_addr + apfs_struct_start
    fp.seek(offset)
    encrypted_keybag = fp.read(block_size)
    pt = AES_decrypt(encrypted_keybag, volume_keybag_addr, block_size, volume_uuid)

    return pt


def get_apfs_containers(fp):
    partition_dict = parse_partition_table(fp)
    apfs_containers = []
    for d in partition_dict:
        if hex_to_guid(partition_dict[d]['partition_type']) == HEX_APFS_CONTAINER_GUID:
            apfs_containers.append(partition_dict[d]['start'])

    return apfs_containers


def get_tree(fp, omap_oid, apfs_struct_start, block_size):
    omap_offset = get_offset_from_oid(omap_oid, apfs_struct_start, block_size)
    fp.seek(omap_offset + 0x30) # location for tree_oid
    tree_oid = fp.read(0x10)
    tree_oid = uint_to_int(tree_oid)
    tree_offset = get_offset_from_oid(tree_oid, apfs_struct_start, block_size)

    fp.seek(tree_offset)
    tree = fp.read(0x1000)

    return tree


def get_container_keybag(fp, apfs_struct_start, block_size, keylocker_paddr):
    # calculate offset to read from
    offs = block_size * keylocker_paddr + apfs_struct_start
    fp.seek(offs)
    data = fp.read(block_size)

    return data


def find_valid_csb(fp, block_size, xp_desc_base, xp_desc_blocks, apfs_start):
    max_xid = 0
    max_xid_paddr = 0

    for paddr in range(xp_desc_base, xp_desc_base + xp_desc_blocks):
        offs = block_size * paddr + apfs_start
        fp.seek(offs + 0x10)
        csb_xid = uint_to_int(fp.read(0x8))
        if csb_xid >= max_xid:
            max_xid = csb_xid
            max_xid_paddr = paddr

    print(f"[+] Found valid csb with xid {max_xid} at {hex(max_xid_paddr)}")
    return max_xid_paddr


def main():

    p = argparse.ArgumentParser()
    p.add_argument('filename')
    p.add_argument('-o', '--offset', help='[OPTIONAL] offset for APFS volume - may be necessary if partition table is not present')
    args = p.parse_args()

    filename = args.filename
    with open(filename, 'rb') as fp:

        if args.offset:
            apfs_offset = int(args.offset)
            apfs_containers = [apfs_offset]

        else:
            apfs_containers = get_apfs_containers(fp)

        if apfs_containers == []:
            print("[!] APFS volume GUID not found, exiting.")
            exit()

        for apfs_struct_start in apfs_containers:
            print(f"[+] APFS container starts at {hex(apfs_struct_start)}")
            fp.seek(apfs_struct_start)
            csb = fp.read(0x568)

            # read the first csb for initial info - then use this to iterate through all csbs and find the most recent one
            block_size, uuid, keylocker_paddr, omap_oid, fs_oids, xp_desc_base, xp_desc_blocks  = parse_csb(csb)
            valid_csb_paddr = find_valid_csb(fp, block_size, xp_desc_base, xp_desc_blocks, apfs_struct_start)

            fp.seek(valid_csb_paddr * block_size + apfs_struct_start)
            valid_csb = fp.read(block_size)
            block_size, uuid, keylocker_paddr, omap_oid, fs_oids, xp_desc_base, xp_desc_blocks  = parse_csb(valid_csb)

            encrypted_keybag = get_container_keybag(fp, apfs_struct_start, block_size, keylocker_paddr)
            # Unwrap container keybag using AES-XTS with container UUID as key
            starting_pt = AES_decrypt(encrypted_keybag, keylocker_paddr, block_size, uuid)

            # find all volumes to iterate through
            tree = get_tree(fp, omap_oid, apfs_struct_start, block_size)

            volumes_dict = get_volumes(fp, block_size, apfs_struct_start, tree, fs_oids)

            hash_set = set()
            for volume_uuid in volumes_dict:

                # find entry in container's keybag matching volume UUID and has KB_TAG_VOLUME_UNLOCK_RECORDS = 3. Its keydata is location of volume keybag.
                volume_keybag_addr = parse_keybag_entry(volume_uuid, starting_pt)

                # continue if encrypted keybag not found
                if not volume_keybag_addr:
                    continue

                # unwrap volume keybag using volume uuid AES-XTS
                pt = decrypt_volume_keybag(fp, volume_keybag_addr, block_size, apfs_struct_start, volume_uuid)

                # parse TLV for 80 first
                index_iterator = findall(TAG_DICT['unk_80']['tag'], pt)
                for starting_index in index_iterator:
                    starting_index, hash_set = TLV_iterate(starting_index, pt, hash_set, volume_uuid)

        print()
        print("[+] All hashes found.")

    return

if __name__ == "__main__":
    main()
