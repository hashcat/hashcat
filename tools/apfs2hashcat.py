#!/usr/bin/env python3

# For extracting APFS hashes to be cracked by hashcat modes 18300 ($fvde$2$) or 16700 ($fvde$1$).
# Usage: `python3 apfs2hashcat.py <apfs_image_file> -o <_apfs_container_offset>`
# The argument -o is optional. The script will attempt to read the partition table to find the location of APFS container(s). In the case that the partition table is missing or you want to specify a particular APFS container, use -o to provide the offset to the start of the container.

import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KNOWN_RECOVERY_UUIDS = ['EBC6C064-0000-11AA-AA11-00306543ECAC', 'EC1C2AD9-B618-4ED6-BD8D-50F361C27507']
TAG_DICT = {'unk_80' : {'tag' : b'\x80', 'expected_len' : 1},
            'uuid' : {'tag' : b'\x81', 'expected_len' : 0x10},
            'unk_82' : {'tag' : b'\x82'},
            'wrapped_kek' : {'tag' : b'\x83', 'expected_len' : 0x28},
            'iterations' : {'tag' : b'\x84'},
            'salt' : {'tag' : b'\x85', 'expected_len' : 0x10}}
HEX_APFS_CONTAINER_GUID = '7C3457EF-0000-11AA-AA11-00306543ECAC'
AES_XTS_SECTOR_SIZE = 512
EFI_PARTITION_HEADER = b'EFI PART'
OBJECT_TYPE_CONTAINER_KEYBAG = b'keys'
OBJECT_TYPE_VOLUME_KEYBAG = b'recs'
KB_TAG_VOLUME_UNLOCK_RECORDS = 3
WRAPPED_KEK_PACKED_OBJECT_TAG = 0xa3
KEK_PACKED_OBJECT_TAG = 0x30

def uint_to_int(b):
    return int(b[::-1].hex(), 16)

def hex_to_uuid(hex_str):
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}".upper()

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

def parse_apsb_block(block):
    obj_type = uint_to_int(block[24:26])
    magic = block[0x20:0x24]
    uuid = block[240:256]
    encryption = uint_to_int(block[264:272])
    name = block[704:960]

    return obj_type, magic, uuid, encryption, name

def parse_keybag_object(keybag_object):
    object_type = keybag_object[0x18:0x1c]
    return object_type

def parse_keybag_header(keybag_header):
    kl_nkeys = uint_to_int(keybag_header[2:4])
    kl_nbytes = uint_to_int(keybag_header[4:8])
    return kl_nkeys, kl_nbytes

def parse_keybag_entry_header(keybag_entry_header):
    ke_uuid = hex_to_uuid(keybag_entry_header[0:16].hex())
    ke_tag = uint_to_int(keybag_entry_header[16:18])
    ke_keylen = uint_to_int(keybag_entry_header[18:20])

    return ke_uuid, ke_tag, ke_keylen

def parse_container_keybag_entries(key_entries, nkeys):
    volume_unlock_record_dict = {}

    keydata_entries_dict = get_keydata_entries_dict(key_entries, nkeys)
    for ke_uuid in keydata_entries_dict:
        # only tag 3 is needed for constructing the hash
        volume_unlock_record = keydata_entries_dict[ke_uuid].get(KB_TAG_VOLUME_UNLOCK_RECORDS)
        if volume_unlock_record:
            # add to dict - should be up to only one entry per uuid
            volume_unlock_record_dict[ke_uuid] = volume_unlock_record
    return volume_unlock_record_dict

def get_keydata_entries_dict(key_entries, nkeys):
    keybag_entry_start = 0
    keydata_entries_dict = {}

    for key_entry in range(nkeys):
        keybag_entry_header = key_entries[keybag_entry_start : keybag_entry_start + 0x18]
        ke_uuid, ke_tag, ke_keylen = parse_keybag_entry_header(keybag_entry_header)
        keydata_start = keybag_entry_start + 0x18
        keydata_end   = keydata_start + ke_keylen
        keydata = key_entries[keydata_start : keydata_end]

        # make dict entry for uuid if doesn't exist
        if not keydata_entries_dict.get(ke_uuid):
            keydata_entries_dict[ke_uuid] = {}
        keydata_entries_dict[ke_uuid][ke_tag] = keydata

        # 16-byte aligned so round up to next block
        keybag_entry_start = ((keydata_start + ke_keylen + 15) // 16) * 16

    return keydata_entries_dict

def parse_wrapped_kek_packed_object(wrapped_kek, kek_uuid, volume_uuid):
    # print(wrapped_kek.hex())
    starting_pos = 0
    for t in TAG_DICT:
        tag = wrapped_kek[starting_pos:starting_pos + 1]
        length = uint_to_int(wrapped_kek[starting_pos + 1: starting_pos + 2])
        value = wrapped_kek[starting_pos + 2: starting_pos + 2 + length]
        starting_pos = starting_pos + 2 + length
        if TAG_DICT[t].get('tag') != tag:
            return None
        expected_len = TAG_DICT[t].get('expected_len') # use .get() since not all tags have an expected len
        if expected_len:
            if length != expected_len:
                return None

        TAG_DICT[t]['value'] = value

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
    # using UUID from the outer structure as kek uuid as this matches user plist entries
    print(f"\nFound password hash: {password_hash} (kek uuid: {(kek_uuid)}, volume uuid: {(volume_uuid)})")

    return

def parse_kek_packed_object(kek_packed_object, kek_uuid, volume_uuid):
    # expect 0x91 for first byte
    starting_pos = 1
    for _ in range(4): # tags 0x80, 0x81, 0x82, 0xa3 - we only want 0xa3 for wrapped kek
        tag = uint_to_int(kek_packed_object[starting_pos:starting_pos + 1])
        length = uint_to_int(kek_packed_object[starting_pos + 1: starting_pos + 2])
        value = kek_packed_object[starting_pos + 2: starting_pos + 2 + length]
        starting_pos = starting_pos + 2 + length

        if tag == WRAPPED_KEK_PACKED_OBJECT_TAG:
            parse_wrapped_kek_packed_object(value, kek_uuid, volume_uuid)

    return None

def parse_keybag_packed_value(keybag_packed_value, kek_uuid, volume_uuid):
    value_tag = uint_to_int(keybag_packed_value[:1])
    data_size = uint_to_int(keybag_packed_value[1:2])

    if value_tag == KEK_PACKED_OBJECT_TAG:
        parse_kek_packed_object(keybag_packed_value[2:], kek_uuid, volume_uuid)

    return

def parse_volume_keybag_entries(key_entries, nkeys, volume_uuid):
    keydata_entries_dict = get_keydata_entries_dict(key_entries, nkeys)

    for kek_uuid in keydata_entries_dict:
        if kek_uuid in KNOWN_RECOVERY_UUIDS: # skip recovery hash
            print(f"\n[!] Skipping known recovery uuid {kek_uuid}")
        else:
            keybag_packed_value = keydata_entries_dict[kek_uuid].get(KB_TAG_VOLUME_UNLOCK_RECORDS)
            if keybag_packed_value:
                parse_keybag_packed_value(keybag_packed_value, kek_uuid, volume_uuid)
    return

def parse_keybag_entry(pt, uuid):
    keybag_object = pt[:0x20]
    object_type = parse_keybag_object(keybag_object)

    keybag_header = pt[0x20:0x30]
    nkeys, nbytes = parse_keybag_header(keybag_header)
    key_entries = pt[0x30 : 0x30 + nbytes]

    if object_type[::-1] == OBJECT_TYPE_CONTAINER_KEYBAG: # container keybag
        volume_unlock_record_dict = parse_container_keybag_entries(key_entries, nkeys)
        return volume_unlock_record_dict

    if object_type[::-1] == OBJECT_TYPE_VOLUME_KEYBAG: # volume keybag
        parse_volume_keybag_entries(key_entries, nkeys, uuid)

    return

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
    if header != b'NXSB':
        print(f"[!] Invalid CSB header: {header.hex()} (expected 4e585342 for 'NXSB'). Skipping this block.")
        return None

    # header = csb_body[:4] # 'NXSB'
    # assert header == b'NXSB'
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
        print(f"{hex_to_uuid(u.hex())} ({volumes_dict[u]['name'].decode()}) at {hex(volumes_dict[u]['start'] * block_size + apfs_start)}")

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
    found_valid = False

    for paddr in range(xp_desc_base, xp_desc_base + xp_desc_blocks):
        offs = block_size * paddr + apfs_start
        fp.seek(offs)

        # Read the full block to validate header
        block = fp.read(block_size)

        # Check if this block has a valid NXSB header
        if len(block) < 0x568:
            print(f"[!] Block at paddr {hex(paddr)} is too short, skipping")
            continue

        csb_body = block[0x20:0x568]
        header = csb_body[:4]

        if header != b'NXSB':
            continue

        # Valid header found, now check XID
        csb_xid = uint_to_int(block[0x10:0x18])
        if csb_xid >= max_xid:
            max_xid = csb_xid
            max_xid_paddr = paddr
            found_valid = True

    if not found_valid:
        print("[!] No valid CSB found in the descriptor blocks")
        return None

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
            block_size, uuid, keylocker_paddr, omap_oid, fs_oids, xp_desc_base, xp_desc_blocks = parse_csb(csb)

            valid_csb_paddr = find_valid_csb(fp, block_size, xp_desc_base, xp_desc_blocks, apfs_struct_start)

            # If no valid CSB found, skip to next container
            if valid_csb_paddr is None:
                print(f"[!] No valid CSB found for container at {hex(apfs_struct_start)}, skipping to next container")
                continue

            fp.seek(valid_csb_paddr * block_size + apfs_struct_start)
            valid_csb = fp.read(block_size)
            result = parse_csb(valid_csb)

            # Final validation check
            if result is None:
                print(f"[!] Valid CSB at {hex(valid_csb_paddr)} became invalid on re-read, skipping to next container")
                continue

            block_size, uuid, keylocker_paddr, omap_oid, fs_oids, xp_desc_base, xp_desc_blocks = result
            encrypted_keybag = get_container_keybag(fp, apfs_struct_start, block_size, keylocker_paddr)
            # Unwrap container keybag using AES-XTS with container UUID as key
            starting_pt = AES_decrypt(encrypted_keybag, keylocker_paddr, block_size, uuid)

            # find all volumes to iterate through
            tree = get_tree(fp, omap_oid, apfs_struct_start, block_size)

            volumes_dict = get_volumes(fp, block_size, apfs_struct_start, tree, fs_oids)

            volume_unlock_record_dict = parse_keybag_entry(starting_pt, None)
            for volume_uuid in volumes_dict:

                # find entry in container's keybag matching volume UUID and has KB_TAG_VOLUME_UNLOCK_RECORDS = 3. Its keydata is location of volume keybag.
                volume_keybag_addr = volume_unlock_record_dict.get(hex_to_uuid(volume_uuid.hex()))

                # continue if encrypted keybag not found
                if not volume_keybag_addr:
                    continue

                # unwrap volume keybag using volume uuid AES-XTS
                pt = decrypt_volume_keybag(fp, volume_keybag_addr, block_size, apfs_struct_start, volume_uuid)
                volume_uuid = hex_to_uuid(volume_uuid.hex())
                parse_keybag_entry(pt, volume_uuid)


        print()
        print("[+] All hashes found.")

    return

if __name__ == "__main__":
    main()
