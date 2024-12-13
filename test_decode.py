import base64

def analyze_enc8_hash(enc8_hash):
    # Remove {enc8} prefix
    if enc8_hash.startswith('{enc8}'):
        enc8_hash = enc8_hash[6:]
    
    # Decode base64
    decoded = base64.b64decode(enc8_hash)
    
    # Split into hash and salt
    hash_portion = decoded[:-4]
    salt_portion = decoded[-4:]
    
    print(f'Analysis of enc8 hash:')
    print(f'Total length: {len(decoded)} bytes')
    print(f'Hash portion (hex): {hash_portion.hex()}')
    print(f'Salt portion (hex): {salt_portion.hex()}')
    print(f'Salt (little-endian): 0x{salt_portion[::-1].hex()}')
    
    return hash_portion, salt_portion

# Test vector
test_hash = '{enc8}EUxNIpbzGlnJbM4KKjYl+za4fmA='
analyze_enc8_hash(test_hash)
