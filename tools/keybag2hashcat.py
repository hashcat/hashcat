import argparse
import logging
import sys

__VERSION__ = '1.0.0'

# Set up logging
logger = logging.getLogger("keybag_logger")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class Keybag:
    def __init__(self, file_obj):
        self.size = 0
        self.uuid = ''
        self.version = 0
        self.type = 0
        self.hmackey = ''
        self.wrap = 0
        self.salt = ''
        self.iterations = 0
        

        self._read_header(file_obj)
        self.class_keys = self._read_class_keys(file_obj)

    def _read_header(self, file_obj):
        while True:
            tag = file_obj.read(4).decode('ascii')
            if tag == 'DATA': # DATA
                self.size = int.from_bytes(file_obj.read(4), byteorder='big')
            else:
                length = int.from_bytes(file_obj.read(4), byteorder='big')
                data = file_obj.read(length)

            if tag == 'VERS': # VERS
                self.version = int.from_bytes(data, byteorder='big')
            elif tag == 'TYPE':
                self.type = int.from_bytes(data, byteorder='big')
            elif tag == 'UUID':
                if not self.uuid:
                    self.uuid = data.hex()
                else:
                    file_obj.seek(-length - 8, 1)
                    break
            elif tag == 'HMCK':
                self.hmackey = data.hex()
            elif tag == 'WRAP':
                self.wrap = int.from_bytes(data, byteorder='big')
            elif tag == 'SALT':
                self.salt = data.hex()
            elif tag == 'ITER':
                self.iterations = int.from_bytes(data, byteorder='big')

    def _read_class_keys(self, file_obj):
        class_keys = {}

        for x in range(0, 10):
            stop = False
            while stop != True:
                tag = file_obj.read(4).decode('ascii')
                length = int.from_bytes(file_obj.read(4), byteorder='big')
                data = file_obj.read(length)
                # new class key
                if tag == 'UUID':
                    if class_keys.get(x):
                        if class_keys[x].get('UUID'):
                            file_obj.seek(-length - 8, 1)
                            stop = True
                        else:
                            class_keys[x] = {}
                    else:
                        class_keys[x] = {}
                if tag == 'WRAP' or tag == 'CLAS' or tag == 'KTYP':
                    class_keys[x][tag] = int.from_bytes(data, byteorder='big')
                else:
                    class_keys[x][tag] = data.hex()
                if file_obj.tell() > self.size:
                    stop = True
        return class_keys

    
    def print_keybag(self):
        logger.debug(f'SIZE: {self.size}')
        logger.debug(f'VERSION: {self.version}')
        logger.debug(f'TYPE: {self.type}')
        logger.debug(f'UUID: {self.uuid}')
        logger.debug(f'HMACKEY: {self.hmackey}')
        logger.debug(f'SALT: {self.salt}')
        logger.debug(f'ITERATIONS: {self.iterations}')
        for x, class_key in self.class_keys.items():
            logger.debug(f'{x}:')
            for key, value in class_key.items():
                logger.debug(f'    {key}: {value}')

def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Process a keybag file with a specified UID.")

    # Add the UID argument
    parser.add_argument(
        '--uid',
        type=str,
        required=True,
        help="Specify the device UID."
    )

    # Add the keybag file argument
    parser.add_argument(
        'keybag', 
        type=str, 
        help="Path to the keybag file."
    )

    # Add the debug flag
    parser.add_argument(
        '--debug', 
        action='store_true', 
        help="Enable debug logging."
    )

    # Parse the arguments
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)

    # Access the arguments
    uid = args.uid[0:32]
    keybag_path = args.keybag

    logger.debug(f'keybag2hashcat - version {__VERSION__}')

    with open(keybag_path, 'br') as keybag_file:
        kb = Keybag(keybag_file)
        kb.print_keybag()
        if not kb.version:
            logger.error('Unable to detect version of keybag, exiting.')
            sys.exit(1)
        if not kb.salt:
            logger.error('Unable to detect salt, exiting.')
            sys.exit(1)
        if not kb.iterations:
            logger.error('Unable to detect iterations, exiting.')
            sys.exit(1)
        if not kb.version in [3, 4]:
            logger.error(f'This script has not been tested with version {kb.version}.')
            sys.exit(1)
        if not kb.class_keys:
            logger.error(f'Unable to parse class keys, exiting.')
            sys.exit(1)
        classkey1 = 0
        for x, class_key in kb.class_keys.items():
            if class_key.get('WRAP') == 3:
                class_type = class_key.get('CLAS')
                if class_type == 1 or class_type == 33:
                    classkey1 = class_key.get('WPKY')
        
        if not classkey1:
            logger.error(f'Unable to find a classkey of class NSFileProtectionComplete.')
            logger.error(f'You could try to get another class key, make sure it is ktyp 0 and wrap 3.')
            exit(1)
    print(f'$uido${uid}${kb.salt}${kb.iterations}${classkey1}')
        

if __name__ == "__main__":
    main()
