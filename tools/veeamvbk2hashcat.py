import argparse
import binascii

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=False, help="VBK file")
    parser.add_argument('-s', '--seek', required=False, help="skip N bytes for large files")
    options = parser.parse_args()

    if options.file:
        with open(options.file, mode="rb") as f:
            if options.seek:
                f.seek(int(options.seek),0)
            while True:
                data = f.read(131072) #read data from file per 128 kBytes
                if not data:
                    break
                offs = data.find(b'\x60\x00\x00\x00\x10\x00\x00\x00\x40\x00\x00\x00')
                if offs != -1:
                    print("Found !")
                    part1 = data[offs+12:offs+12+96]
                    part2 = data[offs+12+96:offs+12+96+16]
                    part3 = data[offs+12+96+16:offs+12+96+16+64]
                    print(f'$vbk$*%s*10000*%s' % (binascii.hexlify(part3).decode('utf-8'), binascii.hexlify(part2).decode('utf-8')))
                    break
