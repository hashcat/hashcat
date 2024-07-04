import os
import re
import glob
import argparse

def extract_hashes_from_pcl(file_path):
    shiro_pattern = re.compile(br'\$shiro1\$SHA-512\$(\d+)\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+')
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        matches = shiro_pattern.finditer(data)
        extracted_hashes = []

        for match in matches:
            full_match = match.group(0).decode()
            print(f'[+] Found Shiro 1 hash: {full_match}')
            extracted_hashes.append(full_match)
            
        if not extracted_hashes:
            print(f"No Shiro 1 hashes found in {file_path}")
            return None

        return extracted_hashes

    except Exception as e:
        print(f"Failed to parse {file_path}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Extract Apache Shiro 1 hashes from .pcl files for use with Hashcat.")
    parser.add_argument("input_dir", help="Directory path containing the .pcl files")
    parser.add_argument("output_file", help="Output file to save the hashes")

    args = parser.parse_args()

    pcl_files = glob.glob(os.path.join(args.input_dir, '*.pcl'))
    all_hashes = []

    for pcl_file in pcl_files:
        print(f"Processing {pcl_file}")
        hashes = extract_hashes_from_pcl(pcl_file)
        if hashes:
            all_hashes.extend(hashes)

    if all_hashes:
        with open(args.output_file, 'w') as f:
            for hashcat_hash in all_hashes:
                f.write(f"{hashcat_hash}\n")
        print(f"Extracted hashes have been saved to {args.output_file}!\nTotal hashes: {len(all_hashes)}\nRun hashcat with mode 12150!")
    else:
        print("No hashes were extracted.")

if __name__ == '__main__':
    main()
