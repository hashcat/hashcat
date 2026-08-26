#!/usr/bin/env python3

# this script is ran automatically; there should be no need to run this manually
#  used in .github/workflows/build.yml to generate docs/hashcat-example-hashes.md on every commit to master
# example usage: ./hashcat --example-hashes --machine-readable --quiet | python3 hashcat-example-hashes_machine-readable2md.py >> docs/hashcat-example_hashes.md


import sys
import json
import os
import re

# Replace LUKS v1 and v2 hashes, they're too big: Github no longer shows the .md "(Sorry about that, but we can’t show files that are this big right now.)"
EXAMPLE_HASH_REPLACEMENTS = {
    "14600": "https://hashcat.net/misc/example_hashes/hashcat_luks_testfiles.7z",
    "29511": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha1_aes_cbc-essiv_128.txt",
    "29512": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha1_serpent_cbc-plain64_256.txt",
    "29513": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha1_twofish_xts-plain64_256.txt",
    "29521": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha256_aes_cbc-plain64_128.txt",
    "29522": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha256_serpent_xts-plain64_512.txt",
    "29523": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha256_twofish_cbc-essiv_256.txt",
    "29531": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha512_aes_cbc-plain64_256.txt",
    "29532": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha512_serpent_cbc-essiv_128.txt",
    "29533": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha512_twofish_cbc-plain64_256.txt",
    "29541": "https://hashcat.net/misc/example_hashes/hashcat_luks_ripemd160_aes_cbc-essiv_256.txt",
    "29542": "https://hashcat.net/misc/example_hashes/hashcat_luks_ripemd160_serpent_xts-plain64_256.txt",
    "29543": "https://hashcat.net/misc/example_hashes/hashcat_luks_ripemd160_twofish_cbc-plain64_128.txt",
    "34100": "https://hashcat.net/misc/example_hashes/hashcat_luks2_argon2id_sha256_aes_xts-plain64_512.txt",
}

OPENCL_DIR = "../../OpenCL"
MODULES_DIR = "../../src/modules"
TESTS_DIR = "../../tools/test_modules"

OPENCL_ABBREV = {
    "_a0-pure": "a0p",
    "_a0-optimized": "a0o",
    "_a1-pure": "a1p",
    "_a1-optimized": "a1o",
    "_a3-pure": "a3p",
    "_a3-optimized": "a3o",
    "pure": "p",
    "optimized": "o",
}
OPENCL_ABBREV_SORT_ORDER = ["p", "o", "a0p", "a0o", "a1p", "a1o", "a3p", "a3o"]
order_map = {v: i for i, v in enumerate(OPENCL_ABBREV_SORT_ORDER)}

def md_remove_backticks_and_pipes(msg):
    return msg.replace('`', '').replace('|', '')

def sort_abbrevs(links):
    """Sort markdown links by their abbreviation order."""
    return sorted(links, key=lambda link: order_map.get(link.split("]")[0][1:], 999))

def find_opencl(zfilled_key, visited=None):
    """Return markdown links for OpenCL kernels, following redirect if needed."""
    if visited is None:
        visited = set()
    if zfilled_key in visited:
        return ""  # Avoid infinite loops
    visited.add(zfilled_key)

    kernels = []
    if os.path.isdir(OPENCL_DIR):
        for filename in sorted(os.listdir(OPENCL_DIR)):
            if zfilled_key in filename:
                for key, abbr in OPENCL_ABBREV.items():
                    if key in filename:
                        link = f"[{abbr}](/{OPENCL_DIR}/{filename})"
                        kernels.append(link)
                        break
    if kernels:
        return " " + ",&nbsp;".join(sort_abbrevs(kernels))

    # No kernels found → check module file for redirect
    module_file = os.path.join(MODULES_DIR, f"module_{zfilled_key}.c")
    if os.path.isfile(module_file):
        with open(module_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.search(r"static\s+const\s+u64\s+KERN_TYPE\s*=\s*(\d+);", line)
                if m:
                    redirect_key = str(m.group(1)).zfill(5)
                    return find_opencl(redirect_key, visited)
    return ""

def find_test(zfilled_key):
    """Return markdown links for Perl tests"""
    # List of TrueCrypt modes which have test containers
    TC_MODES = [
        "6211", "6212", "6213",
        "6221", "6222", "6223",
        "6231", "6232", "6233",
        "6241", "6242", "6243",
        "29311", "29312", "29313",
        "29321", "29322", "29323",
        "29331", "29332", "29333",
        "29341", "29342", "29343"
    ]

    # List of VeraCrypt modes which have test containers
    VC_MODES = [
        "13711", "13712", "13713",
        "13721", "13722", "13723",
        "13731", "13732", "13733",
        "13741", "13742", "13743",
        "13751", "13752", "13753",
        "13761", "13762", "13763",
        "13771", "13772", "13773",
        "13781", "13782", "13783",
        "29411", "29412", "29413",
        "29421", "29422", "29423",
        "29431", "29432", "29433",
        "29441", "29442", "29443",
        "29451", "29452", "29453",
        "29461", "29462", "29463",
        "29471", "29472", "29473",
        "29481", "29482", "29483"
    ]

    # List of LUKS modes which have test containers
    LUKS_MODES = [
        "14600",
        "29511", "29512", "29513",
        "29521", "29522", "29523",
        "29531", "29532", "29533",
        "29541", "29542", "29543"
    ]

    # Cryptoloop mode which have test containers
    CL_MODES = [
        "14511", "14512", "14513",
        "14521", "14522", "14523",
        "14531", "14532", "14533",
        "14541", "14542", "14543",
        "14551", "14552", "14553"
    ]

    ALL_MODES = TC_MODES + VC_MODES + LUKS_MODES + CL_MODES

    if zfilled_key in [m.zfill(5) for m in ALL_MODES]:
        return f"[:white_check_mark:](/tools/test.sh)"

    if os.path.isdir(TESTS_DIR):
        for filename in sorted(os.listdir(TESTS_DIR)):
            if zfilled_key in filename:
                return f"[:white_check_mark:](/{TESTS_DIR}/{filename})"

    #test not found
    return ":x:"

def main():
    input_data = sys.stdin.read()
    try:
        data = json.loads(input_data)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"❌ Invalid JSON input: {e}\n")
        sys.exit(1)

    footnote_map = {}
    footnote_counter = 1
    table_rows = []

    for key, value in data.items():
        name = value["name"]
        example_hash = value["example_hash"]
        example_pass = value["example_pass"]
        usage_notice = value["usage_notice"]
        advice_notice = value["advice_notice"]

        # Replace example_hash if key is in the replacement map
        if key in EXAMPLE_HASH_REPLACEMENTS:
            example_hash = EXAMPLE_HASH_REPLACEMENTS[key]

        footnote = ""
        if example_pass != "hashcat":
            footnote_val = f"Example password: `{example_pass}`"
            if footnote_val not in footnote_map:
                footnote_map[footnote_val] = footnote_counter
                footnote_counter += 1
            footnote += f"[^{footnote_map[footnote_val]}]"

        if usage_notice != "N/A":
            usage_notice = md_remove_backticks_and_pipes(usage_notice)
            footnote_val = f"Module usage notice: `{usage_notice}`"
            if footnote_val not in footnote_map:
                footnote_map[footnote_val] = footnote_counter
                footnote_counter += 1
            footnote += f"[^{footnote_map[footnote_val]}]"

        if advice_notice != "N/A":
            advice_notice = md_remove_backticks_and_pipes(advice_notice)
            footnote_val = f"Module advice notice: `{advice_notice}`"
            if footnote_val not in footnote_map:
                footnote_map[footnote_val] = footnote_counter
                footnote_counter += 1
            footnote += f"[^{footnote_map[footnote_val]}]"

        zfilled_key = key.zfill(5)
        opencl_links = find_opencl(zfilled_key)
        test_link = find_test(zfilled_key)

        # Make sure we refer to root for display
        opencl_links = opencl_links.replace('/../../', '/')
        test_link = test_link.replace('/../../', '/')

        name = md_remove_backticks_and_pipes(name)
        example_hash = md_remove_backticks_and_pipes(example_hash)

        row = f"| [`{key}`](/src/modules/module_{zfilled_key}.c) | `{name}`{footnote} | <sup> {opencl_links} </sup> | {test_link} | `{example_hash}` |"
        table_rows.append(row)

    # Print the table
    print("\n".join(table_rows))

    # Print footnotes
    if footnote_map:
        print()
        for val, num in footnote_map.items():
            print(f"[^{num}]: {val}")

if __name__ == "__main__":
    main()
