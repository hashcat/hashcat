# Hashcat - Android Build Documentation

Revision: 1.1

Author: See `docs/credits.txt`

---

## Android Requirements

- Android 8.0 or higher (OpenCL 3.0 support)

- Termux app installed from [GitHub](https://github.com/termux/termux-app/releases/latest) or F-Droid

---

## Building Hashcat on Android

### Step 1: Install Dependencies

```bash
apt update
apt install git make clang python rust libiconv sse2neon
apt install libbz2 liblzma libsqlite openssl readline ncurses ncurses-utils
```

Install OpenCL Vendor Driver:

```bash
apt install -y opencl-vendor-driver
```

### Step 2: Verify OpenCL Support

```bash
apt install -y clinfo
clinfo -l
```

If clinfo shows nothing, you will need to fix OpenCL libraries.

### Step 3: Fix OpenCL Libraries (If Needed)

Auto-Fix (Try This First):

```bash
lib_path=$(find /system/lib64 /vendor/lib64 /system/lib /vendor/lib -name "android.hardware.graphics.common-V*-ndk.so" 2>/dev/null | head -1) && \
if [ -n "$lib_path" ]; then \
    mkdir -p $PREFIX/opt/vendor/lib && \
    ln -sf "$lib_path" "$PREFIX/opt/vendor/lib/android.hardware.graphics.common-V4-ndk.so" && \
    echo "[+] OpenCL linked: $lib_path"; \
else \
    echo "[-] Auto-fix failed - try manual linking"; \
fi
```

Manual Solution (If Auto-Fix Failed):

Find the missing graphics library:

```bash
find /system /vendor -name "android.hardware.graphics.common-V*-ndk.so" 2>/dev/null
```

Link the library:

```bash
mkdir -p $PREFIX/opt/vendor/lib
ln -s /path/to/found/library.so $PREFIX/opt/vendor/lib/android.hardware.graphics.common-V4-ndk.so
```

Example (64-bit):

```bash
ln -s /system/lib64/android.hardware.graphics.common-V5-ndk.so $PREFIX/opt/vendor/lib/android.hardware.graphics.common-V4-ndk.so
```

Example (32-bit):

```bash
ln -s /system/lib/android.hardware.graphics.common-V5-ndk.so $PREFIX/opt/vendor/lib/android.hardware.graphics.common-V4-ndk.so
```

### Step 4: Clone and Build Hashcat

```bash
git clone --depth 1 https://github.com/hashcat/hashcat.git
cd hashcat
make clean; make
```

### Step 5: Verify Build

```bash
./hashcat -I
./hashcat --version
```

> [!IMPORTANT]
> If you encounter an `Illegal instruction` error, you may need to adjust the target architecture. This is a known issue for some ARM devices ([#4579](https://github.com/hashcat/hashcat/issues/4579)).

```bash
sed -i 's/-march=native/-march=armv8-a/g' src/Makefile
sed -i 's/-mtune=native/-mtune=generic/g' src/Makefile

make clean
make
```

Verify the fix worked:

```bash
./hashcat -I
```

---

## OpenCL Troubleshooting

If Library Not Found on Device

Use ADB from your computer to find and copy the library:

```bash
# Find the library via ADB
adb shell "find /system /vendor -name '*graphics.common*' 2>/dev/null"

# Copy it to Android sdcard
adb shell "cp /system/lib64/android.hardware.graphics.common-V5-ndk.so /sdcard/"

# In Termux, move it
mkdir -p $PREFIX/opt/vendor/lib
mv /sdcard/android.hardware.graphics.common-V5-ndk.so $PREFIX/opt/vendor/lib/android.hardware.graphics.common-V4-ndk.so
```

Alternative OpenCL Drivers

If the vendor driver doesn't work:

```bash
apt remove opencl-vendor-driver
apt install mesa-opencl-icd-rusticl
```

Verify OpenCL Fix

```bash
clinfo | grep "Number of platforms"
# Should show: Number of platforms 1 or more
```

---

## Usage Examples

Safe Benchmark (Skips Memory-Intensive Algorithms)

```bash
./hashcat -b --skip=1700,22000,11300
```

Dictionary Attack

```bash
./hashcat -a 0 -m 0 hashes.txt wordlist.txt -O
```

Brute Force

```bash
./hashcat -a 3 -m 0 hash.txt "?l?l?l?l?l?d?d?d" -w 3
```

---

## Known Limitations

Memory-Intensive Algorithms

These algorithms exceed mobile memory limits and will crash:

- WPA2 (22000) - PBKDF2 memory requirements

- Bitcoin (11300) - Large kernel needs

- SHA512 (1700) - 512-bit operations

Recommended for Mobile

- MD4/MD5 (800-1200 MH/s)

- SHA1 (200-400 MH/s)

- SHA256 (80-150 MH/s)

- Dictionary attacks

- Educational use

---

## Performance Results (POCO X6 Pro)

| Algorithm | Speed     | Status  |
|-----------|-----------|---------|
| MD4       | 1179 MH/s | Working |
| MD5       | 853 MH/s  | Working |
| SHA1      | 282 MH/s  | Working |
| SHA256    | 111 MH/s  | Working |
| WPA2      | OOM       | Crashed |

Real-world: 9-character password cracked in 90 seconds at 694 MH/s

---

## Done

Your Android device is now ready for **hashcat!** Perfect for:

- Educational password security

- Portable penetration testing

- On-the-go hash verification

- Security research and learning

---

Tested on **POCO X6 Pro** | **Android 16** | **Termux 0.119.0-beta.3**
