#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${1:-}" ]]; then
  echo "X Missing argument: LUKS mode"
  hashcat_module=""
else
  hashcat_module=$1
fi

if [[ -z "${2:-}" ]]; then
#   echo "X Missing argument: password"
  password=""
else
  password=$2
fi

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"


size=20   # MiB

# Where the containers, the mount points and the log go. tools/test.sh points these
# at the directory of the run that asked for them, so nothing is left in /tmp when
# the run is thrown away. Run by hand they keep the paths they always had.
OUTPUT_DIR="${HCTEST_SCRATCH_DIR:-/tmp/out}"
mkdir -p "$OUTPUT_DIR"
MOUNT_DIR="${HCTEST_MOUNT_DIR:-/tmp/mnt}"
mkdir -p "$MOUNT_DIR"
LOG_FILE="${OUTPUT_DIR}/luks1.log"
CMD_LOG_FILE="${OUTPUT_DIR}/luks1.cmd.log"

create_luks_container() {
  local PASSWORD="$1"
  local filename="$2"
  local luks_type="$3"
  local cipher="$4"
  local hash="$5"
  local keysize="$6"
  local size_mb="$7"
  shift 7
  local extra_opts=("$@")

  echo  "Creating $filename (size ${size_mb}MiB) with password length ${#PASSWORD}: $PASSWORD..." >> ${LOG_FILE}
  dd if=/dev/zero of="$filename" bs=1M count="$size_mb" status=none

  echo "sudo losetup --show -f "$filename"" >  ${CMD_LOG_FILE}
  loopdev=$(sudo losetup --show -f "$filename")

cat >> ${CMD_LOG_FILE} <<EOF
sudo cryptsetup luksFormat \
--batch-mode \
--type "$luks_type" \
--cipher "$cipher" \
--key-size $keysize \
--hash "$hash" \
${extra_opts:+${extra_opts[@]}} \
"$loopdev" <<< "$PASSWORD" # $filename
EOF

  if sudo cryptsetup luksFormat \
      --batch-mode \
      --type "$luks_type" \
      --cipher "$cipher" \
      --key-size $keysize \
      --hash "$hash" \
      "${extra_opts[@]}" \
      "$loopdev" <<< "$PASSWORD"; then
      true
      echo "Formatted: $filename" >> ${LOG_FILE}
  else
    echo "X Failed to format: $filename" >> ${LOG_FILE}
    sudo losetup -d "$loopdev"
    rm -f "$filename"
    return
  fi

  name="luks$(basename "$filename" | sha1sum | cut -c1-8)"

  if [ -e "/dev/mapper/$name" ]; then
    echo "! Device $name already exists. Closing it first." >> ${LOG_FILE}
    sudo cryptsetup close "$name" || true
  fi

  if sudo cryptsetup open "$loopdev" "$name" <<< "$PASSWORD"; then
    true
    echo "Decrypted: $filename" >> ${LOG_FILE}
  else
    echo  "X Failed to decrypt: $filename" >> ${LOG_FILE}
    sudo losetup -d "$loopdev"
    rm -f "$filename"
    return
  fi

  sudo mkfs.ext4 -q /dev/mapper/"$name" 2>> ${LOG_FILE}

  mount_point="$MOUNT_DIR/$name"
  mkdir -p "$mount_point"
  sudo mount /dev/mapper/"$name" "$mount_point"

  sudo sh -c 'echo "Hello from $filename" > "$mount_point/info.txt"'
  while ! sudo umount "$mount_point"; do
    # echo  "Waiting for $mount_point to become free..."
    sleep 1
  done
  sudo cryptsetup close "$name"

  # the mount point is empty now, and one is created per container
  rmdir "$mount_point" 2>/dev/null || true

  echo  "ext4: $filename" >> ${LOG_FILE}

  sudo losetup -D
}

# These options don't generate for me on Ubuntu 24.04; cbc-essiv_128, cbc-essiv_256, cbc-essiv_512, xts-plain64_128, cbc-plain64_512
# while true; do ./luks1.sh "14600" 'aaaaaaaa'; done 2>&1 | tee -a luks1.log
# less luks1.log | grep -i failed -B1 | grep img | cut -d'/' -f4- | cut -d'_' -f2-4 | rev | cut -d'-' -f2- | rev | sort -u
# ripemd160_aes-cbc-essiv_512
# ripemd160_aes-cbc-plain64_512
# ripemd160_serpent-cbc-essiv_512
# ripemd160_serpent-cbc-plain64_512
# ripemd160_twofish-cbc-essiv_128
# ripemd160_twofish-cbc-essiv_256
# ripemd160_twofish-cbc-essiv_512
# ripemd160_twofish-cbc-plain64_512
# ripemd160_twofish-xts-plain64_128
# sha1_aes-cbc-essiv_128
# sha1_aes-cbc-essiv_512
# sha1_aes-cbc-plain64_512
# sha1_aes-xts-plain64_128
# sha1_serpent-cbc-essiv_256
# sha1_serpent-cbc-essiv_512
# sha1_serpent-cbc-plain64_512
# sha1_twofish-cbc-essiv_128
# sha1_twofish-cbc-essiv_256
# sha1_twofish-cbc-essiv_512
# sha1_twofish-xts-plain64_128
# sha256_aes-cbc-essiv_128
# sha256_aes-cbc-essiv_256
# sha256_aes-cbc-essiv_512
# sha256_aes-cbc-plain64_512
# sha256_aes-xts-plain64_128
# sha256_serpent-cbc-essiv_128
# sha256_serpent-cbc-essiv_256
# sha256_serpent-cbc-essiv_512
# sha256_twofish-cbc-essiv_256
# sha256_twofish-cbc-essiv_512
# sha256_twofish-cbc-plain64_512
# sha256_twofish-xts-plain64_128
# sha512_aes-cbc-essiv_128
# sha512_aes-cbc-plain64_512
# sha512_aes-xts-plain64_128
# sha512_serpent-cbc-essiv_128
# sha512_serpent-cbc-essiv_256
# sha512_serpent-cbc-essiv_512
# sha512_twofish-cbc-essiv_128
# sha512_twofish-cbc-essiv_256
# sha512_twofish-cbc-plain64_512
# sha512_twofish-xts-plain64_128
# whirlpool_aes-cbc-plain64_512
# whirlpool_aes-xts-plain64_128
# whirlpool_serpent-cbc-essiv_128
# whirlpool_serpent-cbc-essiv_256
# whirlpool_serpent-cbc-essiv_512
# whirlpool_serpent-cbc-plain64_512
# whirlpool_twofish-cbc-essiv_128
# whirlpool_twofish-cbc-essiv_256
# whirlpool_twofish-cbc-essiv_512
# whirlpool_twofish-cbc-plain64_512

LUKS_TYPES=("luks1")
HASHES=("sha1" "sha256" "sha512" "ripemd160" "whirlpool")
CIPHERS=("aes" "serpent" "twofish")
CIPHER_MODES=("cbc-essiv" "cbc-plain64" "xts-plain64")
KEYSIZES=("128" "256" "512")

# --- random picks ---
while true; do
  luks_type=${LUKS_TYPES[$RANDOM % ${#LUKS_TYPES[@]}]}
  cipher=${CIPHERS[$RANDOM % ${#CIPHERS[@]}]}
  cipher_mode=${CIPHER_MODES[$RANDOM % ${#CIPHER_MODES[@]}]}
  hash=${HASHES[$RANDOM % ${#HASHES[@]}]}
  keysize=${KEYSIZES[$RANDOM % ${#KEYSIZES[@]}]}

  # filter out not supported combinations:
  case "$hashcat_module" in
    14600) # LUKS v1 (legacy)
      case "$hash" in
        whirlpool) continue ;;   # 14600 doesnt support any whirlpool hashes see kern_type_luks_t src/modules/module_14600.c; 14651, 14652, 14653 don't exist..
      esac
      ;;
    29511) # LUKS v1 SHA-1 + AES
      cipher="aes"
      hash="sha1"
      ;;
    29512) # LUKS v1 SHA-1 + Serpent
      cipher="serpent"
      hash="sha1"
      ;;
    29513) # LUKS v1 SHA-1 + Twofish
      cipher="twofish"
      hash="sha1"
      ;;
    29521) # LUKS v1 SHA-256 + AES
      cipher="aes"
      hash="sha256"
      ;;
    29522) # LUKS v1 SHA-256 + Serpent
      cipher="serpent"
      hash="sha256"
      ;;
    29523) # LUKS v1 SHA-256 + Twofish
      cipher="twofish"
      hash="sha256"
      ;;
    29531) # LUKS v1 SHA-512 + AES
      cipher="aes"
      hash="sha512"
      ;;
    29532) # LUKS v1 SHA-512 + Serpent
      cipher="serpent"
      hash="sha512"
      ;;
    29533) # LUKS v1 SHA-512 + Twofish
      cipher="twofish"
      hash="sha512"
      ;;
    29541) # LUKS v1 RIPEMD-160 + AES
      cipher="aes"
      hash="ripemd160"
      ;;
    29542) # LUKS v1 RIPEMD-160 + Serpent
      cipher="serpent"
      hash="ripemd160"
      ;;
    29543) # LUKS v1 RIPEMD-160 + Twofish
      cipher="twofish"
      hash="ripemd160"
      ;;
  esac

  case "$keysize" in
    128)
      case "$cipher_mode" in
        cbc-essiv|xts-plain64) continue ;;   # skip this pick, try again
      esac
      ;;
    256)
      case "$cipher_mode" in
        cbc-essiv) continue ;;   # skip this pick, try again
      esac
      ;;
    512)
      case "$cipher_mode" in
        cbc-essiv|cbc-plain64) continue ;;   # skip this pick, try again
      esac
      ;;
  esac

  break # we good

done

file="${OUTPUT_DIR}/${luks_type}_${hash}_${cipher}_${cipher_mode}_${keysize}-size${size}MiB_$(date +%Y%m%d%H%M%S%6N).img"

# echo "Creating $file"
cipher_cipher_mode=${cipher}-${cipher_mode}
create_luks_container "$password" "$file" "$luks_type" "$cipher_cipher_mode" "$hash" "$keysize" "$size"


${TDIR}/luks2hashcat.py $file | grep -vE '^[0-9]+$' > $file.hash

if [[ ${hashcat_module} -eq "14600" ]]; then
  # the legacy format reads the container itself, so it has to survive
  echo "$file"
else
  # every other mode is handed the extracted hash, and the container is 20 MiB of dead
  # weight the moment it is out. Without this a suite run leaves one image per generated
  # vector behind in OUTPUT_DIR, for good.
  rm -f "$file"

  echo "$file.hash"
fi
# echo ""
