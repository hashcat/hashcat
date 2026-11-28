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

# The test modules hand every container of an association group the same PBKDF2 iteration count,
# because hashcat refuses an -a 9 run whose hashes differ in it. Without one, cryptsetup times its
# own count as before.

extra_format_opts=()

if [[ -n "${3:-}" ]]; then
  extra_format_opts=(--pbkdf-force-iterations "$3")
fi

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"


size=20   # MiB

# Where the containers, the mount points and the log go. A caller that sets HCTEST_SCRATCH_DIR
# and HCTEST_MOUNT_DIR points these at a directory of its own, so nothing is left in /tmp when
# that directory is thrown away. Run by hand they keep the /tmp paths they always had.
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

  sudo sh -c 'echo "Hello from $1" > "$2/info.txt"' _ "$filename" "$mount_point"
  while ! sudo umount "$mount_point"; do
    # echo  "Waiting for $mount_point to become free..."
    sleep 1
  done
  sudo cryptsetup close "$name"

  # the mount point is empty now, and one is created per container
  rmdir "$mount_point" 2>/dev/null || true

  echo  "ext4: $filename" >> ${LOG_FILE}

  # only the device this call attached, other loop devices on the box are not ours to detach

  sudo losetup -d "$loopdev"
}

# A 128 bit key takes the CBC modes only, because XTS splits its key into two halves. A 512 bit key
# takes XTS only, because none of the ciphers has a 512 bit key of its own. The key size filter
# below skips the other picks. ESSIV is spelled with its hash, or dm-crypt refuses the mapping.

LUKS_TYPES=("luks1")
HASHES=("sha1" "sha256" "sha512" "ripemd160" "whirlpool")
CIPHERS=("aes" "serpent" "twofish")
CIPHER_MODES=("cbc-essiv:sha256" "cbc-plain64" "xts-plain64")
KEYSIZES=("128" "256" "512")

# Blowfish has an eight byte block, so XTS does not apply to it.
BLOWFISH_MODES=("cbc-plain64" "cbc-essiv:sha256")

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
    29514) # LUKS v1 SHA-1 + Blowfish
      cipher="blowfish"
      hash="sha1"
      cipher_mode=${BLOWFISH_MODES[$RANDOM % ${#BLOWFISH_MODES[@]}]}
      ;;
    29524) # LUKS v1 SHA-256 + Blowfish
      cipher="blowfish"
      hash="sha256"
      cipher_mode=${BLOWFISH_MODES[$RANDOM % ${#BLOWFISH_MODES[@]}]}
      ;;
    29534) # LUKS v1 SHA-512 + Blowfish
      cipher="blowfish"
      hash="sha512"
      cipher_mode=${BLOWFISH_MODES[$RANDOM % ${#BLOWFISH_MODES[@]}]}
      ;;
    29544) # LUKS v1 RIPEMD-160 + Blowfish
      cipher="blowfish"
      hash="ripemd160"
      cipher_mode=${BLOWFISH_MODES[$RANDOM % ${#BLOWFISH_MODES[@]}]}
      ;;
  esac

  case "$keysize" in
    128)
      case "$cipher_mode" in
        xts-plain64) continue ;;   # skip this pick, try again
      esac
      ;;
    512)
      case "$cipher_mode" in
        cbc-essiv:sha256|cbc-plain64) continue ;;   # skip this pick, try again
      esac
      ;;
  esac

  break # we good

done

file="${OUTPUT_DIR}/${luks_type}_${hash}_${cipher}_${cipher_mode}_${keysize}-size${size}MiB_$(date +%Y%m%d%H%M%S%6N).img"

# echo "Creating $file"
cipher_cipher_mode=${cipher}-${cipher_mode}
create_luks_container "$password" "$file" "$luks_type" "$cipher_cipher_mode" "$hash" "$keysize" "$size" "${extra_format_opts[@]}"


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
