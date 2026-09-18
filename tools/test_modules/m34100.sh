#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${1:-}" ]]; then
#   echo "X Missing argument: password"
  password=""
else
  password=$1
fi

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"

# Different Argon2 options
ARGON_KDFS=("argon2id" "argon2i")
ARGON_TIMES=(4 5 6)
ARGON_MEMORY=(16 32 64 128 256 512 1024)
ARGON_THREADS=(1 2 3 4) # max is 4 https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/configure.ac?ref_type=heads#L787

declare -A CIPHERS=(
  ["aes"]="aes-xts-plain64"
#   ["serpent"]="serpent-xts-plain64" # not supported by 34100 yet
#   ["twofish"]="twofish-xts-plain64" # not supported by 34100 yet
)

size=20   # MiB

# Where the containers, the mount points and the log go. tools/test.sh points these
# at the directory of the run that asked for them, so nothing is left in /tmp when
# the run is thrown away. Run by hand they keep the paths they always had.
OUTPUT_DIR="${HCTEST_SCRATCH_DIR:-/tmp/out}"
mkdir -p "$OUTPUT_DIR"
MOUNT_DIR="${HCTEST_MOUNT_DIR:-/tmp/mnt}"
mkdir -p "$MOUNT_DIR"
LOG_FILE="${OUTPUT_DIR}/m34100.log"
CMD_LOG_FILE="${OUTPUT_DIR}/m34100.cmd.log"

create_luks_container() {
  local PASSWORD="$1"
  local filename="$2"
  local luks_type="$3"
  local cipher="$4"
  local hash="$5"
  local size_mb="$6"
  shift 6
  local extra_opts=("$@")

  echo  "Creating $filename (size ${size_mb}MiB) with password length ${#PASSWORD}: $PASSWORD..." >> ${LOG_FILE}
  dd if=/dev/zero of="$filename" bs=1M count="$size_mb" status=none

  loopdev=$(sudo losetup --show -f "$filename")

cat >> ${CMD_LOG_FILE} <<EOF
sudo cryptsetup luksFormat \
--batch-mode \
--type "$luks_type" \
--cipher "$cipher" \
--key-size 512 \
--hash "$hash" \
${extra_opts:+${extra_opts[@]}} \
"$loopdev" <<< "$PASSWORD" # $filename
EOF

  if sudo cryptsetup luksFormat \
      --batch-mode \
      --type "$luks_type" \
      --cipher "$cipher" \
      --key-size 512 \
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

# --- random picks ---
kdf=${ARGON_KDFS[$RANDOM % ${#ARGON_KDFS[@]}]}
time=${ARGON_TIMES[$RANDOM % ${#ARGON_TIMES[@]}]}
memory=${ARGON_MEMORY[$RANDOM % ${#ARGON_MEMORY[@]}]}
threads=${ARGON_THREADS[$RANDOM % ${#ARGON_THREADS[@]}]}
cipher_name=$(printf "%s\n" "${!CIPHERS[@]}" | shuf -n1)
cipher=${CIPHERS[$cipher_name]}

file="${OUTPUT_DIR}/luks2-${cipher_name}-${kdf}-t${time}-m${memory}-p${threads}-size${size}MiB_$(date +%Y%m%d%H%M%S%6N).img"

# echo -n "Creating $file with:"
# echo  " kdf=$kdf time=$time memory=$memory threads=$threads cipher=$cipher"

create_luks_container "$password" "$file" luks2 "$cipher" sha256 "$size" \
  --pbkdf "$kdf" \
  --pbkdf-force-iterations "$time" \
  --pbkdf-memory "$((memory * 1024))" \
  --pbkdf-parallel "$threads"

${TDIR}/luks2hashcat.py $file | grep -vE '^[0-9]+$' > $file.hash

# the caller is handed the extracted hash, so the container is 20 MiB of dead weight
# from here on. Without this a suite run leaves one image per generated vector behind
# in OUTPUT_DIR, for good.
rm -f "$file"

echo "$file.hash"
