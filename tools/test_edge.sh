#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

VERSION="1.1"

function usage()
{
  echo "> Edge Testing Suite, version ${VERSION}"
  echo ""
  echo "> Usage: $0 [<OPTIONS>]"
  echo ""
  echo "<OPTIONS>:"
  echo ""
  echo "-m / --hash-type <arg>              : set Hash Type (default: all)"
  echo "     --hash-type-min <arg>          : set min hash-type (default: 0)"
  echo "     --hash-type-max <arg>          : set max hash-type (default: 99999)"
  echo ""
  echo "-A / --attack-exec <arg>            : set Attack Exec Type (default: all. supported: 0 (Inside kernel), 1 (Outside kernel)"
  echo ""
  echo "-a / --attack-type <arg>            : set Attack Type or a list of comma-separated Attack Types"
  echo "                                      (default: all. supported: 0 (Straight), 1 (Combination), 3 (Brute-force), 4 (PCFG), 6 (Hybrid Wordlist + Mask), 7 (Hybrid Mask + Wordlist), 8 (Generic), 9 (Association), 12 (Hybrid, mask says where the word goes))"
  echo "-K / --kernel-type <arg>            : set Kernel Type (default: all. supported: 0 (Pure), 1 (Optimized))"
  echo ""
  echo "-t / --target-type <arg>            : set Target Type (default: all. supported: single, multi)"
  echo ""
  echo "-V / --vector-width <arg>           : set Vector Width or a list of comma-separated Vector Widths"
  echo "                                      (default: all. supported: 1, 2, 4, 8, 16)"
  echo "     --vector-width-min <arg>       : set min vector-width (default: 1)"
  echo "     --vector-width-max <arg>       : set max vector-width (default: 16)"
  echo ""
  echo "-d <arg>                            : set Device ID or a list of comma-separated Device IDs (default: not set)"
  echo ""
  echo "-D <arg>                            : set Device-Type ID or a list of comma-separated Device-Type IDs (default: not set)"
  echo ""
  echo "-r <arg>                            : set max runtime, in seconds, for each kernel execution (default: 270)"
  echo ""
  echo "     --metal-compiler-runtime <arg> : set max runtime, in seconds, for each kernel build using Apple Metal (default: 120)"
  echo ""
  echo "     --metal-backend                : exclude all hash types that do not work with Metal, exclude vector-width > 4, set --metal-compiler-runtime argument"
  echo ""
  echo "     --backend-devices-keepfree     : Keep specified percentage of device memory free (default: disabled. supported: from 1 to 100)"
  echo ""
  echo "     --allow-all-attacks            : Do not skip attack types other than Straight with hash types with attack exec outside kernel"
  echo ""
  echo "     --allow-self-tests             : Do not skip self tests"
  echo ""
  echo "     --skip-clean-cache             : Skip cleaning the kernel caches before starting the tests"
  echo ""
  echo "-f / --force                        : run hashcat using --force"
  echo ""
  echo "-v / --verbose                      : show debug messages (supported: -v or -vv)"
  echo ""
  echo "-h / --help                         : show this help, then exit"
  echo ""

  exit 1
}

function is_in_array()
{
  for e in "${@:2}"; do
    [ "$e" = "$1" ] && return 0
  done

  return 1
}

# The mask attacks do not test the correct password on its own. The mask puts candidates on one side
# of it or the other, and the correct one has to be picked out of them, which is what catches a kernel
# that reports a neighbour of the match. An attack reading a word list has no mask, so the same noise
# is written out as words here: the tail of the word replaced by every digit, with the word itself put
# back in the middle of them.
#
# The count is what -a 6 and -a 7 spend, 100 on a fast hash and 10 on a slow one, so every candidate
# still reaches the device in one launch.

function noise_words()
{
  local noise_word=$1
  local noise_slow=$2
  local noise_suffix=$3

  local cut_len=2

  if [ "${noise_slow}" -eq 1 ]; then
    cut_len=1
  fi

  if [ ${#noise_word} -lt ${cut_len} ]; then
    cut_len=${#noise_word}
  fi

  # An empty word has no variant of its own length, and a variant of another length would be testing
  # the length constraint rather than the password.

  if [ ${cut_len} -eq 0 ]; then
    printf '%s%s\n' "${noise_word}" "${noise_suffix}"
    return
  fi

  local tails=$(echo {0..9})

  if [ ${cut_len} -eq 2 ]; then
    tails=$(echo {0..9}{0..9})
  fi

  local stem="${noise_word:0:$(( ${#noise_word} - cut_len ))}"

  local half=$(( $(echo ${tails} | wc -w) / 2 ))
  local at=0

  for noise_tail in ${tails}; do
    if [ ${at} -eq ${half} ]; then
      printf '%s%s\n' "${noise_word}" "${noise_suffix}"
    fi

    printf '%s%s\n' "${stem}${noise_tail}" "${noise_suffix}"

    at=$((at + 1))
  done
}

# A -a 4 ruleset line is a value, a tab, and a probability, so a word holding a tab cannot be written
# into one. An empty word cannot be written into one either, because a grammar assembles a candidate
# out of terminals and the shortest terminal is one character long. Neither case says anything is
# wrong with the attack, so the test vector is skipped rather than failed.

function attack_rejects_word()
{
  local check_word=$1
  local check_attack=$2

  if [ "${check_attack}" -ne 4 ]; then
    return 1
  fi

  if [ ${#check_word} -eq 0 ]; then
    return 0
  fi

  if [[ "${check_word}" == *$'\t'* ]]; then
    return 0
  fi

  return 1
}

function clean_cache()
{
  echo "! cleaning cache ..."

  OS=$1

  if [ "$OS" == "Darwin" ]; then
    temp_dir=$(getconf DARWIN_USER_TEMP_DIR)
    cache_dir=$(getconf DARWIN_USER_CACHE_DIR)

    if [ -d "$temp_dir/homed" ]; then
      find $temp_dir -mindepth 1 -exec rm -rf {} + 2>/dev/null
    fi

    if [ -d "$cache_dir/com.apple.metalfe" ]; then
      rm -rf $cache_dir/com.apple.metalfe
    fi

    if [ -d "$cache_dir/com.apple.metal" ]; then
      rm -rf $cache_dir/com.apple.metal
    fi
  fi

  if [ -d "kernels" ]; then
    rm -rf kernels/*
  fi
}

export LC_CTYPE=C
export LANG=C

OUTD="test_edge_$(date +%s)"

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# A mode with OPTS_TYPE_BINARY_HASHFILE takes the path of a container file where every other mode
# takes a hash string, and test.pl prints that container base64 encoded. The base64 has to be
# decoded back into a file before hashcat sees it, which is what test.sh already does. A mode that
# also sets the OPTIONAL variant accepts the hash as text and its test module prints it that way,
# so those are left out.

BINARY_HASHFILE_TYPES=$(grep -l OPTS_TYPE_BINARY_HASHFILE "${TDIR}"/../src/modules/module_*.c | xargs -r grep -L OPTS_TYPE_BINARY_HASHFILE_OPTIONAL | sed -E 's/.*module_0*([0-9]+)\.c/\1/' | tr '\n' ' ')

UNAME=$(uname -s)

HASH_TYPE="all"
HASH_TYPE_MIN=0
HASH_TYPE_MAX=99999
ATTACK_EXEC="all"
ATTACK_EXECS="0 1"
ATTACK_TYPE="all"

# -a 9 is in "all" because -a 0 does not cover it. It builds the straight kernels with the salt
# taken from the global id rather than from the launch, so it is different source, a different
# cache entry, and its own failure modes: a kernel that shares one hash's salt across a workgroup
# is correct under every other attack and wrong under this one.

ATTACK_TYPES="0 1 3 4 6 7 8 9 12"

# Attack types 4, 8 and 9 hand hashcat one candidate per word, the same way attack type 0 does, so
# they cost the same on a slow hash and are not skipped along with the mask attacks.

WHOLE_WORD_ATTACK_TYPES="0 4 8 9"
KERNEL_TYPE="all"
TARGET_TYPE="all"
VECTOR_WIDTH="all"
VECTOR_WIDTHS="1 2 4 8 16"
VECTOR_WIDTH_MIN=1
VECTOR_WIDTH_MAX=16
DEVICE_TYPE=""

FORCE=0
VERBOSE=0
RUNTIME_MAX=270 # 4.5 min
METAL_BACKEND=0
METAL_COMPILER_RUNTIME=120
BACKEND_DEVICES_KEEPFREE=0
ALL_ATTACKS=0
SELF_TEST_DISABLE=1
CLEAN_CACHE_DISABLE=0

OPTS="--quiet --potfile-disable --machine-readable --logfile-disable"

SKIP_HASH_TYPES="" #2000 2500 2501 16800 16801 99999 32000"
SKIP_HASH_TYPES_METAL="21800"

METAL_FORCE_KEEPFREE="8900 22700 27700 28200 29800"

# 14000, 14100, 31500 and 31600 crack a plaintext other than the one the hash was made from,
# and 22000 and 22001 write the cracked line as the parts of the handshake rather than as the
# hash and the plaintext. Neither can be compared against what test.pl generated.

SKIP_OUT_MATCH_HASH_TYPES="14000 14100 22000 22001 31500 31600"
SKIP_SAME_SALT_HASH_TYPES="6600 7100 7200 8200 13200 13400 15300 15310 15900 15910 16900 18300 18900 20200 20300 20400 27000 27100 29700 29930 29940"
#SKIP_SAME_SALT_HASH_TYPES="400 3200 5800 6400 6500 6600 6700 7100 7200 7401 7900 8200 9100 9200 9400 10500 10901 12001 12200 12300 12400 12500 12700 12800 12900 13000 13200 13400 13600 14700 14800 15100 15200 15300 15310 15400 15600 15900 15910 16200 16300 16700 16900 18300 18400 18800 18900 19000 19100 19600 19700 19800 19900 20011 20012 20013 20200 20300 20400 21501 22100 22400 22600 23100 23300 23500 23600 23700 23900 24100 24200 24410 24420 24500 25300 25400 25500 25600 25800 26100 26500 26600 27000 27100 27400 27500 27600 28100 28400 28600 28800 28900 29600 29700 29910 29920 29930 29940 30600 31200 31900"

pyenv_free_threaded=0
pyenv local 2>/dev/null | grep 't-dev\|[0-9]t$'
if [ $? -eq 0 ]; then
  pyenv_free_threaded=1
fi

# Parse long options manually
#while [[ "$1" == --* ]]; do
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-devices-keepfree)
      BACKEND_DEVICES_KEEPFREE=$2
      shift 2

      # Validate: must be numeric and > 0
      if ! [[ "$BACKEND_DEVICES_KEEPFREE" =~ ^[0-9]+$ ]]; then
        echo "Error: --backend-devices-keepfree must be a positive integer."
        usage
      elif (( BACKEND_DEVICES_KEEPFREE < 1 || BACKEND_DEVICES_KEEPFREE > 100 )); then
        echo "Error: --backend-devices-keepfree must be between 1 and 100."
        usage
      fi
      ;;
    --metal-backend)
      METAL_BACKEND=1
      shift
      ;;
    --metal-compiler-runtime)
      if [[ "$2" =~ ^-?[0-9]+$ ]]; then
        METAL_COMPILER_RUNTIME=$2
      else
        echo "Error: --metal-compiler-runtime requires a valid argument (integer)"
        usage
      fi
      shift 2
      ;;
    --allow-all-attacks)
      ALL_ATTACKS=1
      shift
      ;;
    --allow-self-tests)
      SELF_TEST_DISABLE=0
      shift
      ;;
    --skip-clean-cache)
      CLEAN_CACHE_DISABLE=1
      shift
      ;;
    --vector-width-min)
      if [[ "$2" =~ ^(1|2|4|8|16)$ ]]; then
        VECTOR_WIDTH_MIN=$2
      else
        echo "Error: --vector-width-min requires a valid argument"
        usage
      fi
      shift 2
      ;;
    --vector-width-max)
      if [[ "$2" =~ ^(1|2|4|8|16)$ ]]; then
        VECTOR_WIDTH_MAX=$2
      else
        echo "Error: --vector-width-max requires a valid argument"
        usage
      fi
      shift 2
      ;;
    --hash-type-min)
      if [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 0 && $2 <= 99999 )); then
        HASH_TYPE_MIN=$2
      else
        echo "Error: --hash-type-min requires a valid argument (integer between 0 and 99999)"
        usage
      fi
      shift 2
      ;;
    --hash-type-max)
      if [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 0 && $2 <= 99999 )); then
        HASH_TYPE_MAX=$2
      else
        echo "Error: --hash-type-max requires a valid argument (integer between 0 and 99999)"
        usage
      fi
      shift 2
      ;;
    --help)
      usage
      ;;
    -?*)
      optstring="${1:1}" # strip leading '-'
      # Parse each char in the cluster
      for (( i=0; i<${#optstring}; i++ )); do
        opt="${optstring:i:1}"
        case "$opt" in
          r)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -r requires an argument"
              usage
            fi

            if [[ ! "$optarg" =~ ^[0-9]+$ ]]; then
              echo "Error: -r requires a valid argument (integer)"
              usage
            fi

            RUNTIME_MAX="$optarg"

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          v)
            (( VERBOSE++ ))
            if [ ${VERBOSE} -gt 2 ]; then
              echo "Error: too many -v specified (max: 2)"
              usage
            fi
            ;;
          f)
            FORCE=1
            ;;
          h)
            usage
            ;;
          d)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -d requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -d requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ ! "$optarg" =~ ^[0-9,]+$ ]]; then
              echo "Error: -d argument must be comma-separated numbers"
              usage
            fi

            OPTS="${OPTS} -d ${optarg}"

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          D)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -D requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -D requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ ! "$optarg" =~ ^[0-9,]+$ ]]; then
              echo "Error: -D argument must be comma-separated numbers"
              usage
            fi

            case "$optarg" in
              1) OPTS="${OPTS} -D 1"; DEVICE_TYPE="Cpu" ;;
              2) OPTS="${OPTS} -D 2"; DEVICE_TYPE="Gpu" ;;
              *) OPTS="${OPTS} -D $optarg"; DEVICE_TYPE="Cpu + Gpu" ;;
            esac

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          V)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -V requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -V requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ "$optarg" == "all" ]]; then
              :
            else
              VECTOR_WIDTH=""
              VECTOR_WIDTHS=""

              IFS=',' read -ra INPUT_VECTOR_WIDTHS <<< "$optarg"
              for vec in "${INPUT_VECTOR_WIDTHS[@]}"; do
                if [[ "$vec" =~ ^(1|2|4|8|16)$ ]]; then
                  VECTOR_WIDTHS+=" $vec"
                else
                  echo "Invalid Vector width: $vec"
                  usage
                fi
              done

              VECTOR_WIDTHS="$(echo "$VECTOR_WIDTHS" | xargs)"  # Trim leading/trailing spaces
            fi

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          t)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -t requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -t requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ "$optarg" == "single" ]]; then
              TARGET_TYPE=0
            elif [[ "$optarg" == "multi" ]]; then
              TARGET_TYPE=1
            elif [[ "$optarg" == "all" ]]; then
              :
            else
              echo "Invalid target type: $optarg"
              usage
            fi

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          m)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -m requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -m requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ "$optarg" == "all" ]]; then
              :
            elif [[ "$optarg" =~ ^[0-9]+$ ]]; then
              HASH_TYPE="$optarg"
            else
              echo "Invalid hash type: $optarg"
              usage
            fi

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          a)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -a requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -a requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ "$optarg" == "all" ]]; then
              :
            else
              ATTACK_TYPE=""
              ATTACK_TYPES=""

              IFS=',' read -ra INPUT_ATTACK_TYPES <<< "$optarg"
              for atk in "${INPUT_ATTACK_TYPES[@]}"; do
                if [[ "$atk" =~ ^(0|1|3|4|6|7|8|9|12)$ ]]; then
                  ATTACK_TYPES+=" $atk"
                else
                  echo "Invalid attack type: $atk"
                  usage
                fi
              done

              ATTACK_TYPES="$(echo "$ATTACK_TYPES" | xargs)"  # Trim leading/trailing spaces
            fi

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          K)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -K requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -K requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ "$optarg" == "all" ]]; then
              :
            elif [[ "$optarg" =~ ^(0|1)$ ]]; then
              KERNEL_TYPE="$optarg"
            else
              echo "Invalid kernel type: $optarg"
              usage
            fi

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          A)
            if (( i + 1 < ${#optstring} )); then
              optarg="${optstring:$((i+1))}"
              shift_inline=1
            elif [[ -n "$2" && "$2" != -* ]]; then
              optarg="$2"
              shift_inline=0
            else
              echo "Error: -A requires an argument"
              usage
            fi

            if [[ "$optarg" == -* ]]; then
              echo "Error: -A requires a valid argument, not another option (-$optarg)"
              usage
            fi

            if [[ "$optarg" == "all" ]]; then
              :
            elif [[ "$optarg" =~ ^(0|1)$ ]]; then

              ATTACK_EXEC=""
              ATTACK_EXECS=""

              IFS=',' read -ra INPUT_ATTACK_EXECS <<< "$optarg"
              for atk in "${INPUT_ATTACK_EXECS[@]}"; do
                if [[ "$atk" =~ ^(0|1)$ ]]; then
                  ATTACK_EXECS+=" $atk"
                else
                  echo "Invalid attack exec: $atk"
                  usage
                fi
              done

              ATTACK_EXECS="$(echo "$ATTACK_EXECS" | xargs)"  # Trim leading/trailing spaces
            else
              echo "Invalid kernel type: $optarg"
              usage
            fi

            [[ "$shift_inline" -eq 0 ]] && shift

            break
            ;;
          *)
            echo "Unknown option: -$opt"
            usage
            ;;
        esac
      done
      shift
      ;;
    --*)
      echo "Unknown long option: $1"
      usage
      ;;
    *)
      echo "empty $1"
      shift
      ;;
  esac
done

OPTS="${OPTS} --runtime ${RUNTIME_MAX}"

if [[ "$HASH_TYPE" != "all" && ( "$HASH_TYPE_MIN" -ne 0 || "$HASH_TYPE_MAX" -ne 99999 ) ]]; then
  echo "Error: cannot set --hash-type and --hash-type-min/--hash-type-max"
  usage
fi

if [[ "$VECTOR_WIDTH" != "all" && ( "$VECTOR_WIDTH_MIN" -ne 1 || "$VECTOR_WIDTH_MAX" -ne 16 ) ]]; then
  echo "Error: cannot set --vector-width and --vector-width-min/--vector-width-max"
  usage
fi

if [ ${SELF_TEST_DISABLE} -eq 1 ]; then
  OPTS="${OPTS} --self-test-disable"
fi

if [ ${FORCE} -eq 1 ]; then
  OPTS="${OPTS} --force"
fi

if [ $METAL_BACKEND -eq 1 ]; then
  VECTOR_WIDTHS_FILTER=""
  for v in $VECTOR_WIDTHS; do
    if [ "$v" -le 4 ]; then
      VECTOR_WIDTHS_FILTER="$VECTOR_WIDTHS_FILTER$v "
    fi
  done

  VECTOR_WIDTHS="$(echo "$VECTOR_WIDTHS_FILTER" | xargs)"

  if [ $VECTOR_WIDTH_MAX -gt 4 ]; then
    VECTOR_WIDTH_MAX=4
  fi

  if [ $METAL_COMPILER_RUNTIME -ne 120 ]; then
    OPTS="${OPTS} --metal-compiler-runtime ${METAL_COMPILER_RUNTIME}"
  fi
fi

if [ $BACKEND_DEVICES_KEEPFREE -gt 0 ]; then
  OPTS="${OPTS} --backend-devices-keepfree ${BACKEND_DEVICES_KEEPFREE}"
fi

if [ $CLEAN_CACHE_DISABLE -eq 0 ]; then
  clean_cache $UNAME
fi

if [ ${VERBOSE} -ge 1 ]; then
  echo "Global hashcat options selected: ${OPTS}"
fi

errors=0
startTime=$(date +%s)

mkdir -p ${OUTD} &> /dev/null

for hash_type in $(ls tools/test_modules/*.pm | cut -d'm' -f3 | cut -d'.' -f1 | awk '{print $1+=0}'); do

  if [ $HASH_TYPE != "all" ]; then
    if [ $HASH_TYPE -ne $hash_type ]; then continue; fi
  else
    if [ $hash_type -lt ${HASH_TYPE_MIN} ]; then continue; fi
    if [ $hash_type -gt ${HASH_TYPE_MAX} ]; then continue; fi
  fi

  if is_in_array "${hash_type}" ${SKIP_HASH_TYPES}; then
    echo "[ ${OUTD} ] > Skip processing Hash-Type ${hash_type} (common)" | tee -a ${OUTD}/test_edge.details.log
    continue
  fi

  if [ $METAL_BACKEND -eq 1 ]; then
    if is_in_array "${hash_type}" ${SKIP_HASH_TYPES_METAL}; then
      echo "[ ${OUTD} ] > Skip processing Hash-Type ${hash_type} (due to metal kernel build failed)" | tee -a ${OUTD}/test_edge.details.log
      continue
    fi
  fi

  deprecated=$(./hashcat -m ${hash_type} -HH | grep "Deprecated\\.\\." | awk '{print $2}')
  if [ "${deprecated}" == "Yes" ]; then
    echo "[ ${OUTD} ] > Skip processing Hash-Type ${hash_type} (is deprecated)" | tee -a ${OUTD}/test_edge.details.log
    continue
  fi

  if [ $pyenv_free_threaded -eq 0 ] && [ $hash_type -eq 72000 ]; then
    echo "[ ${OUTD} ] > Skip processing Hash-Type ${hash_type} (missing python 'free-threaded' library support)" | tee -a ${OUTD}/test_edge.details.log
    continue
  fi

  if [ $pyenv_free_threaded -eq 1 ] && [ $hash_type -eq 73000 ]; then
    if [ "$UNAME" == "Darwin" ]; then
      echo "[ ${OUTD} ] > Skip processing Hash-Type ${hash_type} (not supported on Apple and Windows with python 'free-threaded' library support)" | tee -a ${OUTD}/test_edge.details.log
    fi
    continue
  fi

  build_failed_err=0
  test_vectors_err=0

  for attack_type in ${ATTACK_TYPES}; do

    kernel_types=$(./hashcat -m ${hash_type} -HH | grep 'Kernel.Type(s' | cut -d: -f2 | xargs | sed -e 's/,//g')

    for kernel_type in ${kernel_types}; do

      kernel_type_pad=$(printf "%9s\n" ${kernel_type})

      CUR_OPTS="${OPTS}"

      optimized=0
      if [ "${kernel_type}" == "optimized" ]; then
        optimized=1
        CUR_OPTS="${CUR_OPTS} -O"
      fi

      if [ "$KERNEL_TYPE" != "all" ] && [ $KERNEL_TYPE -ne $optimized ]; then continue; fi

      slow_hash=0
      tmp_slow_hash=$(./hashcat -m ${hash_type} -HH | grep Slow\\.Hash | awk '{print $2}')
      if [ "${tmp_slow_hash}" == "Yes" ]; then
        slow_hash=1
      fi

      binary_hashfile=0
      if is_in_array "${hash_type}" ${BINARY_HASHFILE_TYPES}; then
        binary_hashfile=1
      fi

      if [ "$ATTACK_EXEC" != "all" ] && ! is_in_array "${slow_hash}" ${ATTACK_EXECS}; then continue; fi

      if [ $slow_hash -eq 1 ]; then
        if [ "$ATTACK_EXEC" == "all" ] || is_in_array "1" ${ATTACK_EXECS}; then
          if is_in_array "0" ${ATTACK_TYPES} && [ "$ALL_ATTACKS" -eq 0 ]; then
            is_in_array "${attack_type}" ${WHOLE_WORD_ATTACK_TYPES}
            if [ ${?} -eq 1 ]; then
              if [ $HASH_TYPE == "all" ] && [ $hash_type -ne 400 ]; then
                if [ ${VERBOSE} -ge 2 ]; then
                  echo "[ ${OUTD} ] > Skip processing Hash-Type ${hash_type} with Attack-Type ${attack_type} and Kernel-Type ${kernel_type} (disabled on ATTACK_EXEC_OUTSIDE_KERNEL by default)" | tee -a ${OUTD}/test_edge.details.log
                else
                  echo "[ ${OUTD} ] > Skip processing Hash-Type ${hash_type} with Attack-Type ${attack_type} and Kernel-Type ${kernel_type} (disabled on ATTACK_EXEC_OUTSIDE_KERNEL by default)" >> ${OUTD}/test_edge.details.log
                fi
                continue
              fi
            fi
          fi
        fi
      fi

      tmp_salt=$(./hashcat -m ${hash_type} -HH | grep Salt\\.Type)
      have_salt=$?

      if [ $have_salt -eq 0 ]; then
        salt_type=$(echo $tmp_salt | awk '{print $2}')

        if [ $salt_type == "Virtual" ]; then
          have_salt=1
        fi
      fi

      pt_hex=0
      pt_base58=0
      tmp_pw_type=$(./hashcat -m ${hash_type} -HH | grep Password\\.Type | awk '{print $2}')
      if [ "${tmp_pw_type}" == "HEX" ]; then
        pt_hex=1
      elif [ "${tmp_pw_type}" == "BASE58" ]; then
        pt_base58=1
      fi

      if [ $hash_type -eq 31500 ] || [ $hash_type -eq 31600 ]; then
        # using ?a instead of ?d with masks
        pt_base58=1
      fi

      echo "[ ${OUTD} ] # Export tests for Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}" >> ${OUTD}/test_edge.details.log

      edge_out="${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}.out"

      ./tools/test.pl edge ${hash_type} ${attack_type} ${optimized} 2>/dev/null > ${edge_out}

      if [ ${VERBOSE} -ge 2 ]; then
        cat ${edge_out}
      fi

      if [ $? -eq 0 ]; then

        # test.pl wraps the field in single quotes, so an empty hash arrives as two characters.
        # Strip the quotes and ask whether anything is left, rather than counting characters. A
        # length of 3 is a one character hash, which is what mode 99999 emits and is legitimate.

        check_hash=$(cat ${edge_out} | cut -d, -f8- | head -1 | sed -e "s/^'//" -e "s/'$//")
        if [ -z "${check_hash}" ]; then
          echo "[ ${OUTD} ] !> error detected with Hash-Type ${hash_type}: empty test vectors" | tee -a ${OUTD}/test_edge.details.log
          ((errors++))
          break
        fi

        for vector_width in ${VECTOR_WIDTHS}; do

          if [ "$VECTOR_WIDTH" == "all" ]; then
            if [ ${vector_width} -lt ${VECTOR_WIDTH_MIN} ]; then continue; fi
            if [ ${vector_width} -gt ${VECTOR_WIDTH_MAX} ]; then continue; fi
          fi

          CUR_OPTS_V="${CUR_OPTS} --backend-vector-width ${vector_width}"

          if [ $pt_hex -eq 1 ]; then
            CUR_OPTS_V="${CUR_OPTS_V} --hex-charset"
          fi

          if [ $METAL_BACKEND -eq 1 ]; then
            if is_in_array "${hash_type}" ${METAL_FORCE_KEEPFREE}; then
              CUR_OPTS_V="${CUR_OPTS_V} --backend-devices-keepfree 1"
            fi
          fi

          # The cracked hashes are read out of the outfile rather than out of what hashcat printed.
          # A warning goes to stdout next to the results, "High memory usage by desktop or other apps
          # detected" for one, and comparing that against the expected plaintext fails a test that
          # passed. The default outfile format is the hash and the plaintext, which is what the
          # comparison already expects.

          outfile="${OUTD}/out_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.outfile"

          CUR_OPTS_V="${CUR_OPTS_V} --outfile ${outfile}"

          # single hash
          if [ $TARGET_TYPE == all ] || [ $TARGET_TYPE == 0 ]; then

            echo "[ ${OUTD} ] # Processing Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type single" | tee -a ${OUTD}/test_edge.details.log

            cnt=$(wc -l ${edge_out} | awk '{print $1}')

            for ((i = 1; i <= cnt; i++)); do
              word_compare=None
              word_len=$(cat ${edge_out} | cut -d, -f4 | head -${i} | tail -1)
              salt_len=$(cat ${edge_out} | cut -d, -f5 | head -${i} | tail -1)
              word=$(cat ${edge_out} | cut -d, -f6 | head -${i} | tail -1)
              salt=$(cat ${edge_out} | cut -d, -f7 | head -${i} | tail -1)
              hash=$(cat ${edge_out} | cut -d, -f8- | head -${i} | tail -1)

              x="echo -n '${word}'"

              if [ ${hash_type} -eq 20510 ]; then
                word_compare="echo -n '${word}'"
                x="echo -n '${word}' | cut -b7-"
              fi

              if [ ${have_salt} -eq 1 ]; then
                salt_len="None"
                salt=
              else
                z="echo -n '${salt}'"
                salt=$(eval $z)
              fi

              word=$(eval $x)

              if [ ${hash_type} -eq 20510 ]; then
                if [ "$word_len" -le 6 ] && [ "${#word}" -eq 0 ] && { [ "$attack_type" -eq 3 ] || [ "$attack_type" -eq 6 ] || [ "$attack_type" -eq 7 ] || [ "$attack_type" -eq 12 ]; }; then
                 echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type multi (word len <= 6 not allowed with attack-type 3, 6, 7 and 12)" | tee -a ${OUTD}/test_edge.details.log
                 continue
                fi
              fi

              if attack_rejects_word "${word}" ${attack_type}; then
                echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Test ID ${i}, Target-Type single (this word cannot be written into the attack's input)" | tee -a ${OUTD}/test_edge.details.log
                continue
              fi

              if [ ${VERBOSE} -ge 1 ]; then
                echo "[ ${OUTD} ] > Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Test ID ${i}, Word len ${word_len}, Salt len ${salt_len}, Word '${word}', Salt '${salt}', Hash ${hash}" | tee -a ${OUTD}/test_edge.details.log
              else
                echo "[ ${OUTD} ] > Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Test ID ${i}, Word len ${word_len}, Salt len ${salt_len}, Word '${word}', Salt '${salt}', Hash ${hash}" >> ${OUTD}/test_edge.details.log
              fi

              # These modes take the path of a container file, and hashcat prints that path where a
              # cracked hash would normally go, so the output comparison further down matches on it
              # too. m05200.pm and m09000.pm print the container base64 encoded and it has to be
              # decoded back into a file. m14600.pm builds a real LUKS image and prints its path,
              # so that one is already a container and must be passed through untouched.

              if [ ${binary_hashfile} -eq 1 ]; then
                y="echo -n ${hash}"
                hash=$(eval $y)

                if [ -f "${hash}" ]; then
                  hash_file="${hash}"
                else
                  hash_file="${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${i}.hashfile"

                  echo -n "${hash}" | base64 -d > ${hash_file}
                fi

                hash="${hash_file}"
              fi

              CMD=""

              if [ "${attack_type}" -eq 0 ]; then
                #echo ${word} > test_${hash_type}_${kernel_type}_${attack_type}_${i}.word

                CMD="echo ${word} | ./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 0"
              elif [ "${attack_type}" -eq 1 ]; then
                word=$(eval $x)

                if [ "${word_len}" -eq 2 ]; then
                  word_1=$(echo $word | cut -c -1)
                  word_2=$(echo $word | cut -c 2-)
                elif [ "${word_len}" -gt 2 ]; then
                  word_1_cnt=$((word_len/2))

                  word_1=$(echo $word | cut -c -${word_1_cnt})

                  ((word_1_cnt++))

                  word_2=$(echo $word | cut -c ${word_1_cnt}-)
                fi

                echo ${word_1} > ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}.1.word
                echo ${word_2} > ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}.2.word

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 1 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}.1.word ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}.2.word"
              elif [ "${attack_type}" -eq 3 ]; then

                if [ $pt_hex -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?b"
                elif [ $pt_base58 -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?a?a"
                else
                  if [ "${word_len}" -eq 2 ]; then
                    word_1="${word%?}"
                    mask_1="?d"
                  elif [ "${slow_hash}" -eq 1 ]; then
                    word_1="${word%??}"
                    mask_1="?d?d"
                  else
                    word_1="${word%???}"
                    mask_1="?d?d?d"
                  fi
                fi

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 3 ${word_1}${mask_1}"
              elif [ "${attack_type}" -eq 6 ]; then

                if [ $pt_hex -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?b"
                elif [ $pt_base58 -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?a?a"
                else
                  if [ "${word_len}" -eq 2 ] || [ "${slow_hash}" -eq 1 ]; then
                    word_1="${word%?}"
                    mask_1="?d"
                  else
                    word_1="${word%??}"
                    mask_1="?d?d"
                  fi
                fi

                echo -n ${word_1} > ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_1.word

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 6 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_1.word ${mask_1}"
              elif [ "${attack_type}" -eq 7 ]; then

                if [ $pt_hex -eq 1 ]; then
                  word_1="${word#??}"
                  mask_1="?b"
                elif [ $pt_base58 -eq 1 ]; then
                  word_1="${word#??}"
                  mask_1="?a?a"
                else
                  if [ "${word_len}" -eq 2 ] || [ "${slow_hash}" -eq 1 ]; then
                    word_1="${word#?}"
                    mask_1="?d"
                  else
                    word_1="${word#??}"
                    mask_1="?d?d"
                  fi
                fi

                echo -n ${word_1} > ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_2.word

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 7 ${mask_1} ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_2.word"
              elif [ "${attack_type}" -eq 12 ]; then

                # A mask on both sides of the word is the shape -a 6 and -a 7 cannot reach, so that is
                # what is tested here, and the two sides share the budget those two spend on one. A
                # word with nothing left once a mask character is taken off each end gets the mask in
                # front of it instead, and so does a slow hash, whose budget is one character. One ?b
                # is already 256 candidates, so the hex charset stays in front as well.

                mask_c="?d"
                cut_len=1
                both_sides=1

                if [ $pt_hex -eq 1 ]; then
                  mask_c="?b"
                  cut_len=2
                  both_sides=0
                elif [ $pt_base58 -eq 1 ]; then
                  mask_c="?a"
                fi

                if [ ${slow_hash} -eq 1 ]; then
                  both_sides=0
                fi

                mid_len=$((${#word} - cut_len - cut_len))

                if [ ${both_sides} -eq 1 ] && [ ${mid_len} -ge 1 ]; then
                  word_1="${word:${cut_len}:${mid_len}}"
                  mask_1="${mask_c}?w${mask_c}"
                else
                  word_1="${word:${cut_len}}"
                  mask_1="${mask_c}?w"
                fi

                echo -n "${word_1}" > ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_12.word

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 12 ${mask_1} ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_12.word"
              elif [ "${attack_type}" -eq 4 ]; then

                # The smallest ruleset that produces a named list of candidates. X is the flat token, so
                # its entries carry their own length and always live in Context/1.txt, and a grammar of
                # one shape at probability 1 makes the run exactly as long as the list under it.

                ruleset="${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}.ruleset"

                mkdir -p ${ruleset}/Grammar ${ruleset}/Context

                printf 'X1\t1.0\n' > ${ruleset}/Grammar/grammar.txt

                noise_words "${word}" ${slow_hash} $'\t1.0' > ${ruleset}/Context/1.txt

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 4 ${ruleset}"
              elif [ "${attack_type}" -eq 8 ]; then

                # -a 0 with no wordlist already runs the stdin feed, so the one worth naming here is the
                # wordlist feed, which nothing else in this script reaches. The noise around the word
                # also puts it at an offset the feed has to seek to, rather than at the front.

                noise_words "${word}" ${slow_hash} "" > ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_8.word

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 8 wordlist ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_8.word"
              elif [ "${attack_type}" -eq 9 ]; then

                # -a 9 named a wordlist pairs word N with hash N. The other form of it cuts the
                # candidate off the front of the hash line instead, which needs a separator the word is
                # not allowed to contain and refuses an empty candidate, so neither edge is reachable
                # that way.
                #
                # One candidate per salt is what the attack is, so this is the one attack here that
                # cannot be given noise around the word. A second word would be a second salt.

                echo "${word}" > ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_9.word

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash} -a 9 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${i}_9.word"
              fi

              cmd_out="${OUTD}/cmd_${hash_type}_${kernel_type}_${attack_type}_${i}.single.log"

              rm -f ${outfile}

              eval ${CMD} &> ${cmd_out}
              retVal=$?

              #echo "RET: $retVal"

              cat ${cmd_out} >> ${OUTD}/test_edge.details.log

              if [ "${retVal}" -ne 0 ]; then
                if [ "${retVal}" -eq 252 ]; then
                  echo "[ ${OUTD} ] > Skipping current tests due to unmet memory requirements ..." | tee -a ${OUTD}/test_edge.details.log
                  break
                fi

                echo '```' | tee -a ${OUTD}/test_edge.details.log
                echo "[ ${OUTD} ] !> error ($retVal) detected with CMD: ${CMD}" | tee -a ${OUTD}/test_edge.details.log
                echo "[ ${OUTD} ] !> Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Test ID ${i}, Word len ${word_len}, Salt len ${salt_len}, Word '${word}', Hash ${hash}" | tee -a ${OUTD}/test_edge.details.log
                cat ${cmd_out} | tee -a ${OUTD}/test_edge.details.log
                echo '```' | tee -a ${OUTD}/test_edge.details.log
                ((errors++))

                if [ "${retVal}" -eq 250 ]; then
                  echo "[ ${OUTD} ] > Skipping current tests due to build error ..." | tee -a ${OUTD}/test_edge.details.log
                  break
                fi
              else
                if is_in_array "${hash_type}" ${SKIP_OUT_MATCH_HASH_TYPES}; then
                  echo "[ ${OUTD} ] > Skip output check for Hash-Type ${hash_type} (due to collisions)" >> ${OUTD}/test_edge.details.log
                  continue
                fi

                ./hashcat -m ${hash_type} -HH | grep 'Keep.Guessing.......: Yes' &> /dev/null
                if [ $? -eq 0 ]; then
                  echo "[ ${OUTD} ] > Skip output check for Hash-Type ${hash_type} (due to keep guessing)" >> ${OUTD}/test_edge.details.log
                  continue
                fi

                out=$(cat ${outfile} 2>/dev/null | sed -e 's/    (user password.*$//g')

                x="echo -n ${hash}"
                hash=$(eval $x)

                md5_1=$(echo ${out} | md5sum | cut -d' ' -f1)

                hc_out="${hash}:${word}"

                if [ "${word_compare}" != "None" ]; then
                  word_tmp=$(eval $word_compare)
                  hc_out="${hash}:${word_tmp}"
                fi

                md5_2=$(echo ${hc_out} | md5sum | cut -d' ' -f1)

                if [ $md5_1 != $md5_2 ]; then
                  echo '```' | tee -a ${OUTD}/test_edge.details.log
                  echo "[ ${OUTD} ] !> error detected (output don't match) with CMD: ${CMD}" | tee -a ${OUTD}/test_edge.details.log
                  echo "[ ${OUTD} ] !> Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Test ID ${i}, Word len ${word_len}, Salt len ${salt_len}, Word '${word}', Salt '${salt}', Hash ${hash}" | tee -a ${OUTD}/test_edge.details.log
                  echo "! output" | tee -a ${OUTD}/test_edge.details.log
                  echo | tee -a ${OUTD}/test_edge.details.log
                  echo "${out}" | tee -a ${OUTD}/test_edge.details.log
                  echo | tee -a ${OUTD}/test_edge.details.log
                  echo "! expected output" | tee -a ${OUTD}/test_edge.details.log
                  echo | tee -a ${OUTD}/test_edge.details.log
                  echo "${hc_out}" | tee -a ${OUTD}/test_edge.details.log
                  echo '```' | tee -a ${OUTD}/test_edge.details.log
                  ((errors++))
                fi
              fi
            done
          fi

          # multi hash
          if [ $TARGET_TYPE == all ] || [ $TARGET_TYPE == 1 ]; then
            cnt_max=-1
            tmp_cnt_max=$(./hashcat -m ${hash_type} -HH | grep Hashes\\.Count\\.Max | awk '{print $2}')
            if [[ $tmp_cnt_max =~ ^-?[0-9]+$ ]]; then
              cnt_max=$tmp_cnt_max
            fi

            if [ $hash_type -eq 20510 ]; then
              cnt_max=1
            fi

            # One binary container holds one hash, and 5200 and 9000 set neither
            # module_hash_binary_count nor module_hash_binary_parse, so hashcat loads exactly one
            # hash from the file. Neither mode has a multi hash form to test.

            if [ ${binary_hashfile} -eq 1 ]; then
              cnt_max=1
            fi

            if [ $cnt_max -eq 1 ]; then
              # cannot exec multi-hash because this hash_type allow max 1 hash at time
              echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type multi (max 1 hash at time allowed)" | tee -a ${OUTD}/test_edge.details.log
              cnt=0
              continue
            fi

            # -a 9 gives one candidate to each salt, and every hash of an unsalted mode is on the one
            # salt, so a second hash there would have no second candidate to go with it.

            if [ ${attack_type} -eq 9 ] && [ ${have_salt} -eq 1 ]; then
              echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type multi (every hash is on the same salt, and -a 9 takes one candidate per salt)" | tee -a ${OUTD}/test_edge.details.log
              cnt=0
              continue
            fi

            # check if hash_type cannot crack multiple hashes with the same salt
            same_salt=1

            is_in_array "${hash_type}" ${SKIP_SAME_SALT_HASH_TYPES}
            if [ ${?} -eq 1 ]; then
              multi_hashes_same_salt_allowed=$(./hashcat -m ${hash_type} -HH | grep Hashes\\.w/\\.Same\\.Salt | awk '{print $2}')
              if [ "${multi_hashes_same_salt_allowed}" == "Not" ]; then
                same_salt=0
              fi
            fi

            # Two hashes on one salt share a candidate under -a 9 whatever the hash mode allows, so the
            # salt has to be unique here even where the mode would accept a repeat.

            if [ ${attack_type} -eq 9 ]; then
              same_salt=0
            fi

            cnt=$(wc -l ${edge_out} | awk '{print $1}')

            if [ $cnt -eq 0 ]; then
              echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type multi (due to no valid test vectors)" | tee -a ${OUTD}/test_edge.details.log
              continue
            fi

            echo "[ ${OUTD} ] # Processing Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type multi" | tee -a ${OUTD}/test_edge.details.log

            CMD=""
            SALTS_VAL=""

            hash_cnt=0

            hash_in="${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.hashes"

            ruleset="${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.ruleset"

            if [ ${attack_type} -eq 4 ]; then
              rm -rf ${ruleset}

              mkdir -p ${ruleset}/Grammar ${ruleset}/Context

              printf 'X1\t1.0\n' > ${ruleset}/Grammar/grammar.txt
            fi

            for ((i = 1; i <= cnt; i++)); do

              # limit to cnt_max if is set
              if [ ${cnt_max} -gt 1 ] && [ ${hash_cnt} -gt ${cnt_max} ]; then continue; fi

              word_compare=None
              word_len=$(cat ${edge_out} | cut -d, -f4 | head -${i} | tail -1)
              salt_len=$(cat ${edge_out} | cut -d, -f5 | head -${i} | tail -1)
              word=$(cat ${edge_out} | cut -d, -f6 | head -${i} | tail -1)
              salt=$(cat ${edge_out} | cut -d, -f7 | head -${i} | tail -1)
              hash=$(cat ${edge_out} | cut -d, -f8- | head -${i} | tail -1)

              x="echo -n '${word}'"
              y="echo -n ${hash}"

              if [ "${hash_type}" == "20510" ]; then
                word_compare="echo -n '${word}'"
                x="echo -n '${word}' | cut -b7-"
              fi

              if [ ${have_salt} -eq 1 ]; then
                salt_len="None"
                salt=
              else
                z="echo -n '${salt}'"
                salt=$(eval $z)

                # skip hashes with same salt if are not allowed
                if [ ${same_salt} -eq 0 ]; then
                  if is_in_array "${salt_len}:${salt}" ${SALTS_VAL}; then
                    continue
                  fi
                  if [ ${#SALTS_VAL} -eq 0 ]; then
                    SALTS_VAL="${salt_len}:${salt}"
                  else
                    SALTS_VAL="${SALTS_VAL} ${salt_len}:${salt}"
                  fi
                fi
              fi

              word=$(eval $x)
              hash=$(eval $y)

              if attack_rejects_word "${word}" ${attack_type}; then
                echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Test ID ${i}, Target-Type multi (this word cannot be written into the attack's input)" | tee -a ${OUTD}/test_edge.details.log
                continue
              fi

              echo $hash >> ${hash_in}

              if [ "${word_compare}" != "None" ]; then
                w=$(eval $word_compare)
                echo $w >> ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.words_compare
              else
                echo ${word} >> ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.words
              fi

              if [ "${attack_type}" -eq 0 ]; then
                ((hash_cnt++))

                echo ${word} >> ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}.1.words

                CMD="cat ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}.1.words | ./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 0"
              elif [ "${attack_type}" -eq 1 ]; then
                ((hash_cnt++))

                if [ "${word_len}" -eq 2 ]; then
                  word_1=$(echo $word | cut -c -1)
                  word_2=$(echo $word | cut -c 2-)
                elif [ "${word_len}" -gt 2 ]; then
                  word_1_cnt=$((word_len/2))
                  word_1=$(echo $word | cut -c -${word_1_cnt})
                 ((word_1_cnt++))
                 word_2=$(echo $word | cut -c ${word_1_cnt}-)
                fi

                echo ${word_1} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.words
                echo ${word_2} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.2.words

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 1 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.words ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.2.words"
              elif [ "${attack_type}" -eq 3 ]; then
                ((hash_cnt++))

                if [ $pt_hex -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?b"
                elif [ $pt_base58 -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?a?a"
                else
                  if [ "${word_len}" -eq 2 ]; then
                    word_1="${word%?}"
                    mask_1="?d"
                  elif [ "${slow_hash}" -eq 1 ]; then
                    word_1="${word%??}"
                    mask_1="?d?d"
                  else
                    word_1="${word%???}"
                    mask_1="?d?d?d"
                  fi
                fi

                echo -n ${word_1} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.words.masks
                echo ${mask_1} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.words.masks

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 3 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.words.masks"
              elif [ "${attack_type}" -eq 6 ]; then
                ((hash_cnt++))

                if [ $pt_hex -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?b"
                elif [ $pt_base58 -eq 1 ]; then
                  word_1="${word%??}"
                  mask_1="?a?a"
                else
                  if [ "${word_len}" -eq 2 ] || [ "${slow_hash}" -eq 1 ]; then
                    word_1="${word%?}"
                    mask_1="?d"
                  else
                    word_1="${word%??}"
                    mask_1="?d?d"
                  fi
                fi

                echo ${word_1} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.words
                echo ${mask_1} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.masks

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 6 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.words ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.1.masks"
              elif [ "${attack_type}" -eq 7 ]; then
                ((hash_cnt++))

                if [ $pt_hex -eq 1 ]; then
                  word_1="${word#??}"
                  mask_1="?b"
                elif [ $pt_base58 -eq 1 ]; then
                  word_1="${word#??}"
                  mask_1="?a?a"
                else
                  if [ "${word_len}" -eq 2 ] || [ "${slow_hash}" -eq 1 ]; then
                    word_1="${word#?}"
                    mask_1="?d"
                  else
                    word_1="${word#??}"
                    mask_1="?d?d"
                  fi
                fi

                echo ${word_1} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.2.words
                echo ${mask_1} >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.2.masks

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 7 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.2.masks ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}.2.words"
              elif [ "${attack_type}" -eq 12 ]; then
                ((hash_cnt++))

                # Same two shapes as the single hash run above, and the masks go into a mask file so
                # that every word is tried against every one of them.

                mask_c="?d"
                cut_len=1
                both_sides=1

                if [ $pt_hex -eq 1 ]; then
                  mask_c="?b"
                  cut_len=2
                  both_sides=0
                elif [ $pt_base58 -eq 1 ]; then
                  mask_c="?a"
                fi

                if [ ${slow_hash} -eq 1 ]; then
                  both_sides=0
                fi

                mid_len=$((${#word} - cut_len - cut_len))

                if [ ${both_sides} -eq 1 ] && [ ${mid_len} -ge 1 ]; then
                  word_1="${word:${cut_len}:${mid_len}}"
                  mask_1="${mask_c}?w${mask_c}"
                else
                  word_1="${word:${cut_len}}"
                  mask_1="${mask_c}?w"
                fi

                echo "${word_1}" >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.12.words
                echo "${mask_1}" >> ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.12.masks

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 12 ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.12.masks ${OUTD}/test_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.12.words"
              elif [ "${attack_type}" -eq 4 ]; then
                ((hash_cnt++))

                # The words of the other hashes are the noise here, the same way they are under -a 0
                # and -a 8, so the ruleset holds one entry per hash and nothing more.

                printf '%s\t1.0\n' "${word}" >> ${ruleset}/Context/1.txt

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 4 ${ruleset}"
              elif [ "${attack_type}" -eq 8 ]; then
                ((hash_cnt++))

                echo "${word}" >> ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.8.words

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 8 wordlist ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.8.words"
              elif [ "${attack_type}" -eq 9 ]; then
                ((hash_cnt++))

                echo "${word}" >> ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.9.words

                CMD="./hashcat ${CUR_OPTS_V} -m ${hash_type} ${hash_in} -a 9 ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.9.words"
              fi
            done

            #echo "hash_cnt: $hash_cnt"
            #cat ${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}.hashes

            if [ $hash_cnt -gt 1 ]; then
              cmd_out="${OUTD}/cmd_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.multi.log"

              rm -f ${outfile}

              eval ${CMD} &> ${cmd_out}
              retVal=$?

              cat ${cmd_out} >> ${OUTD}/test_edge.details.log

              hc_out="${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.hashes.words"

              if [ "${word_compare}" != "None" ]; then
                word_in="${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.words_compare"
              else
                word_in="${OUTD}/edge_${hash_type}_${kernel_type}_${attack_type}_${vector_width}.words"
              fi

              paste -d ":" ${hash_in} ${word_in} > ${hc_out}

              if [ "${retVal}" -ne 0 ]; then
                if [ "${retVal}" -eq 252 ]; then
                  echo "[ ${OUTD} ] > Skipping current tests due to unmet memory requirements ..." | tee -a ${OUTD}/test_edge.details.log
                  break
                fi

                # -a 9 gives one candidate to each salt and wants a single iteration count across the
                # whole set. test.pl picks an iteration count per test vector for some hash modes, so
                # hashcat says so and stops before it runs. That is the attack telling the suite what
                # it takes, not a defect to report.

                if [ ${attack_type} -eq 9 ] && grep -q "Mixed iteration counts are not supported" ${cmd_out}; then
                  echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type multi (the test vectors do not share one iteration count)" | tee -a ${OUTD}/test_edge.details.log
                  continue
                fi

                echo '```' | tee -a ${OUTD}/test_edge.details.log
                echo "[ ${OUTD} ] !> error ($retVal) detected with CMD: ${CMD}" | tee -a ${OUTD}/test_edge.details.log
                echo "[ ${OUTD} ] !> Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Words ${word_in}, Hashes ${hash_in}" | tee -a ${OUTD}/test_edge.details.log
                cat ${cmd_out} | tee -a ${OUTD}/test_edge.details.log
                echo '```' | tee -a ${OUTD}/test_edge.details.log
                ((errors++))

                if [ "${retVal}" -eq 250 ]; then
                  echo "[ ${OUTD} ] > Skipping current tests due to build error ..." | tee -a ${OUTD}/test_edge.details.log
                  break
                fi
              else
                if is_in_array "${hash_type}" ${SKIP_OUT_MATCH_HASH_TYPES}; then
                  echo "[ ${OUTD} ] > Skip output check for Hash-Type ${hash_type} (due to collisions)" >> ${OUTD}/test_edge.details.log
                  continue
                fi

                ./hashcat -m ${hash_type} -HH | grep 'Keep.Guessing.......: Yes' &> /dev/null
                if [ $? -eq 0 ]; then
                  echo "[ ${OUTD} ] > Skip output check for Hash-Type ${hash_type} (due to keep guessing)" >> ${OUTD}/test_edge.details.log
                  continue
                fi

                out=$(cat ${outfile} 2>/dev/null | sed -e 's/    (user password.*$//g')

                md5_1=$(echo "${out}" | sort -s | md5sum | cut -d' ' -f1)
                md5_2=$(cat ${hc_out} | sort -s | md5sum | cut -d' ' -f1)

                if [ $md5_1 != $md5_2 ]; then
                  echo '```' | tee -a ${OUTD}/test_edge.details.log
                  echo "[ ${OUTD} ] !> error detected (output don't match) with CMD: ${CMD}" | tee -a ${OUTD}/test_edge.details.log
                  echo "[ ${OUTD} ] !> Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Words ${word_in}, Hashes ${hash_in}" | tee -a ${OUTD}/test_edge.details.log
                  echo "! output" | tee -a ${OUTD}/test_edge.details.log
                  echo | tee -a ${OUTD}/test_edge.details.log
                  echo "${out}" | sort -s | tee -a ${OUTD}/test_edge.details.log
                  echo | tee -a ${OUTD}/test_edge.details.log
                  echo "! expected output" | tee -a ${OUTD}/test_edge.details.log
                  echo | tee -a ${OUTD}/test_edge.details.log
                  cat ${hc_out} | sort -s | tee -a ${OUTD}/test_edge.details.log
                  echo '```' | tee -a ${OUTD}/test_edge.details.log
                  ((errors++))
                fi
              fi
            else
              echo "[ ${OUTD} ] > Skipping Hash-Type ${hash_type}, Attack-Type ${attack_type}, Kernel-Type ${kernel_type}, Vector-Width ${vector_width}, Target-Type multi, Hashes ${hash_in} (hashes < 2)" | tee -a ${OUTD}/test_edge.details.log
              #echo "hash_cnt: ${hash_cnt}"
            fi
          fi
        done
      fi
    done
  done
done

endTime=$(date +%s)
elapsed=$((endTime - startTime))

days=$((elapsed / 86400))
hours=$(((elapsed % 86400) / 3600))
minutes=$(((elapsed % 3600) / 60))
seconds=$((elapsed % 60))

echo "[ ${OUTD} ] > All tests done in ${days}d:$(printf "%02dh:%02dm:%02ds" "$hours" "$minutes" "$seconds")"

echo "[ ${OUTD} ] > Errors detected: $errors"
if [ $errors -gt 0 ]; then
  echo "[ ${OUTD} ] !> Details on ${OUTD}/test_edge.details.log"
fi
