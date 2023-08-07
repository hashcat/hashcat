#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

OPTS="--quiet --potfile-disable --hwmon-disable --logfile-disable"

FORCE=0
RUNTIME=400

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# List of TrueCrypt modes which have test containers
TC_MODES="6211 6212 6213 6221 6222 6223 6231 6232 6233 6241 6242 6243 29311 29312 29313 29321 29322 29323 29331 29332 29333 29341 29342 29343"

# List of VeraCrypt modes which have test containers
VC_MODES="13711 13712 13713 13721 13722 13723 13731 13732 13733 13741 13742 13743 13751 13752 13753 13761 13762 13763 13771 13772 13773 13781 13782 13783 29411 29412 29413 29421 29422 29423 29431 29432 29433 29441 29442 29443 29451 29452 29453 29461 29462 29463 29471 29472 29473 29481 29482 29483"

# List of modes which return a different output hash format than the input hash format
NOCHECK_ENCODING="16800 22000"

# List of LUKS modes which have test containers
LUKS_MODES="14600 29511 29512 29513 29521 29522 29523 29531 29532 29533 29541 29542 29543"

# Cryptoloop mode which have test containers
CL_MODES="14511 14512 14513 14521 14522 14523 14531 14532 14533 14541 14542 14543 14551 14552 14553"

# missing hash types: 5200

HASH_TYPES=$(ls "${TDIR}"/test_modules/*.pm | sed -E 's/.*m0*([0-9]+).pm/\1/')
HASH_TYPES="${HASH_TYPES} ${TC_MODES} ${VC_MODES} ${LUKS_MODES} ${CL_MODES}"
HASH_TYPES=$(echo -n "${HASH_TYPES}" | tr ' ' '\n' | sort -u -n | tr '\n' ' ')

VECTOR_WIDTHS="1 2 4 8 16"

KEEP_GUESSING=$(grep -l OPTS_TYPE_SUGGEST_KG       "${TDIR}"/../src/modules/module_*.c | sed -E 's/.*module_0*([0-9]+).c/\1/' | tr '\n' ' ')
HASHFILE_ONLY=$(grep -l OPTS_TYPE_BINARY_HASHFILE  "${TDIR}"/../src/modules/module_*.c | sed -E 's/.*module_0*([0-9]+).c/\1/' | tr '\n' ' ')
SLOW_ALGOS=$(   grep -l ATTACK_EXEC_OUTSIDE_KERNEL "${TDIR}"/../src/modules/module_*.c | sed -E 's/.*module_0*([0-9]+).c/\1/' | tr '\n' ' ')

# fake slow algos, due to specific password pattern (e.g. ?d from "mask_3" is invalid):
# ("only" drawback is that just -a 0 is tested with this workaround)

SLOW_ALGOS="${SLOW_ALGOS} 28501 28502 28503 28504 28505 28506 30901 30902 30903 30904 30905 30906"

OUTD="test_$(date +%s)"

PACKAGE_CMD="7z a"
PACKAGE_FOLDER=""

EXTRACT_CMD="7z x"

mask_3[0]=""
mask_3[1]="?d"
mask_3[2]="?d?d"
mask_3[3]="?d?d?d"
mask_3[4]="?d?d?d?d"
mask_3[5]="?d?d?d?d?d"
mask_3[6]="?d?d?d?d?d?d"
mask_3[7]="?d?d?d?d?d?d?d"
mask_3[8]="?d?d?d?d?d?d?d?d"
mask_3[9]="?d?d?d?d?d?d?d?d?d"
mask_3[10]="?d?d?d?d?d?d?d?d?d?d"
mask_3[11]="?d?d?d?d?d?d?d?d?d?d?d"
mask_3[12]="?d?d?d?d?d?d?d?d?d?d?d?d"
mask_3[13]="?d?d?d?d?d?d?d?d?d?d?d?d?d"
mask_3[14]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d"
mask_3[15]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d"
mask_3[16]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d0"
mask_3[17]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d00"
mask_3[18]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d000"
mask_3[19]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d0000"
mask_3[20]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d00000"
mask_3[21]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d000000"
mask_3[22]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d0000000"
mask_3[23]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d00000000"
mask_3[24]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d000000000"
mask_3[25]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d0000000000"
mask_3[26]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d00000000000"
mask_3[27]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d000000000000"
mask_3[28]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d0000000000000"
mask_3[29]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d00000000000000"
mask_3[30]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d000000000000000"
mask_3[31]="?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d0000000000000000"

mask_6[0]=""
mask_6[1]=""
mask_6[2]="?d"
mask_6[3]="?d?d"
mask_6[4]="?d?d"
mask_6[5]="?d?d?d"
mask_6[6]="?d?d?d"
mask_6[7]="?d?d?d?d"
mask_6[8]="?d?d?d?d"
mask_6[9]="?d?d?d?d?d"
mask_6[10]="?d?d?d?d?d"
mask_6[11]="?d?d?d?d?d?d"
mask_6[12]="?d?d?d?d?d?d"
mask_6[13]="?d?d?d?d?d?d?d"
mask_6[14]="?d?d?d?d?d?d?d"
mask_6[15]="?d?d?d?d?d?d?d?d"
mask_6[16]="?d?d?d?d?d?d?d?d"
mask_6[17]="?d?d?d?d?d?d?d?d0"
mask_6[18]="?d?d?d?d?d?d?d?d0"
mask_6[19]="?d?d?d?d?d?d?d?d00"
mask_6[20]="?d?d?d?d?d?d?d?d00"
mask_6[21]="?d?d?d?d?d?d?d?d000"
mask_6[22]="?d?d?d?d?d?d?d?d000"
mask_6[23]="?d?d?d?d?d?d?d?d0000"
mask_6[24]="?d?d?d?d?d?d?d?d0000"
mask_6[25]="?d?d?d?d?d?d?d?d00000"
mask_6[26]="?d?d?d?d?d?d?d?d00000"
mask_6[27]="?d?d?d?d?d?d?d?d000000"
mask_6[28]="?d?d?d?d?d?d?d?d000000"
mask_6[29]="?d?d?d?d?d?d?d?d0000000"
mask_6[30]="?d?d?d?d?d?d?d?d0000000"
mask_6[31]="?d?d?d?d?d?d?d?d00000000"

mask_7[0]=""
mask_7[1]=""
mask_7[2]="?d"
mask_7[3]="?d"
mask_7[4]="?d?d"
mask_7[5]="?d?d"
mask_7[6]="?d?d?d"
mask_7[7]="?d?d?d"
mask_7[8]="?d?d?d?d"
mask_7[9]="?d?d?d?d"
mask_7[10]="?d?d?d?d?d"
mask_7[11]="?d?d?d?d?d"
mask_7[12]="?d?d?d?d?d?d"
mask_7[13]="?d?d?d?d?d?d"
mask_7[14]="?d?d?d?d?d?d?d"
mask_7[15]="?d?d?d?d?d?d?d"
mask_7[16]="?d?d?d?d?d?d?d?d"
mask_7[17]="?d?d?d?d?d?d?d?d"
mask_7[18]="?d?d?d?d?d?d?d?d0"
mask_7[19]="?d?d?d?d?d?d?d?d0"
mask_7[20]="?d?d?d?d?d?d?d?d00"
mask_7[21]="?d?d?d?d?d?d?d?d00"
mask_7[22]="?d?d?d?d?d?d?d?d000"
mask_7[23]="?d?d?d?d?d?d?d?d000"
mask_7[24]="?d?d?d?d?d?d?d?d0000"
mask_7[25]="?d?d?d?d?d?d?d?d0000"
mask_7[26]="?d?d?d?d?d?d?d?d00000"
mask_7[27]="?d?d?d?d?d?d?d?d00000"
mask_7[28]="?d?d?d?d?d?d?d?d000000"
mask_7[29]="?d?d?d?d?d?d?d?d000000"
mask_7[30]="?d?d?d?d?d?d?d?d0000000"
mask_7[31]="?d?d?d?d?d?d?d?d0000000"

# Array lookup
# $1: value
# $2: array
# Returns 0 (SUCCESS) if the value is found, 1 otherwise

function is_in_array()
{
  for e in "${@:2}"; do
    [ "$e" = "$1" ] && return 0
  done

  return 1
}

function init()
{
  if [ "${PACKAGE}" -eq 1 ]; then
    echo "[ ${OUTD} ] > Generate tests for hash type $hash_type."
  else
    echo "[ ${OUTD} ] > Init test for hash type $hash_type."
  fi

  rm -rf "${OUTD}/${hash_type}.sh" "${OUTD}/${hash_type}_passwords.txt" "${OUTD}/${hash_type}_hashes.txt"

  # Exclude TrueCrypt, VeraCrypt and CryptoLoop testing modes
  if is_in_array "${hash_type}" ${TC_MODES}; then
    return 0
  fi
  if is_in_array "${hash_type}" ${VC_MODES}; then
    return 0
  fi
  if is_in_array "${hash_type}" ${CL_MODES}; then
    return 0
  fi

  if is_in_array "${hash_type}" ${LUKS_MODES}; then
    which 7z &>/dev/null
    if [ $? -eq 1 ]; then
      echo "ATTENTION: 7z is missing. Skipping download and extract luks test files."
      return 0
    fi

    luks_tests_folder="${TDIR}/luks_tests/"

    if [ ! -d "${luks_tests_folder}" ]; then
      mkdir -p "${luks_tests_folder}"
    fi

    luks_first_test_file="${luks_tests_folder}/hashcat_ripemd160_aes_cbc-essiv_128.luks"

    if [ ! -f "${luks_first_test_file}" ]; then
      luks_tests="hashcat_luks_testfiles.7z"
      luks_tests_url="https://hashcat.net/misc/example_hashes/${luks_tests}"

      cd "${TDIR}" || exit

      # if the file already exists, but was not successfully extracted, we assume it's a broken
      # downloaded file and therefore it should be deleted

      if [ -f "${luks_tests}" ]; then
        rm -f "${luks_tests}"
      fi

      echo ""
      echo "ATTENTION: the luks test files (for -m ${hash_type}) are currently missing on your system."
      echo "They will be fetched from ${luks_tests_url}"
      echo "Note: this needs to be done only once and could take a little bit to download/extract."
      echo "These luks test files are not shipped directly with hashcat because the file sizes are"
      echo "particularly large and therefore a bandwidth burner for users who do not run these tests."
      echo ""

      # download:
      wget -q "${luks_tests_url}"

      if [ $? -ne 0 ] || [ ! -f "${luks_tests}" ]; then
        cd - >/dev/null
        echo "ERROR: Could not fetch the luks test files from this url: ${luks_tests_url}"
        return 0
      fi

      # extract:

      ${EXTRACT_CMD} "${luks_tests}" &>/dev/null

      # cleanup:

      rm -f "${luks_tests}"
      cd - >/dev/null || exit

      # just to be very sure, check again that (one of) the files now exist:

      if [ ! -f "${luks_first_test_file}" ]; then
        echo "ERROR: downloading and extracting ${luks_tests} into ${luks_tests_folder} did not complete successfully"
        return 0
      fi
    fi

    return 0
  fi

  # create list of password and hashes of same type
  cmd_file=${OUTD}/${hash_type}.sh

  grep " ${hash_type} '" "${OUTD}/all.sh" > "${cmd_file}" 2>/dev/null

  # create separate list of password and hashes
  sed 's/^echo *|.*$//'       "${cmd_file}" | awk '{print $2}'                                                                    > "${OUTD}/${hash_type}_passwords.txt"
  sed 's/^echo *|/echo "" |/' "${cmd_file}" | awk '{t="";for(i=10;i<=NF;i++){if(t){t=t" "$i}else{t=$i}};print t}' | cut -d"'" -f2 > "${OUTD}/${hash_type}_hashes.txt"

  if [ "${hash_type}" -eq 10300 ]; then
    #cat ${OUTD}/${hash_type}.sh | cut -d' ' -f11- | cut -d"'" -f2 > ${OUTD}/${hash_type}_hashes.txt
    cut -d"'" -f2 "${OUTD}/${hash_type}.sh" > "${OUTD}/${hash_type}_hashes.txt"
  fi

  # truncate dicts
  rm -rf "${OUTD}/${hash_type}_dict1" "${OUTD}/${hash_type}_dict2"
  touch "${OUTD}/${hash_type}_dict1" "${OUTD}/${hash_type}_dict2"

  # minimum password length

  min=1         # minimum line number from start of the file
  min_offset=0  # minimum offset starting from ${min} lines

  if   [ "${hash_type}" -eq  2500 ]; then
    min_offset=7 # means length 8, since we start with 0
  elif [ "${hash_type}" -eq 14000 ]; then
    min=0
    min_offset=4
  elif [ "${hash_type}" -eq 14100 ]; then
    min=0
    min_offset=3
  elif [ "${hash_type}" -eq 14900 ]; then
    min=0
    min_offset=5
  elif [ "${hash_type}" -eq 15400 ]; then
    min=0
    min_offset=3
  elif [ "${hash_type}" -eq 16800 ]; then
    min_offset=7 # means length 8, since we start with 0
  elif [ "${hash_type}" -eq 22000 ]; then
    min_offset=7 # means length 8, since we start with 0
  fi

  # foreach password entry split password in 2 (skip first entry, is len 1)

  i=1

  while read -r -u 9 pass; do

    if [ ${i} -gt ${min} ]; then

      # split password, 'i' is the len
      p0=$((i / 2))
      p1=$((p0 + 1))

      # special case (passwords longer than expected)
      pass_len=${#pass}

      if [ "${pass_len}" -gt 1 ]; then

        p1=$((p1 + min_offset))
        p0=$((p0 + min_offset))

        if [ "${p1}" -gt "${pass_len}" ]; then
          p1=${pass_len}
          p0=$((p1 - 1))
        fi

        # add splitted password to dicts
        echo "${pass}" | cut -c -${p0} >> "${OUTD}/${hash_type}_dict1"
        echo "${pass}" | cut -c ${p1}- >> "${OUTD}/${hash_type}_dict2"
      elif [ "${pass_len}" -eq 1 ]; then
        echo "${pass}" >> "${OUTD}/${hash_type}_dict1"
        echo >> "${OUTD}/${hash_type}_dict2"
      else
        echo >> "${OUTD}/${hash_type}_dict1"
        echo >> "${OUTD}/${hash_type}_dict2"
      fi

    fi

    i=$((i + 1))

  done 9< "${OUTD}/${hash_type}_passwords.txt"

  min_len=0

  if   [ "${hash_type}" -eq  2500 ]; then
    min_len=7 # means length 8, since we start with 0
  elif [ "${hash_type}" -eq 14000 ]; then
    min_len=7
  elif [ "${hash_type}" -eq 14100 ]; then
    min_len=23
  elif [ "${hash_type}" -eq 14900 ]; then
    min_len=9
  elif [ "${hash_type}" -eq 15400 ]; then
    min_len=31
  elif [ "${hash_type}" -eq 16800 ]; then
    min_len=7 # means length 8, since we start with 0
  elif [ "${hash_type}" -eq 22000 ]; then
    min_len=7 # means length 8, since we start with 0
  fi

  # generate multiple pass/hash foreach len (2 to 8)
  if [ "${MODE}" -ge 1 ]; then

    i=2

    while [ "$i" -lt 9 ]; do

      cmd_file=${OUTD}/${hash_type}_multi_${i}.txt

      rm -rf "${cmd_file}" "${OUTD}/${hash_type}_passwords_multi_${i}.txt" "${OUTD}/${hash_type}_hashes_multi_${i}.txt"
      rm -rf "${OUTD}/${hash_type}_dict1_multi_${i}" "${OUTD}/${hash_type}_dict2_multi_${i}"
      touch "${OUTD}/${hash_type}_dict1_multi_${i}" "${OUTD}/${hash_type}_dict2_multi_${i}"

      perl tools/test.pl single "${hash_type}" ${i} > "${cmd_file}"

      sed 's/^echo *|.*$//'       "${cmd_file}" | awk '{print $2}'                                                                    > "${OUTD}/${hash_type}_passwords_multi_${i}.txt"
      sed 's/^echo *|/echo "" |/' "${cmd_file}" | awk '{t="";for(i=10;i<=NF;i++){if(t){t=t" "$i}else{t=$i}};print t}' | cut -d"'" -f2 > "${OUTD}/${hash_type}_hashes_multi_${i}.txt"

      if [ "${hash_type}" -eq 10300 ]; then
        #cat ${OUTD}/${hash_type}_multi_${i}.txt | cut -d' ' -f11- | cut -d"'" -f2 > ${OUTD}/${hash_type}_hashes_multi_${i}.txt
        cut -d"'" -f2 "${OUTD}/${hash_type}_multi_${i}.txt" > "${OUTD}/${hash_type}_hashes_multi_${i}.txt"
      fi

      # split password, 'i' is the len
      p0=$((i / 2))
      p1=$((p0 + 1))

      p0=$((p0 + min_len))
      p1=$((p1 + min_len))

      while read -r -u 9 pass; do

        # add splitted password to dicts
        echo "${pass}" | cut -c -${p0} >> "${OUTD}/${hash_type}_dict1_multi_${i}"
        echo "${pass}" | cut -c ${p1}- >> "${OUTD}/${hash_type}_dict2_multi_${i}"

      done 9< "${OUTD}/${hash_type}_passwords_multi_${i}.txt"

      i=$((i + 1))

    done

  fi
}

function status()
{
  RET=$1

  cnt=$((cnt + 1))

  if [ "${RET}" -ne 0 ]; then
    case ${RET} in
      246)
        echo "autotune failure, cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      248)
        echo "skipped by runtime (mixed backend errors detected), cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      249)
        echo "skipped by runtime (Invalid module_extra_buffer_size), cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      250)
        echo "skipped by runtime (Too many compute units to keep minimum kernel accel limit), cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      251)
        echo "skipped by runtime (main kernel build error), cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      252)
        echo "skipped by runtime (memory hit limit), cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      253)
        echo "skipped by runtime (module_unstable_warning), cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      1)
        # next check should not be needed anymore (NEVER_CRACK with exit code EXHAUSTED):
        # if is_in_array "${hash_type}" ${KEEP_GUESSING_ALGOS}; then
        #   return
        # fi

        echo "password not found, cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"
        e_nf=$((e_nf + 1))
        ;;

      4)
        echo "timeout reached, cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_to=$((e_to + 1))
        ;;

      10)
        if is_in_array "${hash_type}" ${KEEP_GUESSING_ALGOS}; then
          return
        fi

        if [ "${pass_only}" -eq 1 ]; then
          echo "plains not found in output, cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"
        else
          echo "hash:plains not matched in output, cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.tx"t
        fi

        e_nm=$((e_nm + 1))
        ;;

      20)
        echo "grep out-of-memory (cannot check if plains match in output), cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_ce=$((e_ce + 1))
        e_nm=$((e_nm + 1))
        ;;

      30)
        echo "luks test files are missing, cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        e_rs=$((e_rs + 1))
        ;;

      *)
        echo "! unhandled return code ${RET}, cmdline : ${CMD}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"
        echo "! unhandled return code, see ${OUTD}/logfull.txt or ${OUTD}/test_report.log for details."

        e_nf=$((e_nf + 1))
        ;;

    esac
  fi
}

function attack_0()
{
  file_only=0

  if is_in_array "${hash_type}" ${FILE_BASED_ALGOS}; then
    file_only=1
  fi

  # single hash
  if [ "${MODE}" -ne 1 ]; then

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 0, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    max=32

    if is_in_array "${hash_type}" ${TIMEOUT_ALGOS}; then
      max=12
    fi

    i=0

    while read -r -u 9 line; do

      if [ "${i}" -ge ${max} ]; then
        break
      fi

      hash="$(echo "${line}" | cut -d\'  -f2)"
      pass="$(echo "${line}" | cut -d' ' -f2)"

      if [ -z "${hash}" ]; then
        break
      fi

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"

        if [ "${hash_type}" -ne 22000 ]; then
          echo "${hash}" | base64 -d > "${temp_file}"
        else
          echo "${hash}" > "${temp_file}"
        fi

        hash="${temp_file}"

      fi

      pass_old=${pass}

      if [ "${hash_type}" -eq 20510 ]; then # special case for PKZIP Master Key
        pass=$(echo "${pass}" | cut -b 7-) # skip the first 6 chars
      fi

      CMD="echo ${pass} | ./${BIN} ${OPTS} -a 0 -m ${hash_type} '${hash}'"

      echo -n "[ len $((i + 1)) ] " >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

      output=$(echo "${pass}" | ./${BIN} ${OPTS} -a 0 -m ${hash_type} "${hash}" 2>&1)

      ret=${?}

      pass=${pass_old}

      echo "${output}" >> "${OUTD}/logfull.txt"

      if [ "${ret}" -eq 0 ]; then

        if [ "${pass_only}" -eq 1 ]; then
          search=":${pass}"
        else
          search="${hash}:${pass}"
        fi

        echo "${output}" | grep -F "${search}" &>/dev/null

        newRet=$?

        if [ "${newRet}" -eq 2 ]; then

          # out-of-memory, workaround

          echo "${output}" | grep -v "^Unsupported\|^$" | head -1 > tmp_file_out
          echo "${search}" > tmp_file_search

          out_md5=$(md5sum tmp_file_out | cut -d' ' -f1)
          search_md5=$(md5sum tmp_file_search | cut -d' ' -f1)

          rm tmp_file_out tmp_file_search

          if [ "${out_md5}" == "${search_md5}" ]; then
            newRet=0
          fi
        fi

        if [ "${newRet}" -ne 0 ]; then
          if [ "${newRet}" -eq 2 ]; then
            ret=20
          else
            ret=10
          fi
        fi

      fi

      status ${ret}

      i=$((i + 1))

    done 9< "${OUTD}/${hash_type}.sh"

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 0, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi

  # multihash
  if [ "${MODE}" -ne 0 ]; then

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 0, markov ${MARKOV}, multi hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    hash_file=${OUTD}/${hash_type}_hashes.txt

    # if file_only -> decode all base64 "hashes" and put them in the temporary file

    if [ "${file_only}" -eq 1 ]; then

      temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
      rm -f "${temp_file}"

      hash_file=${temp_file}

      while read -r file_only_hash; do

        if [ "${hash_type}" -ne 22000 ]; then
          echo -n "${file_only_hash}" | base64 -d >> "${temp_file}"
        else
          echo "${file_only_hash}" >> "${temp_file}"
        fi

      done < "${OUTD}/${hash_type}_hashes.txt"

    fi

    CMD="cat ${OUTD}/${hash_type}_passwords.txt | ./${BIN} ${OPTS} -a 0 -m ${hash_type} ${hash_file}"

    output=$(./${BIN} ${OPTS} -a 0 -m ${hash_type} ${hash_file} < ${OUTD}/${hash_type}_passwords.txt 2>&1)

    ret=${?}

    echo "${output}" >> "${OUTD}/logfull.txt"

    if [ "${ret}" -eq 0 ]; then

      i=1

      while read -r -u 9 hash; do

        pass=$(sed -n ${i}p "${OUTD}/${hash_type}_passwords.txt")

        if [ "${pass_only}" -eq 1 ]; then
          search=":${pass}"
        else
          search="${hash}:${pass}"
        fi

        echo "${output}" | grep -F "${search}" &>/dev/null

        newRet=$?

        if [ "${newRet}" -ne 0 ]; then
          if [ "${newRet}" -eq 2 ]; then
            ret=20
          else
            ret=10
          fi

          break
        fi

        i=$((i + 1))

      done 9< "${OUTD}/${hash_type}_hashes.txt"

    fi

    status ${ret}

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 0, Mode multi,  Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi
}

function attack_1()
{
  file_only=0

  if is_in_array "${hash_type}" ${FILE_BASED_ALGOS}; then
    file_only=1
  fi

  # single hash
  if [ "${MODE}" -ne 1 ]; then

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    min=1
    max=8

    if   [ "${hash_type}" -eq 14000 ]; then
      min=0
      max=5
    elif [ "${hash_type}" -eq 14100 ]; then
      min=0
      max=5
    elif [ "${hash_type}" -eq 14900 ]; then
      min=0
      max=5
    elif [ "${hash_type}" -eq 15400 ]; then
      min=0
      max=5
    elif [ "${hash_type}" -eq 20510 ]; then
      min=2
    fi

    echo "> Testing hash type $hash_type with attack mode 1, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"
    i=1
    while read -r -u 9 hash; do

      if [ $i -gt ${min} ]; then

        if [ "${file_only}" -eq 1 ]; then

          temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"

          if [ "${hash_type}" -ne 22000 ]; then
            echo "${hash}" | base64 -d > "${temp_file}"
          else
            echo "${hash}" > "${temp_file}"
          fi

          hash="${temp_file}"

        fi

        line_nr=1

        if [ "$min" -eq 0 ]; then
          line_nr=$i
        elif [ "${i}" -gt 1 ]; then
          line_nr=$((i - 1))
        fi

        dict1="${OUTD}/${hash_type}_dict1"
        dict2="${OUTD}/${hash_type}_dict2"

        if [ "${hash_type}" -eq 20510 ]; then # special case for PKZIP Master Key
          line_dict1=$(sed -n ${line_nr}p "${dict1}")
          line_dict2=$(sed -n ${line_nr}p "${dict2}")
          line_num=$(wc -l "${dict1}" | sed -E 's/ *([0-9]+) .*$/\1/')

          line_dict1_orig=${line_dict1}
          line_dict2_orig=${line_dict2}

          if [ "${#line_dict1}" -ge 6 ]; then
            line_dict1=$(echo "${line_dict1}" | cut -b 7-) # skip the first 6 chars
          else
            # we need to also "steal" some chars from the second dict
            num_to_steal=$((6 - ${#line_dict1}))
            num_steal_start=$((num_to_steal + 1))

            if [ "${#line_dict2}" -ge 6 ]; then
              num_to_steal_new=$(((${#line_dict2} - num_to_steal) / 2))

              if [ "${num_to_steal_new}" -gt ${num_to_steal} ]; then
                num_to_steal=${num_to_steal_new}
              fi
            fi

            line_chars_stolen=$(echo "${line_dict2}" | cut -b -${num_to_steal} | cut -b ${num_steal_start}-)

            line_dict1="${line_chars_stolen}"
            line_dict2=$(echo "${line_dict2}" | cut -b $((num_to_steal + 1))-)
          fi

          # finally, modify the dicts accordingly:

          tmp_file="${dict1}_mod"
          head -n $((line_nr - 1)) "${dict1}" > "${tmp_file}"
          echo "${line_dict1}" >> "${tmp_file}"
          tail -n $((line_num - line_nr - 1)) "${dict1}" >> "${tmp_file}"

          dict1=${tmp_file}

          tmp_file="${dict2}_mod"

          head -n $((line_nr - 1)) "${dict2}" > "${tmp_file}"
          echo "${line_dict2}" >> "${tmp_file}"
          tail -n $((line_num - line_nr - 1)) "${dict2}" >> "${tmp_file}"

          dict2=${tmp_file}
        fi

        CMD="./${BIN} ${OPTS} -a 1 -m ${hash_type} '${hash}' ${dict1} ${dict2}"

        echo -n "[ len $i ] " >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        output=$(./${BIN} ${OPTS} -a 1 -m ${hash_type} "${hash}" ${dict1} ${dict2} 2>&1)

        ret=${?}

        echo "${output}" >> "${OUTD}/logfull.txt"

        if [ "${ret}" -eq 0 ]; then

          line_dict1=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict1")
          line_dict2=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict2")

          if [ "${pass_only}" -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &>/dev/null

          newRet=$?

          if [ "${newRet}" -eq 2 ]; then

            # out-of-memory, workaround

            echo "${output}" | grep -v "^Unsupported\|^$" | head -1 > tmp_file_out
            echo "${search}" > tmp_file_search

            out_md5=$(md5sum tmp_file_out | cut -d' ' -f1)
            search_md5=$(md5sum tmp_file_search | cut -d' ' -f1)

            rm tmp_file_out tmp_file_search

            if [ "${out_md5}" == "${search_md5}" ]; then
              newRet=0
            fi
          fi

          if [ "${newRet}" -ne 0 ]; then
            if [ "${newRet}" -eq 2 ]; then
              ret=20
            else
              ret=10
            fi
          fi

        fi

        status ${ret}

      fi

      if [ $i -eq ${max} ]; then break; fi

      i=$((i + 1))

    done 9< "${OUTD}/${hash_type}_hashes.txt"

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 1, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi

  # multihash
  if [ "${MODE}" -ne 0 ]; then

    # no multi hash checks for these modes (because we only have 1 hash for each of them)

    if   [ "${hash_type}" -eq 14000 ]; then
      return
    elif [ "${hash_type}" -eq 14100 ]; then
      return
    elif [ "${hash_type}" -eq 14900 ]; then
      return
    elif [ "${hash_type}" -eq 15400 ]; then
      return
    fi

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    offset=7

    if [ "${hash_type}" -eq  5800 ]; then
      offset=6
    elif [ "${hash_type}" -eq  3000 ]; then
      offset=6
    fi

    hash_file=${OUTD}/${hash_type}_multihash_combi.txt

    tail -n ${offset} "${OUTD}/${hash_type}_hashes.txt" > "${hash_file}"

    # if file_only -> decode all base64 "hashes" and put them in the temporary file

    if [ "${file_only}" -eq 1 ]; then

      temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
      rm -f "${temp_file}"

      hash_file=${temp_file}

      while read -r file_only_hash; do

        if [ "${hash_type}" -ne 22000 ]; then
          echo -n "${file_only_hash}" | base64 -d >> "${temp_file}"
        else
          echo "${file_only_hash}" >> "${temp_file}"
        fi

      done < "${OUTD}/${hash_type}_multihash_combi.txt"

    fi

    CMD="./${BIN} ${OPTS} -a 1 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2"

    echo "> Testing hash type $hash_type with attack mode 1, markov ${MARKOV}, multi hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    output=$(./${BIN} ${OPTS} -a 1 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2 2>&1)

    ret=${?}

    echo "${output}" >> "${OUTD}/logfull.txt"

    if [ "${ret}" -eq 0 ]; then

      i=0

      while read -r -u 9 hash; do

        line_nr=1

        if [ "${offset}" -gt ${i} ]; then
          line_nr=$((offset - i))
        fi

        line_dict1=$(tail -n ${line_nr} "${OUTD}/${hash_type}_dict1" | head -1)
        line_dict2=$(tail -n ${line_nr} "${OUTD}/${hash_type}_dict2" | head -1)

        if [ "${pass_only}" -eq 1 ]; then
          search=":${line_dict1}${line_dict2}"
        else
          search="${hash}:${line_dict1}${line_dict2}"
        fi

        echo "${output}" | grep -F "${search}" &>/dev/null

        newRet=$?

        if [ "${newRet}" -ne 0 ]; then
          if [ "${newRet}" -eq 2 ]; then
            ret=20
          else
            ret=10
          fi

          break
        fi

        i=$((i + 1))

      done 9< "${OUTD}/${hash_type}_multihash_combi.txt"
    fi

    status ${ret}

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 1, Mode multi,  Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi
}

function attack_3()
{
  file_only=0

  if is_in_array "${hash_type}" ${FILE_BASED_ALGOS}; then
    file_only=1
  fi

  # single hash
  if [ "${MODE}" -ne 1 ]; then

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 3, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    max=8

    # some algos have a minimum password length

    if   [ "${hash_type}" -eq  2500 ]; then
      max=7
    elif [ "${hash_type}" -eq 14000 ]; then
      max=1
    elif [ "${hash_type}" -eq 14100 ]; then
      max=1
    elif [ "${hash_type}" -eq 14900 ]; then
      max=1
    elif [ "${hash_type}" -eq 15400 ]; then
      max=1
    elif [ "${hash_type}" -eq 16800 ]; then
      max=7
    elif [ "${hash_type}" -eq 22000 ]; then
      max=7
    fi

    i=1

    while read -r -u 9 hash; do

      if [ "${i}" -gt 6 ]; then
        if is_in_array "${hash_type}" ${TIMEOUT_ALGOS}; then
          break
        fi
      fi

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"

        if [ "${hash_type}" -ne 22000 ]; then
          echo "${hash}" | base64 -d > "${temp_file}"
        else
          echo "${hash}" > "${temp_file}"
        fi

        hash="${temp_file}"
      fi

      # construct a meaningful mask from the password itself:

      dict="${OUTD}/${hash_type}_passwords.txt"

      pass=$(sed -n ${i}p "${dict}")

      # passwords can't be smaller than mask in -a 3 = mask attack

      if [ "${#pass}" -lt ${i} ]; then
        i=$((i + 1))
        continue
      fi

      pass_part_2=$(echo -n "${pass}" | cut -b  $((i + 1))-)

      mask=""

      if   [ "${hash_type}" -eq 14000 ]; then
        mask="${pass}"
      elif [ "${hash_type}" -eq 14100 ]; then
        mask="${pass}"
      else
        for i in $(seq 1 ${i}); do
          mask="${mask}?d"
        done

        mask="${mask}${pass_part_2}"
      fi

      if [ "${hash_type}" -eq 20510 ]; then # special case for PKZIP Master Key
        if [ "${i}" -le 1 ]; then
          i=$((i + 1))
          continue
        fi

        cut_pos=$((i * 2 + 6 - i + 1)) # skip it in groups of 2 ("?d"), at least 6, offset +1 for cut to work

        if [ "${i}" -gt 6 ]; then
          cut_pos=13 # 6 * ?d + 1 (6 * 2 + 1)
        fi

        mask=$(echo "${mask}" | cut -b ${cut_pos}-)
      fi

      CMD="./${BIN} ${OPTS} -a 3 -m ${hash_type} '${hash}' ${mask}"

      echo -n "[ len $i ] " >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

      output=$(./${BIN} ${OPTS} -a 3 -m ${hash_type} "${hash}" ${mask} 2>&1)

      ret=${?}

      echo "${output}" >> "${OUTD}/logfull.txt"

      if [ "${ret}" -eq 0 ]; then

        line_dict=$(sed -n ${i}p "${dict}")

        if [ "${pass_only}" -eq 1 ]; then
          search=":${line_dict}"
        else
          search="${hash}:${line_dict}"
        fi

        echo "${output}" | grep -F "${search}" &>/dev/null

        newRet=$?

        if [ "${newRet}" -eq 2 ]; then

          # out-of-memory, workaround

          echo "${output}" | grep -v "^Unsupported\|^$" | head -1 > tmp_file_out
          echo "${search}" > tmp_file_search

          out_md5=$(md5sum tmp_file_out | cut -d' ' -f1)
          search_md5=$(md5sum tmp_file_search | cut -d' ' -f1)

          rm tmp_file_out tmp_file_search

          if [ "${out_md5}" == "${search_md5}" ]; then
            newRet=0
          fi
        fi

        if [ "${newRet}" -ne 0 ]; then
          if [ "${newRet}" -eq 2 ]; then
            ret=20
          else
            ret=10
          fi
        fi

      fi

      status ${ret}

      if [ $i -eq ${max} ]; then break; fi

      i=$((i + 1))

    done 9< "${OUTD}/${hash_type}_hashes.txt"

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 3, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi

  # multihash
  if [ "${MODE}" -ne 0 ]; then

    # no multi hash checks for these modes (because we only have 1 hash for each of them)

    if   [ "${hash_type}" -eq 14000 ]; then
      return
    elif [ "${hash_type}" -eq 14100 ]; then
      return
    elif [ "${hash_type}" -eq 14900 ]; then
      return
    elif [ "${hash_type}" -eq 15400 ]; then
      return
    fi

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    increment_max=8

    if is_in_array "${hash_type}" ${TIMEOUT_ALGOS}; then
      increment_max=5
    fi

    increment_min=1

    if   [ "${hash_type}" -eq  2500 ]; then
      increment_min=8
      increment_max=9
    fi

    if   [ "${hash_type}" -eq 16800 ]; then
      increment_min=8
      increment_max=9
    fi

    if   [ "${hash_type}" -eq 22000 ]; then
      increment_min=8
      increment_max=9
    fi

    # if file_only -> decode all base64 "hashes" and put them in the temporary file

    if [ "${file_only}" -eq 1 ]; then

      temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
      rm -f "${temp_file}"

      hash_file=${temp_file}

      while read -r file_only_hash; do

        if [ "${hash_type}" -ne 22000 ]; then
          echo -n "${file_only_hash}" | base64 -d >> "${temp_file}"
        else
          echo "${file_only_hash}" >> "${temp_file}"
        fi

      done < "${OUTD}/${hash_type}_multihash_bruteforce.txt"

    fi

    hash_file=${OUTD}/${hash_type}_multihash_bruteforce.txt

    tail_hashes=$(awk "length >= ${increment_min} && length <= ${increment_max}" "${OUTD}/${hash_type}_passwords.txt" | wc -l)
    head_hashes=$(awk                               "length <= ${increment_max}" "${OUTD}/${hash_type}_passwords.txt" | wc -l)

    # in very rare cases (e.g. without -O and long passwords) we need to use .hcmask files with the passwords in it
    # otherwise there are no good masks we can test for such long passwords

    need_hcmask=0

    if [ "${tail_hashes}" -gt "${head_hashes}" ]; then
      need_hcmask=1
    fi

    if [ "${tail_hashes}" -lt 1 ]; then
      need_hcmask=1
    fi

    if [ ${need_hcmask} -eq 0 ]; then
      head -n "${head_hashes}" "${OUTD}/${hash_type}_hashes.txt" | tail -n "${tail_hashes}" > "${hash_file}"
    else
      tail_hashes=$(awk "length >= ${increment_min}" "${OUTD}/${hash_type}_passwords.txt" | wc -l)

      if [ "${tail_hashes}" -lt 1 ]; then
        return
      fi

      tail -n "${tail_hashes}" "${OUTD}/${hash_type}_hashes.txt"  > "${hash_file}"
    fi

    mask_pos=8

    if [ "${increment_min}" -gt ${mask_pos} ]; then
      mask_pos=${increment_min}
    fi

    mask=""
    cracks_offset=0

    if [ ${need_hcmask} -eq 0 ]; then
      cracks_offset=$((head_hashes - tail_hashes))

      mask=${mask_3[${mask_pos}]}
    else
      num_hashes=$(wc -l < "${OUTD}/${hash_type}_hashes.txt")
      cracks_offset=$((num_hashes - tail_hashes))

      mask=${OUTD}/${hash_type}_passwords.txt # fake hcmask file (i.e. the original dict)
    fi

    custom_charsets=""

    # modify "default" mask if needed (and set custom charset to reduce keyspace)

    if [ "${hash_type}" -eq 2500 ]; then

      mask="?d?d?d?d?d?1?2?3?4"

      charset_1=""
      charset_2=""
      charset_3=""
      charset_4=""

      # check positions (here we assume that mask is always composed of non literal chars
      # i.e. something like ?d?l?u?s?1 is possible, but ?d?dsuffix not
      charset_1_pos=$(expr index "${mask}" 1)
      charset_2_pos=$(expr index "${mask}" 2)
      charset_3_pos=$(expr index "${mask}" 3)
      charset_4_pos=$(expr index "${mask}" 4)

      # divide each charset position by 2 since each of them occupies 2 positions in the mask

      charset_1_pos=$((charset_1_pos / 2))
      charset_2_pos=$((charset_2_pos / 2))
      charset_3_pos=$((charset_3_pos / 2))
      charset_4_pos=$((charset_4_pos / 2))

      i=1

      while read -r -u 9 hash; do

        pass=$(sed -n ${i}p "${OUTD}/${hash_type}_passwords.txt")

        # charset 1
        char=$(echo "${pass}" | cut -b ${charset_1_pos})
        charset_1=$(printf "%s\n%s\n" "${charset_1}" "${char}")

        # charset 2
        char=$(echo "${pass}" | cut -b ${charset_2_pos})
        charset_2=$(printf "%s\n%s\n" "${charset_2}" "${char}")

        # charset 3
        char=$(echo "${pass}" | cut -b ${charset_3_pos})
        charset_3=$(printf "%s\n%s\n" "${charset_3}" "${char}")

        # charset 4
        char=$(echo "${pass}" | cut -b ${charset_4_pos})
        charset_4=$(printf "%s\n%s\n" "${charset_4}" "${char}")

        i=$((i + 1))

      done 9< "${OUTD}/${hash_type}_multihash_bruteforce.txt"

      # just make sure that all custom charset fields are initialized

      if [ -z "${charset_1}" ]; then
        charset_1="1"
      fi

      if [ -z "${charset_2}" ]; then
        charset_2="2"
      fi

      if [ -z "${charset_3}" ]; then
        charset_3="3"
      fi

      if [ -z "${charset_4}" ]; then
        charset_4="4"
      fi

      # unique and remove new lines

      charset_1=$(echo "${charset_1}" | sort -u | tr -d '\n')
      charset_2=$(echo "${charset_2}" | sort -u | tr -d '\n')
      charset_3=$(echo "${charset_3}" | sort -u | tr -d '\n')
      charset_4=$(echo "${charset_4}" | sort -u | tr -d '\n')

      custom_charsets="-1 ${charset_1} -2 ${charset_2} -3 ${charset_3} -4 ${charset_4}"
    fi

    if [ "${hash_type}" -eq 16800 ]; then

      mask="?d?d?d?d?d?1?2?3?4"

      charset_1=""
      charset_2=""
      charset_3=""
      charset_4=""

      # check positions (here we assume that mask is always composed of non literal chars
      # i.e. something like ?d?l?u?s?1 is possible, but ?d?dsuffix not
      charset_1_pos=$(expr index "${mask}" 1)
      charset_2_pos=$(expr index "${mask}" 2)
      charset_3_pos=$(expr index "${mask}" 3)
      charset_4_pos=$(expr index "${mask}" 4)

      # divide each charset position by 2 since each of them occupies 2 positions in the mask

      charset_1_pos=$((charset_1_pos / 2))
      charset_2_pos=$((charset_2_pos / 2))
      charset_3_pos=$((charset_3_pos / 2))
      charset_4_pos=$((charset_4_pos / 2))

      i=1

      while read -r -u 9 hash; do

        pass=$(sed -n ${i}p "${OUTD}/${hash_type}_passwords.txt")

        # charset 1
        char=$(echo "${pass}" | cut -b ${charset_1_pos})
        charset_1=$(printf "%s\n%s\n" "${charset_1}" "${char}")

        # charset 2
        char=$(echo "${pass}" | cut -b ${charset_2_pos})
        charset_2=$(printf "%s\n%s\n" "${charset_2}" "${char}")

        # charset 3
        char=$(echo "${pass}" | cut -b ${charset_3_pos})
        charset_3=$(printf "%s\n%s\n" "${charset_3}" "${char}")

        # charset 4
        char=$(echo "${pass}" | cut -b ${charset_4_pos})
        charset_4=$(printf "%s\n%s\n" "${charset_4}" "${char}")

        i=$((i + 1))

      done 9< "${OUTD}/${hash_type}_multihash_bruteforce.txt"

      # just make sure that all custom charset fields are initialized

      if [ -z "${charset_1}" ]; then
        charset_1="1"
      fi

      if [ -z "${charset_2}" ]; then
        charset_2="2"
      fi

      if [ -z "${charset_3}" ]; then
        charset_3="3"
      fi

      if [ -z "${charset_4}" ]; then
        charset_4="4"
      fi

      # unique and remove new lines

      charset_1=$(echo "${charset_1}" | sort -u | tr -d '\n')
      charset_2=$(echo "${charset_2}" | sort -u | tr -d '\n')
      charset_3=$(echo "${charset_3}" | sort -u | tr -d '\n')
      charset_4=$(echo "${charset_4}" | sort -u | tr -d '\n')

      custom_charsets="-1 ${charset_1} -2 ${charset_2} -3 ${charset_3} -4 ${charset_4}"
    fi

    if [ "${hash_type}" -eq 22000 ]; then

      mask="?d?d?d?d?d?1?2?3?4"

      charset_1=""
      charset_2=""
      charset_3=""
      charset_4=""

      # check positions (here we assume that mask is always composed of non literal chars
      # i.e. something like ?d?l?u?s?1 is possible, but ?d?dsuffix not
      charset_1_pos=$(expr index "${mask}" 1)
      charset_2_pos=$(expr index "${mask}" 2)
      charset_3_pos=$(expr index "${mask}" 3)
      charset_4_pos=$(expr index "${mask}" 4)

      # divide each charset position by 2 since each of them occupies 2 positions in the mask

      charset_1_pos=$((charset_1_pos / 2))
      charset_2_pos=$((charset_2_pos / 2))
      charset_3_pos=$((charset_3_pos / 2))
      charset_4_pos=$((charset_4_pos / 2))

      i=1

      while read -r -u 9 hash; do

        pass=$(sed -n ${i}p "${OUTD}/${hash_type}_passwords.txt")

        # charset 1
        char=$(echo "${pass}" | cut -b ${charset_1_pos})
        charset_1=$(printf "%s\n%s\n" "${charset_1}" "${char}")

        # charset 2
        char=$(echo "${pass}" | cut -b ${charset_2_pos})
        charset_2=$(printf "%s\n%s\n" "${charset_2}" "${char}")

        # charset 3
        char=$(echo "${pass}" | cut -b ${charset_3_pos})
        charset_3=$(printf "%s\n%s\n" "${charset_3}" "${char}")

        # charset 4
        char=$(echo "${pass}" | cut -b ${charset_4_pos})
        charset_4=$(printf "%s\n%s\n" "${charset_4}" "${char}")

        i=$((i + 1))

      done 9< "${OUTD}/${hash_type}_multihash_bruteforce.txt"

      # just make sure that all custom charset fields are initialized

      if [ -z "${charset_1}" ]; then
        charset_1="1"
      fi

      if [ -z "${charset_2}" ]; then
        charset_2="2"
      fi

      if [ -z "${charset_3}" ]; then
        charset_3="3"
      fi

      if [ -z "${charset_4}" ]; then
        charset_4="4"
      fi

      # unique and remove new lines

      charset_1=$(echo "${charset_1}" | sort -u | tr -d '\n')
      charset_2=$(echo "${charset_2}" | sort -u | tr -d '\n')
      charset_3=$(echo "${charset_3}" | sort -u | tr -d '\n')
      charset_4=$(echo "${charset_4}" | sort -u | tr -d '\n')

      custom_charsets="-1 ${charset_1} -2 ${charset_2} -3 ${charset_3} -4 ${charset_4}"
    fi

    increment_charset_opts=""

    if [ ${need_hcmask} -eq 0 ]; then # the "normal" case without .hcmask file
      increment_charset_opts="--increment --increment-min ${increment_min} --increment-max ${increment_max}"

      if [ -n "${custom_charsets}" ]; then
        increment_charset_opts="${increment_charset_opts} ${custom_charsets}"
      fi
    fi

    CMD="./${BIN} ${OPTS} -a 3 -m ${hash_type} ${increment_charset_opts} ${hash_file} ${mask} "

    echo "> Testing hash type $hash_type with attack mode 3, markov ${MARKOV}, multi hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt"  2>> "${OUTD}/logfull.txt"

    output=$(./${BIN} ${OPTS} -a 3 -m ${hash_type} ${increment_charset_opts} ${hash_file} ${mask} 2>&1)

    ret=${?}

    echo "${output}" >> "${OUTD}/logfull.txt"

    if [ "${ret}" -eq 0 ]; then

      i=1

      while read -r -u 9 hash; do
        line_nr=$((i + cracks_offset))

        pass=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_passwords.txt")

        if [ "${pass_only}" -eq 1 ]; then
          search=":${pass}"
        else
          search="${hash}:${pass}"
        fi

        echo "${output}" | grep -F "${search}" &>/dev/null

        newRet=$?

        if [ "${newRet}" -ne 0 ]; then
          if [ "${newRet}" -eq 2 ]; then
            ret=20
          else
            ret=10
          fi

          break
        fi

        i=$((i + 1))

      done 9< "${OUTD}/${hash_type}_multihash_bruteforce.txt"

    fi

    status ${ret}

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 3, Mode multi,  Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi
}

function attack_6()
{
  file_only=0

  if is_in_array "${hash_type}" ${FILE_BASED_ALGOS}; then
    file_only=1
  fi

  # single hash
  if [ "${MODE}" -ne 1 ]; then

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 6, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    min=1
    max=8
    mask_offset=0

    if   [ "${hash_type}" -eq  2500 ]; then
      max=6
    elif [ "${hash_type}" -eq 14000 ]; then
      min=0
      max=1
      mask_offset=4
    elif [ "${hash_type}" -eq 14100 ]; then
      min=0
      max=1
      mask_offset=21
    elif [ "${hash_type}" -eq 14900 ]; then
      min=0
      max=1
      mask_offset=5
    elif [ "${hash_type}" -eq 15400 ]; then
      min=0
      max=1
      mask_offset=29
    elif [ "${hash_type}" -eq 16800 ]; then
      max=6
    elif [ "${hash_type}" -eq 22000 ]; then
      max=6
    fi

    # special case: we need to split the first line

    if [ "${min}" -eq 0 ]; then
      pass_part_1=$(sed -n 1p "${OUTD}/${hash_type}_dict1")
      pass_part_2=$(sed -n 1p "${OUTD}/${hash_type}_dict2")

      pass="${pass_part_1}${pass_part_2}"

      echo -n "${pass}" | cut -b -$((mask_offset + 0))  > "${OUTD}/${hash_type}_dict1_custom"
      echo -n "${pass}" | cut -b  $((mask_offset + 1))- > "${OUTD}/${hash_type}_dict2_custom"

      mask_custom=""

      for i in $(seq 1 $((${#pass} - mask_offset))); do

        if   [ "${hash_type}" -eq 14000 ]; then
          char=$(echo -n "${pass}" | cut -b $((i + mask_offset)))
          mask_custom="${mask_custom}${char}"
        elif [ "${hash_type}" -eq 14100 ]; then
          char=$(echo -n "${pass}" | cut -b $((i + mask_offset)))
          mask_custom="${mask_custom}${char}"
        else
          mask_custom="${mask_custom}?d"
        fi

      done
    fi

    i=1

    while read -r -u 9 hash; do

      if [ "${i}" -gt 6 ]; then
        if is_in_array "${hash_type}" ${TIMEOUT_ALGOS}; then
          break
        fi
      fi

      if [ ${i} -gt ${min} ]; then

        if [ "${file_only}" -eq 1 ]; then

          temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"

          if [ "${hash_type}" -ne 22000 ]; then
            echo "${hash}" | base64 -d > "${temp_file}"
          else
            echo "${hash}" > "${temp_file}"
          fi

          hash="${temp_file}"

        fi

        dict1=${OUTD}/${hash_type}_dict1
        dict2=${OUTD}/${hash_type}_dict2

        dict1_a6=${OUTD}/${hash_type}_dict1_a6

        cp "${dict1}" "${dict1_a6}"

        pass=$(sed -n ${i}p "${OUTD}/${hash_type}_passwords.txt")

        if [ "${hash_type}" -eq 20510 ]; then # special case for PKZIP Master Key
          pass=$(echo "${pass}" | cut -b 7-) # skip the first 6 chars
        fi

        if [ ${#pass} -le ${i} ]; then
          i=$((i + 1))
          continue
        fi

        echo "${pass}" | cut -b -$((${#pass} - i)) >> "${dict1_a6}"

        # the block below is just a fancy way to do a "shuf" (or sort -R) because macOS doesn't really support it natively
        # we do not really need a shuf, but it's actually better for testing purposes

        rm -f "${dict1_a6}.txt" # temporary file

        line_num=$(wc -l "${dict1_a6}" | sed -E 's/ *([0-9]+) .*$/\1/')

        sorted_lines=$(seq 1 "${line_num}")

        for lines in $(seq 1 "${line_num}"); do

          random_num=$((RANDOM % line_num))
          random_num=$((random_num + 1)) # sed -n [n]p starts counting with 1 (not 0)

          random_line=$(echo -n "${sorted_lines}" | sed -n ${random_num}p)

          sed -n ${random_line}p "${dict1_a6}" >> "${dict1_a6}.txt"

          # update the temp list of lines

          sorted_lines=$(echo -n "${sorted_lines}" | grep -v "^${random_line}$")

          line_num=$((line_num - 1))

        done

        mv "${dict1_a6}.txt" "${dict1_a6}"

        # end of shuf/sort -R

        mask=""

        for j in $(seq 1 ${i}); do
          mask="${mask}?d"
        done

        CMD="./${BIN} ${OPTS} -a 6 -m ${hash_type} '${hash}' ${dict1_a6} ${mask}"

        echo -n "[ len $i ] " >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        output=$(./${BIN} ${OPTS} -a 6 -m ${hash_type} "${hash}" ${dict1_a6} ${mask} 2>&1)

        ret=${?}

        echo "${output}" >> "${OUTD}/logfull.txt"

        if [ "${ret}" -eq 0 ]; then

          line_nr=1

          if [ "${i}" -gt 1 ]; then
            line_nr=$((i - 1))
          fi

          line_dict1=$(sed -n ${line_nr}p "${dict1}")
          line_dict2=$(sed -n ${line_nr}p "${dict2}")

          if [ "${pass_only}" -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &>/dev/null

          newRet=$?

          if [ "${newRet}" -eq 2 ]; then

            # out-of-memory, workaround

            echo "${output}" | grep -v "^Unsupported\|^$" | head -1 > tmp_file_out
            echo "${search}" > tmp_file_search

            out_md5=$(md5sum tmp_file_out | cut -d' ' -f1)
            search_md5=$(md5sum tmp_file_search | cut -d' ' -f1)

            rm tmp_file_out tmp_file_search

            if [ "${out_md5}" == "${search_md5}" ]; then
              newRet=0
            fi
          fi

          if [ "${newRet}" -ne 0 ]; then
            if [ "${newRet}" -eq 2 ]; then
              ret=20
            else
              ret=10
            fi
          fi

        fi

        status ${ret}
      fi

      if [ "${i}" -eq ${max} ]; then break; fi

      i=$((i + 1))

    done 9< "${OUTD}/${hash_type}_hashes.txt"

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 6, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"

    rm -f "${OUTD}/${hash_type}_dict1_custom"
    rm -f "${OUTD}/${hash_type}_dict2_custom"
  fi

  # multihash
  if [ "${MODE}" -ne 0 ]; then

    # no multi hash checks for these modes (because we only have 1 hash for each of them)

    if   [ "${hash_type}" -eq 14000 ]; then
      return
    elif [ "${hash_type}" -eq 14100 ]; then
      return
    elif [ "${hash_type}" -eq 14900 ]; then
      return
    elif [ "${hash_type}" -eq 15400 ]; then
      return
    fi

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    max=9

    if   [ "${hash_type}" -eq  2500 ]; then
      max=5
    elif [ "${hash_type}" -eq  3000 ]; then
      max=8
    elif [ "${hash_type}" -eq  7700 ] || [ "${hash_type}" -eq  7701 ]; then
      max=8
    elif [ "${hash_type}" -eq  8500 ]; then
      max=8
    elif [ "${hash_type}" -eq 16800 ]; then
      max=5
    elif [ "${hash_type}" -eq 22000 ]; then
      max=5
    fi

    if is_in_array "${hash_type}" ${TIMEOUT_ALGOS}; then
      max=5
      if [ "${hash_type}" -eq 3200 ]; then
        max=3
      fi
    fi

    i=2
    while [ "$i" -lt "$max" ]; do

      hash_file=${OUTD}/${hash_type}_hashes_multi_${i}.txt

      # if file_only -> decode all base64 "hashes" and put them in the temporary file

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
        rm -f "${temp_file}"

        hash_file=${temp_file}

        while read -r file_only_hash; do

          if [ "${hash_type}" -ne 22000 ]; then
            echo -n "${file_only_hash}" | base64 -d >> "${temp_file}"
          else
            echo "${file_only_hash}" >> "${temp_file}"
          fi

        done < "${OUTD}/${hash_type}_hashes_multi_${i}.txt"

      fi

      mask=${mask_6[$i]}

      CMD="./${BIN} ${OPTS} -a 6 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1_multi_${i} ${mask}"

      echo "> Testing hash type $hash_type with attack mode 6, markov ${MARKOV}, multi hash with word len ${i}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

      output=$(./${BIN} ${OPTS} -a 6 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1_multi_${i} ${mask} 2>&1)

      ret=${?}

      echo "${output}" >> "${OUTD}/logfull.txt"

      if [ "${ret}" -eq 0 ]; then

        j=1

        while read -r -u 9 hash; do

          line_dict1=$(sed -n ${j}p "${OUTD}/${hash_type}_dict1_multi_${i}")
          line_dict2=$(sed -n ${j}p "${OUTD}/${hash_type}_dict2_multi_${i}")

          if [ "${pass_only}" -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &>/dev/null

          newRet=$?

          if [ "${newRet}" -ne 0 ]; then
            if [ "${newRet}" -eq 2 ]; then
              ret=20
            else
              ret=10
            fi

            break
          fi

          j=$((j + 1))

        done 9< "${OUTD}/${hash_type}_hashes_multi_${i}.txt"
      fi

      status ${ret}
      i=$((i + 1))

    done

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 6, Mode multi,  Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi
}

function attack_7()
{
  file_only=0

  if is_in_array "${hash_type}" ${FILE_BASED_ALGOS}; then
    file_only=1
  fi

  # single hash
  if [ "${MODE}" -ne 1 ]; then

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 7, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    min=1
    max=8

    mask_offset=0

    if   [ "${hash_type}" -eq  2500 ]; then
      max=5
    elif [ "${hash_type}" -eq 14000 ]; then
      mask_offset=4
      min=0
      max=1
    elif [ "${hash_type}" -eq 14100 ]; then
      mask_offset=3
      min=0
      max=1
    elif [ "${hash_type}" -eq 14900 ]; then
      mask_offset=5
      min=0
      max=1
    elif [ "${hash_type}" -eq 15400 ]; then
      mask_offset=3
      min=0
      max=1
    elif [ "${hash_type}" -eq 16800 ]; then
      max=5
    elif [ "${hash_type}" -eq 22000 ]; then
      max=5
    fi

    # special case: we need to split the first line

    if [ "${min}" -eq 0 ]; then

      pass_part_1=$(sed -n 1p "${OUTD}/${hash_type}_dict1")
      pass_part_2=$(sed -n 1p "${OUTD}/${hash_type}_dict2")

      pass="${pass_part_1}${pass_part_2}"

      echo -n "${pass}" | cut -b -$((mask_offset + 0))  > "${OUTD}/${hash_type}_dict1_custom"
      echo -n "${pass}" | cut -b  $((mask_offset + 1))- > "${OUTD}/${hash_type}_dict2_custom"

      mask_custom=""

      for i in $(seq 1 ${mask_offset}); do

        if   [ "${hash_type}" -eq 14000 ]; then
          char=$(echo -n "${pass}" | cut -b ${i})
          mask_custom="${mask_custom}${char}"
        elif [ "${hash_type}" -eq 14100 ]; then
          char=$(echo -n "${pass}" | cut -b ${i})
          mask_custom="${mask_custom}${char}"
        else
          mask_custom="${mask_custom}?d"
        fi

      done

    fi

    i=1

    while read -r -u 9 hash; do

      if [ ${i} -gt ${min} ]; then

        if [ "${file_only}" -eq 1 ]; then

          temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"

          if [ "${hash_type}" -ne 22000 ]; then
            echo "${hash}" | base64 -d > "${temp_file}"
          else
            echo "${hash}" > "${temp_file}"
          fi

          hash="${temp_file}"

        fi

        mask=${mask_7[$i]}

        # adjust mask if needed

        line_nr=1

        if [ "${i}" -gt 1 ]; then
          line_nr=$((i - 1))
        fi

        if [ "${hash_type}" -eq 2500 ]; then

          pass_part_1=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict1")
          pass_part_2=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict2")

          pass_part_2_len=${#pass_part_2}

          pass=${pass_part_1}${pass_part_2}

          pass_len=${#pass}

          # add first x chars of password to mask and append the (old) mask

          mask_len=${#mask}
          mask_len=$((mask_len / 2))

          mask_prefix=$(echo ${pass} | cut -b -$((pass_len - mask_len - pass_part_2_len)))
          mask=${mask_prefix}${mask}

        fi

        if [ "${hash_type}" -eq 16800 ]; then

          pass_part_1=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict1")
          pass_part_2=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict2")

          pass_part_2_len=${#pass_part_2}

          pass=${pass_part_1}${pass_part_2}
          pass_len=${#pass}

          # add first x chars of password to mask and append the (old) mask

          mask_len=${#mask}
          mask_len=$((mask_len / 2))

          mask_prefix=$(echo "${pass}" | cut -b -$((pass_len - mask_len - pass_part_2_len)))
          mask=${mask_prefix}${mask}

        fi

        if [ "${hash_type}" -eq 22000 ]; then

          pass_part_1=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict1")
          pass_part_2=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict2")

          pass_part_2_len=${#pass_part_2}

          pass=${pass_part_1}${pass_part_2}
          pass_len=${#pass}

          # add first x chars of password to mask and append the (old) mask

          mask_len=${#mask}
          mask_len=$((mask_len / 2))

          mask_prefix=$(echo "${pass}" | cut -b -$((pass_len - mask_len - pass_part_2_len)))
          mask=${mask_prefix}${mask}

        fi

        if [ "${hash_type}" -eq 20510 ]; then

          pass_part_1=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict1")
          pass_part_2=$(sed -n ${line_nr}p "${OUTD}/${hash_type}_dict2")

          pass=${pass_part_1}${pass_part_2}

          pass_len=${#pass}

          if [ "${pass_len}" -le 6 ]; then
            i=$((i + 1))
            continue
          fi

          pass_old=${pass}

          pass=$(echo "${pass}" | cut -b 7-) # skip the first 6 chars

          mask_len=$((${#mask} / 2))

          echo "${pass_old}" | cut -b -$((6 + mask_len)) > "${OUTD}/${hash_type}_dict1_custom"
          echo "${pass}"     | cut -b $((mask_len + 1))- > "${OUTD}/${hash_type}_dict2_custom"

          min=0 # hack to use the custom dict
          mask_custom=${mask}

        fi

        dict1=${OUTD}/${hash_type}_dict1
        dict2=${OUTD}/${hash_type}_dict2

        if [ "${min}" -eq 0 ]; then
          mask=${mask_custom}

          dict1=${OUTD}/${hash_type}_dict1_custom
          dict2=${OUTD}/${hash_type}_dict2_custom
        fi

        CMD="./${BIN} ${OPTS} -a 7 -m ${hash_type} '${hash}' ${mask} ${dict2}"

        echo -n "[ len $i ] " >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        output=$(./${BIN} ${OPTS} -a 7 -m ${hash_type} "${hash}" ${mask} ${dict2} 2>&1)

        ret=${?}

        echo "${output}" >> "${OUTD}/logfull.txt"

        if [ "${ret}" -eq 0 ]; then

          line_nr=1

          if [ "${i}" -gt 1 ]; then
            line_nr=$((i - 1))
          fi

          line_dict1=$(sed -n ${line_nr}p "${dict1}")
          line_dict2=$(sed -n ${line_nr}p "${dict2}")

          if [ "${pass_only}" -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &>/dev/null

          newRet=$?

          if [ "${newRet}" -eq 2 ]; then

            # out-of-memory, workaround

            echo "${output}" | grep -v "^Unsupported\|^$" | head -1 > tmp_file_out
            echo "${search}" > tmp_file_search

            out_md5=$(md5sum tmp_file_out | cut -d' ' -f1)
            search_md5=$(md5sum tmp_file_search | cut -d' ' -f1)

            rm tmp_file_out tmp_file_search

            if [ "${out_md5}" == "${search_md5}" ]; then
              newRet=0
            fi
          fi

          if [ "${newRet}" -ne 0 ]; then
            if [ "${newRet}" -eq 2 ]; then
              ret=20
            else
              ret=10
            fi
          fi

        fi

        status ${ret}
      fi

      if [ $i -eq ${max} ]; then break; fi

      i=$((i + 1))

    done 9< "${OUTD}/${hash_type}_hashes.txt"

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 7, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"

    rm -f "${OUTD}/${hash_type}_dict1_custom"
    rm -f "${OUTD}/${hash_type}_dict2_custom"
  fi

  # multihash
  if [ "${MODE}" -ne 0 ]; then

    # no multi hash checks for these modes (because we only have 1 hash for each of them)

    if   [ "${hash_type}" -eq 14000 ]; then
      return
    elif [ "${hash_type}" -eq 14100 ]; then
      return
    elif [ "${hash_type}" -eq 14900 ]; then
      return
    elif [ "${hash_type}" -eq 15400 ]; then
      return
    fi

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    max=9

    if   [ "${hash_type}" -eq  2500 ]; then
      max=5
    elif [ "${hash_type}" -eq  3000 ]; then
      max=8
    elif [ "${hash_type}" -eq  7700 ] || [ "${hash_type}" -eq  7701 ]; then
      max=8
    elif [ "${hash_type}" -eq  8500 ]; then
      max=8
    elif [ "${hash_type}" -eq 14000 ]; then
      max=5
    elif [ "${hash_type}" -eq 14100 ]; then
      max=5
    elif [ "${hash_type}" -eq 14900 ]; then
      max=5
    elif [ "${hash_type}" -eq 15400 ]; then
      max=5
    elif [ "${hash_type}" -eq 16800 ]; then
      max=5
    elif [ "${hash_type}" -eq 22000 ]; then
      max=5
    fi

    if is_in_array "${hash_type}" ${TIMEOUT_ALGOS}; then
      max=7
      if [ "${hash_type}" -eq 3200 ]; then
        max=4
      fi
    fi

    i=2
    while [ "$i" -lt "$max" ]; do

      hash_file=${OUTD}/${hash_type}_hashes_multi_${i}.txt
      dict_file=${OUTD}/${hash_type}_dict2_multi_${i}

      mask=${mask_7[$i]}

      # if file_only -> decode all base64 "hashes" and put them in the temporary file

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
        rm -f "${temp_file}"

        hash_file=${temp_file}

        while read -r file_only_hash; do

          if [ "${hash_type}" -ne 22000 ]; then
            echo -n "${file_only_hash}" | base64 -d >> "${temp_file}"
          else
            echo "${file_only_hash}" >> "${temp_file}"
          fi

        done < "${OUTD}/${hash_type}_hashes_multi_${i}.txt"

        # a little hack: since we don't want to have a very large mask (and wpa has minimum length of 8),
        # we need to create a temporary dict file on-the-fly and use it like this: [small mask] [long(er) words in dict]

        dict_file=${OUTD}/${hash_type}_dict2_multi_${i}_longer
        rm -f "${dict_file}"

        mask_len=${#mask}
        mask_len=$((mask_len / 2))

        j=1

        while read -r -u 9 hash; do

          pass_part_1=$(sed -n ${j}p "${OUTD}/${hash_type}_dict1_multi_${i}")
          pass_part_2=$(sed -n ${j}p "${OUTD}/${hash_type}_dict2_multi_${i}")

          pass="${pass_part_1}${pass_part_2}"

          pass_suffix=$(echo "${pass}" | cut -b $((mask_len + 1))-)

          echo "${pass_suffix}" >> "${dict_file}"

          j=$((j + 1))

        done 9< "${OUTD}/${hash_type}_hashes_multi_${i}.txt"

      fi

      CMD="./${BIN} ${OPTS} -a 7 -m ${hash_type} ${hash_file} ${mask} ${dict_file}"

      echo "> Testing hash type $hash_type with attack mode 7, markov ${MARKOV}, multi hash with word len ${i}." >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

      output=$(./${BIN} ${OPTS} -a 7 -m ${hash_type} ${hash_file} ${mask} ${dict_file} 2>&1)

      ret=${?}

      echo "${output}" >> "${OUTD}/logfull.txt"

      if [ "${ret}" -eq 0 ]; then

        j=1

        while read -r -u 9 hash; do

          line_dict1=$(sed -n ${j}p "${OUTD}/${hash_type}_dict1_multi_${i}")
          line_dict2=$(sed -n ${j}p "${OUTD}/${hash_type}_dict2_multi_${i}")

          if [ "${pass_only}" -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &>/dev/null

          newRet=$?

          if [ "${newRet}" -ne 0 ]; then
            if [ "${newRet}" -eq 2 ]; then
              ret=20
            else
              ret=10
            fi

            break
          fi

          j=$((j + 1))

        done 9< "${OUTD}/${hash_type}_hashes_multi_${i}.txt"
      fi

      status ${ret}
      i=$((i + 1))

    done

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 7, Mode multi,  Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi
}

function cryptoloop_test()
{
  hashType=$1
  keySize=$2
  CMD="unset"

  mkdir -p ${OUTD}/cl_tests
  chmod u+x "${TDIR}/cryptoloop2hashcat.py"

  case $hashType in

    14511)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha1_aes_${keySize}.img\" --hash sha1 --cipher aes --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha1_aes_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha1_aes_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14512)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha1_serpent_${keySize}.img\" --hash sha1 --cipher serpent --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha1_serpent_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha1_serpent_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14513)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha1_twofish_${keySize}.img\" --hash sha1 --cipher twofish --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha1_twofish_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha1_twofish_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14521)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha256_aes_${keySize}.img\" --hash sha256 --cipher aes --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha256_aes_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha256_aes_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14522)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha256_serpent_${keySize}.img\" --hash sha256 --cipher serpent --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha256_serpent_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha256_serpent_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14523)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha256_twofish_${keySize}.img\" --hash sha256 --cipher twofish --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha256_twofish_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha256_twofish_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14531)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha512_aes_${keySize}.img\" --hash sha512 --cipher aes --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha512_aes_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha512_aes_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14532)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha512_serpent_${keySize}.img\" --hash sha512 --cipher serpent --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha512_serpent_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha512_serpent_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14533)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_sha512_twofish_${keySize}.img\" --hash sha512 --cipher twofish --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_sha512_twofish_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_sha512_twofish_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14541)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_ripemd160_aes_${keySize}.img\" --hash ripemd160 --cipher aes --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_ripemd160_aes_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_ripemd160_aes_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14542)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_ripemd160_serpent_${keySize}.img\" --hash ripemd160 --cipher serpent --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_ripemd160_serpent_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_ripemd160_serpent_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14543)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_ripemd160_twofish_${keySize}.img\" --hash ripemd160 --cipher twofish --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_ripemd160_twofish_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_ripemd160_twofish_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14551)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_whirlpool_aes_${keySize}.img\" --hash whirlpool --cipher aes --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_whirlpool_aes_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_whirlpool_aes_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14552)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py\" --source \"${TDIR}/cl_tests/hashcat_whirlpool_serpent_${keySize}.img\" --hash whirlpool --cipher serpent --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_whirlpool_serpent_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_whirlpool_serpent_${keySize}.hash hashca?l"
          ;;
      esac
      ;;

    14553)
      case $keySize in
        128|192|256)
          eval \"${TDIR}/cryptoloop2hashcat.py --source ${TDIR}/cl_tests/hashcat_whirlpool_twofish_${keySize}.img\" --hash whirlpool --cipher twofish --keysize ${keySize} > ${OUTD}/cl_tests/hashcat_whirlpool_twofish_${keySize}.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 14500 ${OUTD}/cl_tests/hashcat_whirlpool_twofish_${keySize}.hash hashca?l"
          ;;
      esac
      ;;
  esac

  if [ ${#CMD} -gt 5 ]; then
    echo "> Testing hash type $hashType with attack mode 3, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, Key-Size ${keySize}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    output=$(${CMD} 2>&1)

    ret=${?}

    echo "${output}" >> "${OUTD}/logfull.txt"

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    status ${ret}

    cnt=1

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 3, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, Key-Size ${keySize} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi
}

function truecrypt_test()
{
  hashType=$1
  tcMode=$2
  CMD="unset"

  mkdir -p ${OUTD}/tc_tests
  chmod u+x "${TDIR}/truecrypt2hashcat.py"

  case $hashType in

    6211)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6211 '${TDIR}/tc_tests/hashcat_ripemd160_aes.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6211 '${TDIR}/tc_tests/hashcat_ripemd160_serpent.tc' hashca?l"
          ;;
        2)
          CMD="./${BIN} ${OPTS} -a 3 -m 6211 '${TDIR}/tc_tests/hashcat_ripemd160_twofish.tc' hashca?l"
          ;;
      esac
      ;;

    6212)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6212 '${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6212 '${TDIR}/tc_tests/hashcat_ripemd160_serpent-aes.tc' hashca?l"
          ;;
        2)
          CMD="./${BIN} ${OPTS} -a 3 -m 6212 '${TDIR}/tc_tests/hashcat_ripemd160_twofish-serpent.tc' hashca?l"
          ;;
      esac
      ;;

    6213)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6213 '${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish-serpent.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6213 '${TDIR}/tc_tests/hashcat_ripemd160_serpent-twofish-aes.tc' hashca?l"
          ;;
      esac
      ;;

    6221)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6221 '${TDIR}/tc_tests/hashcat_sha512_aes.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6221 '${TDIR}/tc_tests/hashcat_sha512_serpent.tc' hashca?l"
          ;;
        2)
          CMD="./${BIN} ${OPTS} -a 3 -m 6221 '${TDIR}/tc_tests/hashcat_sha512_twofish.tc' hashca?l"
          ;;
      esac
      ;;

    6222)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6222 '${TDIR}/tc_tests/hashcat_sha512_aes-twofish.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6222 '${TDIR}/tc_tests/hashcat_sha512_serpent-aes.tc' hashca?l"
          ;;
        2)
          CMD="./${BIN} ${OPTS} -a 3 -m 6222 '${TDIR}/tc_tests/hashcat_sha512_twofish-serpent.tc' hashca?l"
          ;;
      esac
      ;;

    6223)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6223 '${TDIR}/tc_tests/hashcat_sha512_aes-twofish-serpent.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6223 '${TDIR}/tc_tests/hashcat_sha512_serpent-twofish-aes.tc' hashca?l"
          ;;
      esac
      ;;

    6231)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6231 '${TDIR}/tc_tests/hashcat_whirlpool_aes.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6231 '${TDIR}/tc_tests/hashcat_whirlpool_serpent.tc' hashca?l"
          ;;
        2)
          CMD="./${BIN} ${OPTS} -a 3 -m 6231 '${TDIR}/tc_tests/hashcat_whirlpool_twofish.tc' hashca?l"
          ;;
      esac
      ;;

    6232)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6232 '${TDIR}/tc_tests/hashcat_whirlpool_aes-twofish.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6232 '${TDIR}/tc_tests/hashcat_whirlpool_serpent-aes.tc' hashca?l"
          ;;
        2)
          CMD="./${BIN} ${OPTS} -a 3 -m 6232 '${TDIR}/tc_tests/hashcat_whirlpool_twofish-serpent.tc' hashca?l"
          ;;
      esac
      ;;

    6233)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6233 '${TDIR}/tc_tests/hashcat_whirlpool_aes-twofish-serpent.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6233 '${TDIR}/tc_tests/hashcat_whirlpool_serpent-twofish-aes.tc' hashca?l"
          ;;
      esac
      ;;

    6241)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6241 '${TDIR}/tc_tests/hashcat_ripemd160_aes_boot.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6241 '${TDIR}/tc_tests/hashcat_ripemd160_serpent_boot.tc' hashca?l"
          ;;
        2)
          CMD="./${BIN} ${OPTS} -a 3 -m 6241 '${TDIR}/tc_tests/hashcat_ripemd160_twofish_boot.tc' hashca?l"
          ;;
      esac
      ;;

    6242)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6242 '${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish_boot.tc' hashca?l"
          ;;
        1)
          CMD="./${BIN} ${OPTS} -a 3 -m 6242 '${TDIR}/tc_tests/hashcat_ripemd160_serpent-aes_boot.tc' hashca?l"
          ;;
      esac
      ;;

    6243)
      case $tcMode in
        0)
          CMD="./${BIN} ${OPTS} -a 3 -m 6243 '${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish-serpent_boot.tc' hashca?l"
          ;;
      esac
      ;;

    29311)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_aes.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29311 '${OUTD}/tc_tests/hashcat_ripemd160_aes.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_serpent.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29311 '${OUTD}/tc_tests/hashcat_ripemd160_serpent.hash' hashca?l"
          ;;
        2)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_twofish.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_twofish.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29311 '${OUTD}/tc_tests/hashcat_ripemd160_twofish.hash' hashca?l"
          ;;
      esac
      ;;

    29312)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29312 '${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_serpent-aes.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_serpent-aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29312 '${OUTD}/tc_tests/hashcat_ripemd160_serpent-aes.hash' hashca?l"
          ;;
        2)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_twofish-serpent.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_twofish-serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29312 '${OUTD}/tc_tests/hashcat_ripemd160_twofish-serpent.hash' hashca?l"
          ;;
      esac
      ;;

    29313)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish-serpent.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish-serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29313 '${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish-serpent.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_serpent-twofish-aes.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_serpent-twofish-aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29313 '${OUTD}/tc_tests/hashcat_ripemd160_serpent-twofish-aes.hash' hashca?l"
          ;;
      esac
      ;;

    29321)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_aes.tc\" > ${OUTD}/tc_tests/hashcat_sha512_aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29321 '${OUTD}/tc_tests/hashcat_sha512_aes.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_serpent.tc\" > ${OUTD}/tc_tests/hashcat_sha512_serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29321 '${OUTD}/tc_tests/hashcat_sha512_serpent.hash' hashca?l"
          ;;
        2)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_twofish.tc\" > ${OUTD}/tc_tests/hashcat_sha512_twofish.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29321 '${OUTD}/tc_tests/hashcat_sha512_twofish.hash' hashca?l"
          ;;
      esac
      ;;

    29322)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_aes-twofish.tc\" > ${OUTD}/tc_tests/hashcat_sha512_aes-twofish.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29322 '${OUTD}/tc_tests/hashcat_sha512_aes-twofish.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_serpent-aes.tc\" > ${OUTD}/tc_tests/hashcat_sha512_serpent-aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29322 '${OUTD}/tc_tests/hashcat_sha512_serpent-aes.hash' hashca?l"
          ;;
        2)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_twofish-serpent.tc\" > ${OUTD}/tc_tests/hashcat_sha512_twofish-serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29322 '${OUTD}/tc_tests/hashcat_sha512_twofish-serpent.hash' hashca?l"
          ;;
      esac
      ;;

    29323)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_aes-twofish-serpent.tc\" > ${OUTD}/tc_tests/hashcat_sha512_aes-twofish-serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29323 '${OUTD}/tc_tests/hashcat_sha512_aes-twofish-serpent.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_sha512_serpent-twofish-aes.tc\" > ${OUTD}/tc_tests/hashcat_sha512_serpent-twofish-aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29323 '${OUTD}/tc_tests/hashcat_sha512_serpent-twofish-aes.hash' hashca?l"
          ;;
      esac
      ;;

    29331)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_aes.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29331 '${OUTD}/tc_tests/hashcat_whirlpool_aes.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_serpent.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29331 '${OUTD}/tc_tests/hashcat_whirlpool_serpent.hash' hashca?l"
          ;;
        2)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_twofish.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_twofish.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29331 '${OUTD}/tc_tests/hashcat_whirlpool_twofish.hash' hashca?l"
          ;;
      esac
      ;;

    29332)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_aes-twofish.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_aes-twofish.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29332 '${OUTD}/tc_tests/hashcat_whirlpool_aes-twofish.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_serpent-aes.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_serpent-aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29332 '${OUTD}/tc_tests/hashcat_whirlpool_serpent-aes.hash' hashca?l"
          ;;
        2)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_twofish-serpent.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_twofish-serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29332 '${OUTD}/tc_tests/hashcat_whirlpool_twofish-serpent.hash' hashca?l"
          ;;
      esac
      ;;

    29333)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_aes-twofish-serpent.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_aes-twofish-serpent.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29333 '${OUTD}/tc_tests/hashcat_whirlpool_aes-twofish-serpent.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_whirlpool_serpent-twofish-aes.tc\" > ${OUTD}/tc_tests/hashcat_whirlpool_serpent-twofish-aes.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29333 '${OUTD}/tc_tests/hashcat_whirlpool_serpent-twofish-aes.hash' hashca?l"
          ;;
      esac
      ;;

    29341)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_aes_boot.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_aes_boot.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29341 '${OUTD}/tc_tests/hashcat_ripemd160_aes_boot.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_serpent_boot.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_serpent_boot.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29341 '${OUTD}/tc_tests/hashcat_ripemd160_serpent_boot.hash' hashca?l"
          ;;
        2)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_twofish_boot.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_twofish_boot.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29341 '${OUTD}/tc_tests/hashcat_ripemd160_twofish_boot.hash' hashca?l"
          ;;
      esac
      ;;

    29342)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish_boot.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish_boot.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29342 '${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish_boot.hash' hashca?l"
          ;;
        1)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_serpent-aes_boot.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_serpent-aes_boot.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29342 '${OUTD}/tc_tests/hashcat_ripemd160_serpent-aes_boot.hash' hashca?l"
          ;;
      esac
      ;;

    29343)
      case $tcMode in
        0)
          eval \"${TDIR}/truecrypt2hashcat.py\" \"${TDIR}/tc_tests/hashcat_ripemd160_aes-twofish-serpent_boot.tc\" > ${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish-serpent_boot.hash
          CMD="./${BIN} ${OPTS} -a 3 -m 29343 '${OUTD}/tc_tests/hashcat_ripemd160_aes-twofish-serpent_boot.hash' hashca?l"
          ;;
      esac
      ;;
  esac

  if [ ${#CMD} -gt 5 ]; then
    echo "> Testing hash type $hashType with attack mode 3, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, tcMode ${tcMode}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

    output=$(eval ${CMD} 2>&1)

    ret=${?}

    echo "${output}" >> "${OUTD}/logfull.txt"

    e_ce=0
    e_rs=0
    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    status ${ret}

    cnt=1

    msg="OK"

    if [ "${e_ce}" -ne 0 ]; then
      msg="Compare Error"
    elif [ "${e_rs}" -ne 0 ]; then
      msg="Skip"
    elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
      msg="Error"
    elif [ "${e_to}" -ne 0 ]; then
      msg="Warning"
    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 3, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, tcMode ${tcMode} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
  fi
}

# Compose and execute hashcat command on a VeraCrypt test container
# Must not be called for hash types other than 137XY/294XY
# $1: cipher variation, can be 0-6
function veracrypt_test()
{
  cipher_variation=$1

  hash_function=""

  hash_digit="${hash_type:3:1}"
  [ "$hash_digit" -eq "1" ] && hash_function="ripemd160"
  [ "$hash_digit" -eq "2" ] && hash_function="sha512"
  [ "$hash_digit" -eq "3" ] && hash_function="whirlpool"
  [ "$hash_digit" -eq "5" ] && hash_function="sha256"
  [ "$hash_digit" -eq "7" ] && hash_function="streebog"

  [ -n "$hash_function" ] || return

  cipher_cascade=""

  cipher_digit="${hash_type:4:1}"
  case $cipher_digit in
    1)
      [ "$cipher_variation" -eq "0" ] && cipher_cascade="aes"
      [ "$cipher_variation" -eq "1" ] && cipher_cascade="serpent"
      [ "$cipher_variation" -eq "2" ] && cipher_cascade="twofish"
      [ "$cipher_variation" -eq "3" ] && cipher_cascade="camellia"
      [ "$cipher_variation" -eq "5" ] && cipher_cascade="kuznyechik"
      ;;
    2)
      [ "$cipher_variation" -eq "0" ] && cipher_cascade="aes-twofish"
      [ "$cipher_variation" -eq "1" ] && cipher_cascade="serpent-aes"
      [ "$cipher_variation" -eq "2" ] && cipher_cascade="twofish-serpent"
      [ "$cipher_variation" -eq "3" ] && cipher_cascade="camellia-kuznyechik"
      [ "$cipher_variation" -eq "4" ] && cipher_cascade="camellia-serpent"
      [ "$cipher_variation" -eq "5" ] && cipher_cascade="kuznyechik-aes"
      [ "$cipher_variation" -eq "6" ] && cipher_cascade="kuznyechik-twofish"
      ;;
    3)
      [ "$cipher_variation" -eq "0" ] && cipher_cascade="aes-twofish-serpent"
      [ "$cipher_variation" -eq "1" ] && cipher_cascade="serpent-twofish-aes"
      [ "$cipher_variation" -eq "5" ] && cipher_cascade="kuznyechik-serpent-camellia"
      ;;
  esac

  [ -n "$cipher_cascade" ] || return

  filename="${TDIR}/vc_tests/hashcat_${hash_function}_${cipher_cascade}.vc"

  # The hash-cipher combination might be invalid (e.g. RIPEMD-160 + Kuznyechik)
  [ -f "${filename}" ] || return

  case "${hash_type:0:3}" in
    137)
      CMD="./${BIN} ${OPTS} -a 3 -m ${hash_type} '${filename}' hashc?lt"
      ;;

    294)
      mkdir -p ${OUTD}/vc_tests
      chmod u+x "${TDIR}/veracrypt2hashcat.py"

      eval \"${TDIR}/veracrypt2hashcat.py\" \"${TDIR}/vc_tests/hashcat_${hash_function}_${cipher_cascade}.vc\" > ${OUTD}/vc_tests/hashcat_${hash_function}_${cipher_cascade}.hash
      CMD="./${BIN} ${OPTS} -a 3 -m ${hash_type} '${OUTD}/vc_tests/hashcat_${hash_function}_${cipher_cascade}.hash' hashc?lt"
      ;;
  esac

  echo "> Testing hash type ${hash_type} with attack mode 0, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, Cipher ${cipher_cascade}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

  output=$(eval ${CMD} 2>&1)

  ret=${?}

  echo "${output}" >> "${OUTD}/logfull.txt"

  e_ce=0
  e_rs=0
  e_to=0
  e_nf=0
  e_nm=0
  cnt=0

  status ${ret}

  cnt=1

  msg="OK"

  if [ "${e_ce}" -ne 0 ]; then
    msg="Compare Error"
  elif [ "${e_rs}" -ne 0 ]; then
    msg="Skip"
  elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
    msg="Error"
  elif [ "${e_to}" -ne 0 ]; then
    msg="Warning"
  fi

  echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 0, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, Cipher ${cipher_cascade} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"
}

function luks_test()
{
  hashType=$1
  attackType=$2

  # if -m all was set let us default to -a 3 only. You could specify the attack type directly, e.g. -m 0
  # the problem with defaulting to all=0,1,3,6,7 is that it could take way too long

  if [ "${attackType}" -eq 65535 ]; then
    attackType=3
  fi

  mkdir -p "${OUTD}/luks_tests"
  chmod u+x "${TDIR}/luks2hashcat.py"

  for luksMode in "cbc-essiv" "cbc-plain64" "xts-plain64"; do
    for luksKeySize in "128" "256" "512"; do
      CMD="unset"

      # filter out not supported combinations:

      case "${luksKeySize}" in
        128)
          case "${luksMode}" in
            cbc-essiv|cbc-plain64)
            ;;
            *)
              continue
            ;;
          esac
        ;;
        256)
          case "${luksMode}" in
            cbc-essiv|cbc-plain64|xts-plain64)
            ;;
            *)
              continue
            ;;
          esac
        ;;
        512)
          case "${luksMode}" in
            xts-plain64)
            ;;
            *)
              continue
            ;;
          esac
        ;;
      esac

      case $hashType in
        29511)
          luksHash="sha1"
          luksCipher="aes"
          ;;

        29512)
          luksHash="sha1"
          luksCipher="serpent"
          ;;

        29513)
          luksHash="sha1"
          luksCipher="twofish"
          ;;

        29521)
          luksHash="sha256"
          luksCipher="aes"
          ;;

        29522)
          luksHash="sha256"
          luksCipher="serpent"
          ;;

        29523)
          luksHash="sha256"
          luksCipher="twofish"
          ;;

        29531)
          luksHash="sha512"
          luksCipher="aes"
          ;;

        29532)
          luksHash="sha512"
          luksCipher="serpent"
          ;;

        29533)
          luksHash="sha512"
          luksCipher="twofish"
          ;;

        29541)
          luksHash="ripemd160"
          luksCipher="aes"
          ;;

        29542)
          luksHash="ripemd160"
          luksCipher="serpent"
          ;;

        29543)
          luksHash="ripemd160"
          luksCipher="twofish"
          ;;

      esac

      luksMainMask="?l"
      luksMask="${luksMainMask}"

      # for combination or hybrid attacks
      luksPassPartFile1="${OUTD}/${hashType}_dict1"
      luksPassPartFile2="${OUTD}/${hashType}_dict2"

      luksContainer="${TDIR}/luks_tests/hashcat_${luksHash}_${luksCipher}_${luksMode}_${luksKeySize}.luks"
      luksHashFile="${OUTD}/luks_tests/hashcat_${luksHash}_${luksCipher}_${luksMode}_${luksKeySize}.hash"

      case $attackType in
        0)
          CMD="./${BIN} ${OPTS} -a 0 -m ${hashType} '${luksHashFile}' '${TDIR}/luks_tests/pw'"
          ;;
        1)
          luksPassPart1Len=$((${#LUKS_PASSWORD} / 2))
          luksPassPart2Start=$((luksPassPart1Len + 1))

          echo "${LUKS_PASSWORD}" | cut -c-${luksPassPart1Len} > "${luksPassPartFile1}" 2>/dev/null
          echo "${LUKS_PASSWORD}" | cut -c${luksPassPart2Start}- > "${luksPassPartFile2}" 2>/dev/null

          CMD="./${BIN} ${OPTS} -a 6 -m ${hashType} '${luksHashFile}' ${luksPassPartFile1} ${luksPassPartFile2}"
          ;;
        3)
          luksMaskFixedLen=$((${#LUKS_PASSWORD} - 1))

          luksMask="$(echo "${LUKS_PASSWORD}" | cut -c-${luksMaskFixedLen} 2>/dev/null)"
          luksMask="${luksMask}${luksMainMask}"

          CMD="./${BIN} ${OPTS} -a 3 -m ${hashType} '${luksHashFile}' ${luksMask}"
          ;;
        6)
          luksPassPart1Len=$((${#LUKS_PASSWORD} - 1))

          echo "${LUKS_PASSWORD}" | cut -c-${luksPassPart1Len} > "${luksPassPartFile1}" 2>/dev/null

          CMD="./${BIN} ${OPTS} -a 6 -m ${hashType} '${luksHashFile}' ${luksPassPartFile1} ${luksMask}"
          ;;
        7)
          echo "${LUKS_PASSWORD}" | cut -c2- > "${luksPassPartFile1}" 2>/dev/null

          CMD="./${BIN} ${OPTS} -a 7 -m ${hashType} '${luksHashFile}' ${luksMask} ${luksPassPartFile1}"
          ;;
      esac

      eval \"${TDIR}/luks2hashcat.py\" \"${luksContainer}\" > "${luksHashFile}"

      luksMode="${luksHash}-${luksCipher}-${luksMode}-${luksKeySize}"

      if [ -n "${CMD}" ] && [ ${#CMD} -gt 5 ]; then
        echo "> Testing hash type ${hashType} with attack mode ${attackType}, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, Luks-Mode ${luksMode}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

        if [ -f "${luks_first_test_file}" ]; then
          output=$(eval ${CMD} 2>&1)
          ret=${?}

          echo "${output}" >> "${OUTD}/logfull.txt"
        else
          ret=30
        fi

        e_ce=0
        e_rs=0
        e_to=0
        e_nf=0
        e_nm=0
        cnt=0

        status ${ret}

        cnt=1

        msg="OK"

        if [ "${e_ce}" -ne 0 ]; then
          msg="Compare Error"
        elif [ "${e_rs}" -ne 0 ]; then
          msg="Skip"
        elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
          msg="Error"
        elif [ "${e_to}" -ne 0 ]; then
          msg="Warning"
        fi

        echo "[ ${OUTD} ] [ Type ${hash_type}, Attack ${attackType}, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, Luks-Mode ${luksMode} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"

        status ${ret}
      fi
    done
  done
}

function luks_legacy_test()
{
  hashType=$1
  attackType=$2

  # if -m all was set let us default to -a 3 only. You could specify the attack type directly, e.g. -m 0
  # the problem with defaulting to all=0,1,3,6,7 is that it could take way too long

  if [ "${attackType}" -eq 65535 ]; then
    attackType=3
  fi

  #LUKS_HASHES="sha1 sha256 sha512 ripemd160 whirlpool"
  LUKS_HASHES="sha1 sha256 sha512 ripemd160"
  LUKS_CIPHERS="aes serpent twofish"
  LUKS_CIPHER_MODES="cbc-essiv cbc-plain64 xts-plain64"
  LUKS_KEYSIZES="128 256 512"

  LUKS_PASSWORD=$(cat "${TDIR}/luks_tests/pw" 2>/dev/null)

  for luks_h in ${LUKS_HASHES}; do
    for luks_c in ${LUKS_CIPHERS}; do
      for luks_m in ${LUKS_CIPHER_MODES}; do
        for luks_k in ${LUKS_KEYSIZES}; do

          CMD=""

          # filter out not supported combinations:

          case "${luks_k}" in
            128)
              case "${luks_m}" in
                cbc-essiv|cbc-plain64)
                ;;
                *)
                  continue
                ;;
              esac
            ;;
            256)
              case "${luks_m}" in
                cbc-essiv|cbc-plain64|xts-plain64)
                ;;
                *)
                  continue
                ;;
              esac
            ;;
            512)
              case "${luks_m}" in
                xts-plain64)
                ;;
                *)
                  continue
                ;;
              esac
            ;;
          esac

          luks_mode="${luks_h}-${luks_c}-${luks_m}-${luks_k}"
          luks_file="${TDIR}/luks_tests/hashcat_${luks_h}_${luks_c}_${luks_m}_${luks_k}.luks"
          luks_main_mask="?l"
          luks_mask="${luks_main_mask}"

          # for combination or hybrid attacks
          luks_pass_part_file1="${OUTD}/${hashType}_dict1"
          luks_pass_part_file2="${OUTD}/${hashType}_dict2"

          case $attackType in
            0)
              CMD="./${BIN} ${OPTS} -a 0 -m ${hashType} '${luks_file}' '${TDIR}/luks_tests/pw'"
              ;;
            1)
              luks_pass_part1_len=$((${#LUKS_PASSWORD} / 2))
              luks_pass_part2_start=$((luks_pass_part1_len + 1))

              echo "${LUKS_PASSWORD}" | cut -c-${luks_pass_part1_len} > "${luks_pass_part_file1}" 2>/dev/null
              echo "${LUKS_PASSWORD}" | cut -c${luks_pass_part2_start}- > "${luks_pass_part_file2}" 2>/dev/null

              CMD="./${BIN} ${OPTS} -a 6 -m ${hashType} '${luks_file}' ${luks_pass_part_file1} ${luks_pass_part_file2}"
              ;;
            3)
              luks_mask_fixed_len=$((${#LUKS_PASSWORD} - 1))

              luks_mask="$(echo "${LUKS_PASSWORD}" | cut -c-${luks_mask_fixed_len} 2>/dev/null)"
              luks_mask="${luks_mask}${luks_main_mask}"

              CMD="./${BIN} ${OPTS} -a 3 -m ${hashType} '${luks_file}' ${luks_mask}"
              ;;
            6)
              luks_pass_part1_len=$((${#LUKS_PASSWORD} - 1))

              echo "${LUKS_PASSWORD}" | cut -c-${luks_pass_part1_len} > "${luks_pass_part_file1}" 2>/dev/null

              CMD="./${BIN} ${OPTS} -a 6 -m ${hashType} '${luks_file}' ${luks_pass_part_file1} ${luks_mask}"
              ;;
            7)
              echo "${LUKS_PASSWORD}" | cut -c2- > "${luks_pass_part_file1}" 2>/dev/null

              CMD="./${BIN} ${OPTS} -a 7 -m ${hashType} '${luks_file}' ${luks_mask} ${luks_pass_part_file1}"
              ;;
          esac

          if [ -n "${CMD}" ]; then
            echo "> Testing hash type ${hashType} with attack mode ${attackType}, markov ${MARKOV}, single hash, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, luksMode ${luks_mode}" >> "${OUTD}/logfull.txt" 2>> "${OUTD}/logfull.txt"

            if [ -f "${luks_first_test_file}" ]; then
              output=$(eval ${CMD} 2>&1)
              ret=${?}

              echo "${output}" >> "${OUTD}/logfull.txt"
            else
              ret=30
            fi

            e_ce=0
            e_rs=0
            e_to=0
            e_nf=0
            e_nm=0
            cnt=0

            status ${ret}

            cnt=1

            msg="OK"

            if [ "${e_ce}" -ne 0 ]; then
              msg="Compare Error"
            elif [ "${e_rs}" -ne 0 ]; then
              msg="Skip"
            elif [ "${e_nf}" -ne 0 ] || [ "${e_nm}" -ne 0 ]; then
              msg="Error"
            elif [ "${e_to}" -ne 0 ]; then
              msg="Warning"
            fi

            echo "[ ${OUTD} ] [ Type ${hash_type}, Attack ${attackType}, Mode single, Device-Type ${DEVICE_TYPE}, Kernel-Type ${KERNEL_TYPE}, Vector-Width ${VECTOR}, luksMode ${luks_mode} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout, ${e_rs}/${cnt} skipped"

            status ${ret}
          fi
        done
      done
    done
  done
}

function usage()
{
cat << EOF
> Usage : ${0} <options>

OPTIONS:

  -V    Backend vector-width (either 1, 2, 4 or 8), overrides value from device query :
        '1'         => vector-width 1
        '2'         => vector-width 2 (default)
        '4'         => vector-width 4
        '8'         => vector-width 8
        'all'       => test sequentially vector-width ${VECTOR_WIDTHS}

  -t    Select test mode :
        'single'    => single hash (default)
        'multi'     => multi hash
        'all'       => single and multi hash

  -m    Select hash type :
        'all'       => all hash type supported
        (int)       => hash type integer code (default : 0)
        (int)-(int) => hash type integer range

  -a    Select attack mode :
        'all'       => all attack modes
        (int)       => attack mode integer code (default : 0)

  -x    Select cpu architecture :
        '32'        => 32 bit architecture
        '64'        => 64 bit architecture (default)

  -o    Select operating system :
        'win'       => Windows operating system (use .exe file extension)
        'linux'     => Linux operating system (use .bin file extension)
        'macos'     => macOS operating system (use .app file extension)

  -d    Select the Backend device :
        (int)[,int] => comma separated list of devices (default : 1)

  -D    Select the OpenCL device types :
        '1'         => CPU
        '2'         => GPU (default)
        '3'         => FPGA, DSP, Co-Processor
        (int)[,int] => multiple comma separated device types from the list above

  -O    Use optimized kernels (default : -O)

  -P    Use pure kernels instead of optimized kernels (default : -O)

  -s    Use this session name instead of the default one (default : "hashcat")

  -c    Disables markov-chains

  -f    Use --force to ignore hashcat warnings (default : disabled)

  -r    Setup max runtime limit (default: 400)

  -p    Package the tests into a .7z file

  -F    Use this folder as test folder instead of the default one
        (string)    => path to folder

  -I    Use this folder as input/output folder for packaged tests
        (string)    => path to folder

  -h    Show this help

EOF

  exit 1
}

BIN="hashcat"
MARKOV="enabled"
ATTACK=0
MODE=0
DEVICE_TYPE="null"
KERNEL_TYPE="Optimized"
VECTOR="default"
HT=0
PACKAGE=0
OPTIMIZED=1

while getopts "V:t:m:a:b:hcpd:x:o:d:D:F:POI:s:fr:" opt; do

  case ${opt} in
    "V")
      if [ "${OPTARG}" = "1" ]; then
        VECTOR=1
      elif [ "${OPTARG}" = "2" ]; then
        VECTOR=2
      elif [ "${OPTARG}" = "4" ]; then
        VECTOR=4
      elif [ "${OPTARG}" = "8" ]; then
        VECTOR=8
      elif [ "${OPTARG}" = "16" ]; then
        VECTOR=16
      elif [ "${OPTARG}" = "all" ]; then
        VECTOR="all"
      else
        usage
      fi
      ;;

    "t")
      if [ "${OPTARG}" = "single" ]; then
        MODE=0
      elif [ "${OPTARG}" = "multi" ]; then
        MODE=1
      elif [ "${OPTARG}" = "all" ]; then
        MODE=2
      else
        usage
      fi
      ;;

    "m")
      if [ "${OPTARG}" = "all" ]; then
        HT=65535
      else
        HT=${OPTARG}
      fi
      ;;

    "a")
      if [ "${OPTARG}" = "all" ]; then
        ATTACK=65535
      elif [ "${OPTARG}" = "0" ]; then
        ATTACK=0
      elif [ "${OPTARG}" = "1" ]; then
        ATTACK=1
      elif [ "${OPTARG}" = "3" ]; then
        ATTACK=3
      elif [ "${OPTARG}" = "6" ]; then
        ATTACK=6
      elif [ "${OPTARG}" = "7" ]; then
        ATTACK=7
      else
        usage
      fi
      ;;

    "c")
      OPTS="${OPTS} --markov-disable"
      MARKOV="disabled"
      ;;

    "I")
      PACKAGE_FOLDER=$( echo "${OPTARG}" | sed 's!/$!!g' )
      ;;

    "s")
      OPTS="${OPTS} --session \"${OPTARG}\""
      ;;

    "p")
      PACKAGE=1
      ;;

    "x")
      if [ "${OPTARG}" = "32" ]; then
        ARCHITECTURE=32
      elif [ "${OPTARG}" = "64" ]; then
        ARCHITECTURE=64
      else
        usage
      fi
      ;;

    "o")
      if [ "${OPTARG}" = "win" ]; then
        EXTENSION="exe"
      elif [ "${OPTARG}" = "linux" ]; then
        EXTENSION="bin"
      elif [ "${OPTARG}" = "macos" ]; then
        EXTENSION="app"
      else
        usage
      fi
      ;;

    "O")
      # optimized is already default, ignore it
      ;;

    "d")
      OPTS="${OPTS} -d ${OPTARG}"
      ;;

    "D")
      if [ "${OPTARG}" = "1" ]; then
        OPTS="${OPTS} -D 1"
        DEVICE_TYPE="Cpu"
      elif [ "${OPTARG}" = "2" ]; then
        OPTS="${OPTS} -D 2"
        DEVICE_TYPE="Gpu"
      else
        OPTS="${OPTS} -D ${OPTARG}"
        DEVICE_TYPE="Cpu + Gpu"
      fi
      ;;

    "F")
      OUTD=$( echo "${OPTARG}" | sed 's!/$!!g' )
      ;;

    "P")
      OPTIMIZED=0
      KERNEL_TYPE="Pure"
      ;;

    "f")
      FORCE=1
      ;;

    "r")
      RUNTIME=${OPTARG}
      ;;

    \?)
      usage
      ;;

    "h")
      usage
      ;;
  esac

done

# handle Apple Silicon

IS_APPLE_SILICON=0

if [ $(uname) == "Darwin" ]; then
  BIN_sysctl=$(which sysctl)
  if [ $? -eq 0 ]; then
    CPU_TYPE=$(sysctl hw.cputype | awk '{print $2}')

    if [ ${CPU_TYPE} -eq 16777228 ]; then
      IS_APPLE_SILICON=1
    fi
  fi
fi

export IS_OPTIMIZED=${OPTIMIZED}

if [ "${OPTIMIZED}" -eq 1 ]; then
  OPTS="${OPTS} -O"
fi

# set max-runtime

OPTS="${OPTS} --runtime ${RUNTIME}"

# set default device-type to CPU with Apple Intel, else GPU

if [ "${DEVICE_TYPE}" = "null" ]; then
  if [ $(uname) == "Darwin" ] && [ ${IS_APPLE_SILICON} -eq 0 ]; then
    OPTS="${OPTS} -D 1"
    DEVICE_TYPE="Cpu"
  else
    OPTS="${OPTS} -D 2"
    DEVICE_TYPE="Gpu"
  fi
fi

if [ ${FORCE} -eq 1 ]; then
  OPTS="${OPTS} --force"
fi

if [ -n "${ARCHITECTURE}" ]; then
  BIN="${BIN}${ARCHITECTURE}"
fi

if [ -n "${EXTENSION}" ]; then
  BIN="${BIN}.${EXTENSION}"
fi

if [ -n "${PACKAGE_FOLDER}" ]; then
  if [ ! -e "${PACKAGE_FOLDER}" ]; then
    echo "! folder '${PACKAGE_FOLDER}' does not exist"
    exit 1
  fi
fi

if [ "${PACKAGE}" -eq 0 ] || [ -z "${PACKAGE_FOLDER}" ]; then

  # check existence of binary
  if [ ! -e "${BIN}" ]; then
    echo "! ${BIN} not found, please build binary before run test."
    exit 1
  fi

  HT_MIN=0
  HT_MAX=0

  if echo -n "${HT}" | grep -q '^[0-9]\+$'; then
    HT_MIN=${HT}
    HT_MAX=${HT}
  elif echo -n "${HT}" | grep -q '^[0-9]\+-[1-9][0-9]*$'; then
    HT_MIN=$(echo -n ${HT} | sed "s/-.*//")
    HT_MAX=$(echo -n ${HT} | sed "s/.*-//")

    if [ "${HT_MIN}" -gt "${HT_MAX}" ]; then
      echo "! hash type range -m ${HT} is not valid ..."
      usage
    fi
  else
    echo "! hash type is not a number ..."
    usage
  fi

  HT=${HT_MIN}

  # filter by hash_type
  if [ "${HT}" -ne 65535 ]; then

    # validate filter

    if ! is_in_array "${HT_MIN}" ${HASH_TYPES}; then
      echo "! invalid hash type selected ..."
      usage
    fi

    if ! is_in_array "${HT_MAX}" ${HASH_TYPES}; then
      echo "! invalid hash type selected ..."
      usage
    fi
  fi

  if [ -z "${PACKAGE_FOLDER}" ]; then

    # make new dir
    mkdir -p "${OUTD}"

    # generate random test entry
    if [ "${HT}" -eq 65535 ]; then
      for TMP_HT in ${HASH_TYPES}; do
        if ! is_in_array "${TMP_HT}" ${LUKS_MODES}; then
          if ! is_in_array "${TMP_HT}" ${TC_MODES}; then
            if ! is_in_array "${TMP_HT}" ${VC_MODES}; then
              if ! is_in_array "${TMP_HT}" ${CL_MODES}; then
                perl tools/test.pl single "${TMP_HT}" >> "${OUTD}/all.sh"
              fi
            fi
          fi
        fi
      done
    else
      for TMP_HT in $(seq "${HT_MIN}" "${HT_MAX}"); do
        if ! is_in_array "${TMP_HT}" ${HASH_TYPES}; then
          continue
        fi

        if ! is_in_array "${TMP_HT}" ${LUKS_MODES}; then
          # Exclude TrueCrypt and VeraCrypt testing modes
          if ! is_in_array "${TMP_HT}" ${TC_MODES}; then
            if ! is_in_array "${TMP_HT}" ${VC_MODES}; then
              if ! is_in_array "${TMP_HT}" ${CL_MODES}; then
                perl tools/test.pl single "${TMP_HT}" >> "${OUTD}/all.sh"
              fi
            fi
          fi
        fi
      done
    fi

  else

    OUTD=${PACKAGE_FOLDER}

  fi

  rm -rf "${OUTD}/logfull.txt" && touch "${OUTD}/logfull.txt"

  # populate array of hash types where we only should check if pass is in output (not both hash:pass)
  IFS=';' read -ra PASS_ONLY <<< "${HASHFILE_ONLY} ${NOCHECK_ENCODING}"
  IFS=';' read -ra TIMEOUT_ALGOS <<< "${SLOW_ALGOS}"

  IFS=';' read -ra KEEP_GUESSING_ALGOS <<< "${KEEP_GUESSING}"

  # for these particular algos we need to save the output to a temporary file
  IFS=';' read -ra FILE_BASED_ALGOS <<< "${HASHFILE_ONLY}"

  for hash_type in $HASH_TYPES; do

    if [ "${HT}" -ne 65535 ]; then
      # check if the loop variable "hash_type" is between HT_MIN and HT_MAX (both included)

      if   [ "${hash_type}" -lt "${HT_MIN}" ]; then
        continue
      elif [ "${hash_type}" -gt "${HT_MAX}" ]; then
        # we are done because hash_type is larger than range:
        break
      fi
    fi

    if [ "${hash_type}" -eq 20510 ]; then # special case for PKZIP Master Key
      if [ "${MODE}" -eq 1 ]; then # if "multi" was forced we need to skip it
        if [ "${HT_MIN}" -eq 20510 ]; then
          if [ "${HT_MAX}" -eq 20510 ]; then
            echo "ERROR: -m 20510 = PKZIP Master Key can only be run with a single hash"
          fi
        fi

        continue
      fi
    fi

    # skip deprecated hash-types
    if [ "${hash_type}" -eq 2500 ] || [ "${hash_type}" -eq 2501 ] || [ "${hash_type}" -eq 16800 ] || [ "${hash_type}" -eq 16801 ] ; then
      continue
    fi

    # test.pl produce wrong hashes with Apple
    # would be necessary to investigate to understand why
    if [ "${hash_type}" -eq 1800 ]; then
      if [[ "$OSTYPE" == "darwin"* ]]; then
        continue
      fi
    fi

    # Digest::BLAKE2 is broken on Apple Silicon
    if [ "${hash_type}" -eq 600 ]; then
      if [ "${IS_APPLE_SILICON}" -eq 1 ]; then
        continue
      fi
    fi

    # Digest::GOST is broken on Apple Silicon
    if [ "${hash_type}" -eq 6900 ]; then
      if [ "${IS_APPLE_SILICON}" -eq 1 ]; then
        continue
      fi
    fi

    # Crypt::GCrypt is broken on Apple
    if [ "${hash_type}" -eq 18600 ]; then
      if [[ "$OSTYPE" == "darwin"* ]]; then
        continue
      fi
    fi

    if [ -z "${PACKAGE_FOLDER}" ]; then
      # init test data
      init
    else
      echo "[ ${OUTD} ] > Run packaged test for hash type $hash_type."
    fi

    if [ "${PACKAGE}" -eq 0 ]; then

      # should we check only the pass?
      pass_only=0
      is_in_array "${hash_type}"  ${PASS_ONLY} && pass_only=1

      IS_SLOW=0
      is_in_array "${hash_type}" ${SLOW_ALGOS} && IS_SLOW=1

      # we use phpass as slow hash for testing the AMP kernel
      [ "${hash_type}" -eq 400 ] && IS_SLOW=0

      OPTS_OLD=${OPTS}
      VECTOR_OLD=${VECTOR}
      MODE_OLD=${MODE}

      if [ "${hash_type}" -eq 20510 ]; then # special case for PKZIP Master Key
        if [ "${MODE}" -eq 1 ]; then # if "multi" was forced we need to skip it
          continue
        fi

        MODE=0 # force single only
      fi

      for CUR_WIDTH in $VECTOR_WIDTHS; do

        if [ "${VECTOR_OLD}" = "all" ] || [ "${VECTOR_OLD}" = "default" ] || [ "${VECTOR_OLD}" = "${CUR_WIDTH}" ]; then

          if [ "${VECTOR_OLD}" = "default" ] && \
             [ "${CUR_WIDTH}" != "1" ] && \
             [ "${CUR_WIDTH}" != "4" ]; then

             continue
          fi

          VECTOR=${CUR_WIDTH}
          OPTS="${OPTS_OLD} --backend-vector-width ${VECTOR}"

          if [ ${IS_SLOW} -eq 1 ]; then

            # Look up if this is one of supported VeraCrypt modes
            if is_in_array "${hash_type}" ${VC_MODES}; then
              veracrypt_test 0 # aes
              veracrypt_test 1 # serpent
              veracrypt_test 2 # twofish
              veracrypt_test 3 # camellia
              veracrypt_test 4 # camellia (alternative cascade)
              veracrypt_test 5 # kuznyechik
              veracrypt_test 6 # kuznyechik (alternative cascade)
            elif is_in_array "${hash_type}" ${TC_MODES}; then
              # run truecrypt tests
              truecrypt_test "${hash_type}" 0
              truecrypt_test "${hash_type}" 1
              truecrypt_test "${hash_type}" 2
            elif is_in_array "${hash_type}" ${LUKS_MODES}; then
              # run luks tests
              if [ ${hash_type} -eq 14600 ]; then
                # for legacy mode
                luks_legacy_test "${hash_type}" ${ATTACK}
              else
                # for new modes
                luks_test "${hash_type}" ${ATTACK}
              fi
            else
              # run attack mode 0 (stdin)
              if [ ${ATTACK} -eq 65535 ] || [ ${ATTACK} -eq 0 ]; then attack_0; fi
            fi

          else

            if is_in_array "${hash_type}" ${CL_MODES}; then
              # run cryptoloop tests
              cryptoloop_test "${hash_type}" 128
              cryptoloop_test "${hash_type}" 192
              cryptoloop_test "${hash_type}" 256
            else
              # run attack mode 0 (stdin)
              if [ ${ATTACK} -eq 65535 ] || [ ${ATTACK} -eq 0 ]; then attack_0; fi

              # run attack mode 1 (combinator)
              if [ ${ATTACK} -eq 65535 ] || [ ${ATTACK} -eq 1 ]; then attack_1; fi

              # run attack mode 3 (bruteforce)
              if [ ${ATTACK} -eq 65535 ] || [ ${ATTACK} -eq 3 ]; then attack_3; fi

              # run attack mode 6 (dict+mask)
              if [ ${ATTACK} -eq 65535 ] || [ ${ATTACK} -eq 6 ]; then attack_6; fi

              # run attack mode 7 (mask+dict)
              if [ ${ATTACK} -eq 65535 ] || [ ${ATTACK} -eq 7 ]; then attack_7; fi
            fi

          fi
        fi
      done
      OPTS="${OPTS_OLD}"
      VECTOR="${VECTOR_OLD}"
      MODE=${MODE_OLD}
    fi
  done

else

  OUTD=${PACKAGE_FOLDER}

fi

# fix logfile
if [ "${PACKAGE}" -eq 0 ]; then
  cat -vet "${OUTD}/logfull.txt" | sed -e 's/\^M                                             \^M//g' | sed -e 's/\$$//g' > "${OUTD}/test_report.log"
fi

rm -rf "${OUTD}/logfull.txt"

if [ "${PACKAGE}" -eq 1 ]; then

  echo "[ ${OUTD} ] > Generate package ${OUTD}/${OUTD}.7z"

  cp "${BASH_SOURCE[0]}" "${OUTD}/test.sh"

  copy_luks_dir=0
  copy_tc_dir=0
  copy_vc_dir=0
  copy_cl_dir=0

  if [ "${HT}" -eq 65535 ]; then
    copy_luks_dir=1
    copy_tc_dir=1
    copy_vc_dir=1
    copy_cl_dir=1
  else
    for TMP_HT in $(seq "${HT_MIN}" "${HT_MAX}"); do
      if is_in_array "${TMP_HT}" "${LUKS_MODES}"; then
        copy_luks_dir=1
      elif is_in_array "${TMP_HT}" ${TC_MODES}; then
        copy_tc_dir=1
      elif is_in_array "${TMP_HT}" ${VC_MODES}; then
        copy_vc_dir=1
      elif is_in_array "${TMP_HT}" ${CL_MODES}; then
        copy_cl_dir=1
      fi
    done
  fi

  if [ "${copy_luks_dir}" -eq 1 ]; then
    mkdir "${OUTD}/luks_tests/"
    cp ${TDIR}/luks_tests/* "${OUTD}/luks_tests/"
  fi

  if [ "${copy_tc_dir}" -eq 1 ]; then
    mkdir "${OUTD}/tc_tests/"
    cp ${TDIR}/tc_tests/* "${OUTD}/tc_tests/"
  fi

  if [ "${copy_vc_dir}" -eq 1 ]; then
    mkdir "${OUTD}/vc_tests/"
    cp ${TDIR}/vc_tests/* "${OUTD}/vc_tests/"
  fi

  if [ "${copy_cl_dir}" -eq 1 ]; then
    mkdir "${OUTD}/cl_tests/"
    cp ${TDIR}/cl_tests/* "${OUTD}/cl_tests/"
  fi

  # if we package from a given folder, we need to check if e.g. the files needed for multi mode are there

  if [ -n "${PACKAGE_FOLDER}" ]; then

    MODE=2

    ls "${PACKAGE_FOLDER}"/*multi* &>/dev/null

    if [ "${?}" -ne 0 ]; then
      MODE=0
    fi

    HT=$(grep -o -- "-m  *[0-9]*" "${PACKAGE_FOLDER}/all.sh" | sort -u | sed 's/-m  //' 2> /dev/null)

    if [ -n "${HT}" ]; then
      HT_COUNT=$(echo "${HT}" | wc -l)

      if [ "${HT_COUNT}" -gt 1 ]; then
        HT=65535
      fi
    fi

    #ATTACK=65535 # more appropriate ?
  fi

  # for convenience: 'run package' is default action for packaged test.sh ( + add other defaults too )

  SED_IN_PLACE='-i'

  UNAME=$(uname -s)

  # of course macOS requires us to implement a special case (sed -i "" for the backup file)
  if [ "${UNAME}" = "Darwin" ] ; then
    SED_IN_PLACE='-i ""'
  fi

  HT_PACKAGED=${HT}

  if [ "${HT_MIN}" -ne "${HT_MAX}" ]; then
    HT_PACKAGED=${HT_MIN}-${HT_MAX}
  fi

  HASH_TYPES_PACKAGED=$(   echo "${HASH_TYPES}"    | tr '\n' ' ' | sed 's/ *$//')
  HASHFILE_ONLY_PACKAGED=$(echo "${HASHFILE_ONLY}" | tr '\n' ' ' | sed 's/ *$//')
  KEEP_GUESSING_PACKAGED=$(echo "${KEEP_GUESSING}" | tr '\n' ' ' | sed 's/ *$//')
  SLOW_ALGOS_PACKAGED=$(   echo "${SLOW_ALGOS}"    | tr '\n' ' ' | sed 's/ *$//')

  sed "${SED_IN_PLACE}" -e 's/^\(PACKAGE_FOLDER\)=""/\1="$( echo "${BASH_SOURCE[0]}" | sed \"s!test.sh\\$!!\" )"/' \
    -e "s/^\(HASH_TYPES\)=\$(.*/\1=\"${HASH_TYPES_PACKAGED}\"/" \
    -e "s/^\(HASHFILE_ONLY\)=\$(.*/\1=\"${HASHFILE_ONLY_PACKAGED}\"/" \
    -e "s/^\(KEEP_GUESSING\)=\$(.*/\1=\"${KEEP_GUESSING_PACKAGED}\"/" \
    -e "s/^\(SLOW_ALGOS\)=\$(.*/\1=\"${SLOW_ALGOS_PACKAGED}\"/" \
    -e "s/^\(HT\)=0/\1=${HT_PACKAGED}/" \
    -e "s/^\(MODE\)=0/\1=${MODE}/" \
    -e "s/^\(ATTACK\)=0/\1=${ATTACK}/" \
    "${OUTD}/test.sh"

  ${PACKAGE_CMD} "${OUTD}/${OUTD}.7z" "${OUTD}/" &>/dev/null
fi
