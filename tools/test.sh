#!/usr/bin/env bash

##
## Authors.....: Gabriele Gristina <matrix@hashcat.net>
##               Jens Steube <jens.steube@gmail.com>
##               magnum <john.magnum@hushmail.com>
##
## License.....: MIT
##

# missing hash types: 5200,6211,6221,6231,6241,6251,6261,6271,6281

HASH_TYPES="0 10 11 12 20 21 22 23 30 40 50 60 100 101 110 111 112 120 121 122 125 130 131 132 133 140 141 150 160 200 300 400 500 900 1000 1100 1400 1410 1420 1430 1440 1441 1450 1460 1500 1600 1700 1710 1711 1720 1722 1730 1731 1740 1750 1760 1800 2100 2400 2410 2500 2600 2611 2612 2711 2811 3000 3100 3200 3710 3711 3800 4300 4400 4500 4700 4800 4900 5000 5100 5300 5400 5500 5600 5700 5800 6000 6100 6300 6400 6500 6600 6700 6800 6900 7100 7200 7300 7400 7500 7600 7700 7800 7900 8000 8100 8200 8300 8400 8500 8600 8700 8900 9100 9200 9300 9400 9500 9600 9700 9800 9900 10000 10100 10200 10300 10400 10500 10600 10700 10800 10900 11000 11100 11200 11300 11400 11500 11600 11900 12000 12100 12200 12300 12400 12600 12800 12900 13000 13100 13200 13300 13400 13500 13600 13800"

#ATTACK_MODES="0 1 3 6 7"
ATTACK_MODES="0 1 3 7"

VECTOR_WIDTHS="1 2 4 8 16"

MATCH_PASS_ONLY="2500 5300 5400 6600 6800 8200"

HASHFILE_ONLY="2500"

NEVER_CRACK="11600"

SLOW_ALGOS="400 500 501 1600 1800 2100 2500 3200 5200 5800 6211 6221 6231 6241 6251 6261 6271 6281 6300 6400 6500 6600 6700 6800 7100 7200 7400 7900 8200 8800 8900 9000 9100 9200 9300 9400 9500 9600 10000 10300 10500 10700 10900 11300 11600 11900 12000 12100 12200 12300 12400 12500 12800 12900 13000 13200 13400 13600"

OPTS="--quiet --force --potfile-disable --runtime 200 --gpu-temp-disable --weak-hash-threshold=0"

OUTD="test_$(date +%s)"

PACKAGE_CMD="7z a"
PACKAGE_FOLDER=""

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

contains ()
{
  for element in "${@:2}"; do

    if [ "${element}" == "${1}" ]; then
      return 1
    fi

  done

  return 0
}

function init()
{
  if [ "${PACKAGE}" -eq 1 ]; then

    echo "[ ${OUTD} ] > Generate tests for hash type $hash_type."

  else

    echo "[ ${OUTD} ] > Init test for hash type $hash_type."

  fi

  rm -rf ${OUTD}/${hash_type}.sh ${OUTD}/${hash_type}_passwords.txt ${OUTD}/${hash_type}_hashes.txt

  # create list of password and hashes of same type
  grep " ${hash_type} '" ${OUTD}/all.sh > ${OUTD}/${hash_type}.sh

  # create separate list of password and hashes
  cat ${OUTD}/${hash_type}.sh | awk '{print $3}' > ${OUTD}/${hash_type}_passwords.txt
  cat ${OUTD}/${hash_type}.sh | awk '{print $11}' | cut -d"'" -f2 > ${OUTD}/${hash_type}_hashes.txt

  if [ "${hash_type}" -eq 10300 ]; then
    cat ${OUTD}/${hash_type}.sh | cut -d' ' -f11- | cut -d"'" -f2 > ${OUTD}/${hash_type}_hashes.txt
  fi

  # truncate dicts
  rm -rf ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2
  touch ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2

  # foreach password entry split password in 2 (skip first entry, is len 1)
  i=1

  # minimum password length

  min_len=0

  if [ "${hash_type}" -eq 2500 ]; then

    min_len=7 # means length 8, since we start with 0

  fi

  while read -u 9 pass; do

    if [ ${i} -gt 1 ]; then

      # split password, 'i' is the len
      p0=$((i / 2))
      p1=$((p0 + 1))

      # special case (passwords longer than expected)
      pass_len=${#pass}

      if [ "${pass_len}" -gt 1 ]
      then

        p1=$((p1 + ${min_len}))
        p0=$((p0 + ${min_len}))

        if [ "${p1}" -gt ${pass_len} ]; then

          p1=${pass_len}
          p0=$((p1 - 1))

        fi

        # add splitted password to dicts

        echo ${pass} | cut -c -${p0} >> ${OUTD}/${hash_type}_dict1
        echo ${pass} | cut -c ${p1}- >> ${OUTD}/${hash_type}_dict2

     fi
    fi

    ((i++))

  done 9< ${OUTD}/${hash_type}_passwords.txt

  min_len=0

  if [ "${hash_type}" -eq 2500 ]; then

    min_len=7 # means length 8, since we start with 0

  fi

  # generate multiple pass/hash foreach len (2 to 8)
  if [ ${MODE} -ge 1 ]; then

    for ((i = 2; i < 9; i++)); do

      rm -rf ${OUTD}/${hash_type}_multi_${i}.txt ${OUTD}/${hash_type}_passwords_multi_${i}.txt ${OUTD}/${hash_type}_hashes_multi_${i}.txt
      rm -rf ${OUTD}/${hash_type}_dict1_multi_${i} ${OUTD}/${hash_type}_dict2_multi_${i}
      touch ${OUTD}/${hash_type}_dict1_multi_${i} ${OUTD}/${hash_type}_dict2_multi_${i}

      perl tools/test.pl single ${hash_type} ${i} > ${OUTD}/${hash_type}_multi_${i}.txt

      cat ${OUTD}/${hash_type}_multi_${i}.txt | awk '{print $3}' > ${OUTD}/${hash_type}_passwords_multi_${i}.txt
      cat ${OUTD}/${hash_type}_multi_${i}.txt | awk '{print $11}' | cut -d"'" -f2 > ${OUTD}/${hash_type}_hashes_multi_${i}.txt

      if [ "${hash_type}" -eq 10300 ]; then
        cat ${OUTD}/${hash_type}_multi_${i}.txt | cut -d' ' -f11- | cut -d"'" -f2 > ${OUTD}/${hash_type}_hashes_multi_${i}.txt
      fi

      # split password, 'i' is the len
      p0=$((i / 2))
      p1=$((p0 + 1))

      p0=$((p0 + ${min_len}))
      p1=$((p1 + ${min_len}))

      while read -u 9 pass; do

        # add splitted password to dicts
        echo ${pass} | cut -c -${p0} >> ${OUTD}/${hash_type}_dict1_multi_${i}
        echo ${pass} | cut -c ${p1}- >> ${OUTD}/${hash_type}_dict2_multi_${i}

      done 9< ${OUTD}/${hash_type}_passwords_multi_${i}.txt

    done

  fi
}

function status()
{
  RET=$1

  ((cnt++))

  if [ ${RET} -ne 0 ]; then
    case ${RET} in
      1)
        if contains ${hash_type} ${NEVER_CRACK_ALGOS}; then

           echo "password not found, cmdline : ${CMD}" &>> ${OUTD}/logfull.txt
           ((e_nf++))

        fi

        ;;
      2)
        echo "timeout reached, cmdline : ${CMD}" &>> ${OUTD}/logfull.txt
        ((e_to++))

        ;;
      10)
        if [ "${pass_only}" -eq 1 ]; then
          echo "plains not found in output, cmdline : ${CMD}" &>> ${OUTD}/logfull.txt
        else
          echo "hash:plains not matched in output, cmdline : ${CMD}" &>> ${OUTD}/logfull.txt
        fi
        ((e_nm++))

        ;;
      *)
        echo "! unhandled return code ${RET}, cmdline : ${CMD}" &>> ${OUTD}/logfull.txt
        echo "! unhandled return code, see ${OUTD}/logfull.txt for details."
        ((e_nf++))
        ;;
    esac
  fi
}

function attack_0()
{
  file_only=0

  if ! contains ${hash_type} ${FILE_BASED_ALGOS}; then

    file_only=1

  fi

  # single hash
  if [ ${MODE} -ne 1 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 0, markov ${MARKOV}, single hash, device-type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt

    max=32

    if ! contains ${hash_type} ${TIMEOUT_ALGOS}; then

      max=12

    fi

    i=0

    while read -u 9 line; do

      if [ "${i}" -ge ${max} ]; then

        break

      fi

      hash="$(echo "$line" | cut -d\'  -f2)"
      pass="$(echo "$line" | cut -d' ' -f3)"

      if [ -z "${hash}" ]; then

        break

      fi

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
        echo ${hash} | base64 -d > ${temp_file}
        hash="${temp_file}"

      fi

      CMD="echo -n "${pass}" | ./${BIN} ${OPTS} -a 0 -m ${hash_type} '${hash}'"

      echo -n "[ len $((i + 1)) ] " &>> ${OUTD}/logfull.txt

      output=$(echo -n "${pass}" | ./${BIN} ${OPTS} -a 0 -m ${hash_type} "${hash}" 2>&1)

      ret=${?}

      echo "${output}" >> ${OUTD}/logfull.txt

      if [ "${ret}" -eq 0 ]; then

        if [ ${pass_only} -eq 1 ]; then
          search=":${pass}"
        else
          search="${hash}:${pass}"
        fi

        echo "${output}" | grep -F "${search}" &> /dev/null

        if [ "${?}" -ne 0 ]; then

            ret=10

        fi

      fi

      status ${ret}

      i=$((i + 1))

    done 9< ${OUTD}/${hash_type}.sh

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 0, Mode single, Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi

  # multihash
  if [ ${MODE} -ne 0 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 0, markov ${MARKOV}, multi hash, Device-Type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt

    hash_file=${OUTD}/${hash_type}_hashes.txt

    # if file_only -> decode all base64 "hashes" and put them in the temporary file

    if [ "${file_only}" -eq 1 ]; then

      temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
      rm -f ${temp_file}

      hash_file=${temp_file}

      while read base64_hash; do

        echo -n ${base64_hash} | base64 -d >> ${temp_file}

      done < ${OUTD}/${hash_type}_hashes.txt

    fi

    CMD="cat ${OUTD}/${hash_type}_passwords.txt | ./${BIN} ${OPTS} -a 0 -m ${hash_type} ${hash_file}"

    output=$(cat ${OUTD}/${hash_type}_passwords.txt | ./${BIN} ${OPTS} -a 0 -m ${hash_type} ${hash_file} 2>&1)

    ret=${?}

    echo "${output}" >> ${OUTD}/logfull.txt

    if [ "${ret}" -eq 0 ]; then

      i=1

      while read -u 9 hash; do

        pass=$(sed -n ${i}p ${OUTD}/${hash_type}_passwords.txt)

        if [ ${pass_only} -eq 1 ]; then
          search=":${pass}"
        else
          search="${hash}:${pass}"
        fi

        echo "${output}" | grep -F "${search}" &> /dev/null

        if [ "${?}" -ne 0 ]; then

          ret=10

          break

        fi

        i=$((i + 1))

      done 9< ${OUTD}/${hash_type}_hashes.txt

    fi

    status ${ret}

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 0, Mode multi,  Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi
}

function attack_1()
{
  file_only=0

  if ! contains ${hash_type} ${FILE_BASED_ALGOS}; then

    file_only=1

  fi

  # single hash
  if [ ${MODE} -ne 1 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 1, markov ${MARKOV}, single hash, Device-Type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt
    i=1
    while read -u 9 hash; do

      if [ $i -gt 1 ]; then

        if [ "${file_only}" -eq 1 ]; then

          temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
          echo ${hash} | base64 -d > ${temp_file}
          hash="${temp_file}"

        fi

        CMD="./${BIN} ${OPTS} -a 1 -m ${hash_type} '${hash}' ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2"

        echo -n "[ len $i ] " &>> ${OUTD}/logfull.txt

        output=$(./${BIN} ${OPTS} -a 1 -m ${hash_type} "${hash}" ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2 2>&1)

        ret=${?}

        echo "${output}" >> ${OUTD}/logfull.txt

        if [ "${ret}" -eq 0 ]; then

          line_nr=$((i - 1))

          line_dict1=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict1)
          line_dict2=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict2)

          if [ ${pass_only} -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &> /dev/null

          if [ "${?}" -ne 0 ]; then

            ret=10

          fi

        fi

        status ${ret}

      fi

      ((i++))

    done 9< ${OUTD}/${hash_type}_hashes.txt

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 1, Mode single, Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi

  # multihash
  if [ ${MODE} -ne 0 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    offset=14

    if   [ ${hash_type} -eq 2500 ]; then
      offset=7
    elif [ ${hash_type} -eq 5800 ]; then
      offset=6
    elif [ ${hash_type} -eq 3000 ]; then
      offset=6
    elif [ ${hash_type} -eq 2100 ]; then
      offset=11
    elif [ ${hash_type} -eq 1500 ]; then
      offset=7
    elif [ ${hash_type} -eq 7700 ]; then
      offset=7
    elif [ ${hash_type} -eq 8500 ]; then
      offset=7
    fi

    hash_file=${OUTD}/${hash_type}_multihash_combi.txt

    tail -n ${offset} ${OUTD}/${hash_type}_hashes.txt > ${hash_file}

    # if file_only -> decode all base64 "hashes" and put them in the temporary file

    if [ "${file_only}" -eq 1 ]; then

      temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
      rm -f ${temp_file}

      hash_file=${temp_file}

      while read base64_hash; do

        echo -n ${base64_hash} | base64 -d >> ${temp_file}

      done < ${OUTD}/${hash_type}_multihash_combi.txt

    fi

    CMD="./${BIN} ${OPTS} -a 1 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2"

    echo "> Testing hash type $hash_type with attack mode 1, markov ${MARKOV}, multi hash, Device-Type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt

    output=$(./${BIN} ${OPTS} -a 1 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1 ${OUTD}/${hash_type}_dict2 2>&1)

    ret=${?}

    echo "${output}" >> ${OUTD}/logfull.txt

    if [ "${ret}" -eq 0 ]; then

      i=0

      while read -u 9 hash; do

        line_nr=$((offset - i))

        line_dict1=$(tail -n ${line_nr} ${OUTD}/${hash_type}_dict1 | head -1)
        line_dict2=$(tail -n ${line_nr} ${OUTD}/${hash_type}_dict2 | head -1)

        if [ ${pass_only} -eq 1 ]; then
          search=":${line_dict1}${line_dict2}"
        else
          search="${hash}:${line_dict1}${line_dict2}"
        fi

        echo "${output}" | grep -F "${search}" &> /dev/null

        if [ "${?}" -ne 0 ]; then

          ret=10

          break

        fi

        i=$((i + 1))

      done 9< ${OUTD}/${hash_type}_multihash_combi.txt

    fi

    status ${ret}

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 1, Mode multi,  Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi
}

function attack_3()
{
  file_only=0

  if ! contains ${hash_type} ${FILE_BASED_ALGOS}; then

    file_only=1

  fi

  # single hash
  if [ ${MODE} -ne 1 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 3, markov ${MARKOV}, single hash, Device-Type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt

    max=8
    mask_offset=0

    # some algos have a minimum password length

    if [ "${hash_type}" -eq 2500 ];then

      mask_offset=7
      max=7

    fi

    i=1

    while read -u 9 hash; do

      if [ "${i}" -gt 6 ]; then

        if ! contains ${hash_type} ${TIMEOUT_ALGOS}; then

          break;

        fi

      fi

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
        echo ${hash} | base64 -d > ${temp_file}
        hash="${temp_file}"

      fi

      mask=${mask_3[$((i + ${mask_offset}))]}

      # modify "default" mask if needed (and set custom charset to reduce keyspace)

      if [ "${hash_type}" -eq 2500 ]; then

        pass=$(sed -n ${i}p ${OUTD}/${hash_type}_passwords.txt)

        mask=${pass}

        # replace the first x positions in the mask with ?d's

        # first: remove first i (== amount) chars

        mask=$(echo ${mask} | cut -b $((i + 1))-)

        # prepend the ?d's

        for i in $(seq 1 ${i}); do

          mask="?d${mask}"

        done

      fi

      CMD="./${BIN} ${OPTS} -a 3 -m ${hash_type} '${hash}' ${mask}"

      echo -n "[ len $i ] " &>> ${OUTD}/logfull.txt

      output=$(./${BIN} ${OPTS} -a 3 -m ${hash_type} "${hash}" ${mask} 2>&1)

      ret=${?}

      echo "${output}" >> ${OUTD}/logfull.txt

      if [ "${ret}" -eq 0 ]; then

        line_dict=$(sed -n ${i}p ${OUTD}/${hash_type}_passwords.txt)

        if [ ${pass_only} -eq 1 ]; then
          search=":${line_dict}"
        else
          search="${hash}:${line_dict}"
        fi

        echo "${output}" | grep -F "${search}" &> /dev/null

        if [ "${?}" -ne 0 ]; then

          ret=10

        fi

      fi

      status ${ret}

      if [ $i -eq ${max} ]; then break; fi

      ((i++))

    done 9< ${OUTD}/${hash_type}_hashes.txt

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 3, Mode single, Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi

  # multihash
  if [ ${MODE} -ne 0 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    increment_max=8

    if ! contains ${hash_type} ${TIMEOUT_ALGOS}; then

      increment_max=5

    fi

    increment_min=1

    if [ "${hash_type}" -eq 2500 ]; then

      increment_min=8
      increment_max=9

    fi

    hash_file=${OUTD}/${hash_type}_multihash_bruteforce.txt

    head -n $((increment_max - ${increment_min} + 1)) ${OUTD}/${hash_type}_hashes.txt > ${hash_file}

    # if file_only -> decode all base64 "hashes" and put them in the temporary file

    if [ "${file_only}" -eq 1 ]; then

      temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
      rm -f ${temp_file}

      hash_file=${temp_file}

      while read base64_hash; do

        echo -n ${base64_hash} | base64 -d >> ${temp_file}

      done < ${OUTD}/${hash_type}_multihash_bruteforce.txt

    fi

    mask=${mask_3[8]}
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

      while read -u 9 hash; do

        pass=$(sed -n ${i}p ${OUTD}/${hash_type}_passwords.txt)

        # charset 1
        char=$(echo "${pass}" | cut -b ${charset_1_pos})
        charset_1=$(echo -e "${charset_1}\n${char}")

        # charset 2
        char=$(echo "${pass}" | cut -b ${charset_2_pos})
        charset_2=$(echo -e "${charset_2}\n${char}")

        # charset 3
        char=$(echo "${pass}" | cut -b ${charset_3_pos})
        charset_3=$(echo -e "${charset_3}\n${char}")

        # charset 4
        char=$(echo "${pass}" | cut -b ${charset_4_pos})
        charset_4=$(echo -e "${charset_4}\n${char}")

        i=$((i + 1))

      done 9< ${OUTD}/${hash_type}_multihash_bruteforce.txt

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

    CMD="./${BIN} ${OPTS} -a 3 -m ${hash_type} --increment --increment-min ${increment_min} --increment-max ${increment_max} ${custom_charsets} ${hash_file} ${mask} "

    echo "> Testing hash type $hash_type with attack mode 3, markov ${MARKOV}, multi hash, Device-Type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt

    output=$(./${BIN} ${OPTS} -a 3 -m ${hash_type} --increment --increment-min ${increment_min} --increment-max ${increment_max} ${custom_charsets} ${hash_file} ${mask} 2>&1)

    ret=${?}

    echo "${output}" >> ${OUTD}/logfull.txt

    if [ "${ret}" -eq 0 ]; then

      i=1

      while read -u 9 hash; do

        pass=$(sed -n ${i}p ${OUTD}/${hash_type}_passwords.txt)

        if [ ${pass_only} -eq 1 ]; then
          search=":${pass}"
        else
          search="${hash}:${pass}"
        fi

        echo "${output}" | grep -F "${search}" &> /dev/null

        if [ "${?}" -ne 0 ]; then

          ret=10

          break

        fi

        i=$((i + 1))

      done 9< ${OUTD}/${hash_type}_multihash_bruteforce.txt

    fi

    status ${ret}

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 3, Mode multi,  Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi
}

function attack_6()
{
  file_only=0

  if ! contains ${hash_type} ${FILE_BASED_ALGOS}; then

    file_only=1

  fi

  # single hash
  if [ ${MODE} -ne 1 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 6, markov ${MARKOV}, single hash, Device-Type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt

    i=1

    max=8

    if [ "${hash_type}" -eq 2500 ]; then

      max=6

    fi

    while read -u 9 hash; do

      if [ "${i}" -gt 6 ]; then

        if ! contains ${hash_type} ${TIMEOUT_ALGOS}; then

          break;

        fi

      fi

      if [ $i -gt 1 ]; then

        if [ "${file_only}" -eq 1 ]; then

          temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
          echo ${hash} | base64 -d > ${temp_file}
          hash="${temp_file}"

        fi

        CMD="./${BIN} ${OPTS} -a 6 -m ${hash_type} '${hash}' ${OUTD}/${hash_type}_dict1 ${mask_6[$i]}"

        echo -n "[ len $i ] " &>> ${OUTD}/logfull.txt

        output=$(./${BIN} ${OPTS} -a 6 -m ${hash_type} "${hash}" ${OUTD}/${hash_type}_dict1 ${mask_6[$i]} 2>&1)

        ret=${?}

        echo "${output}" >> ${OUTD}/logfull.txt

        if [ "${ret}" -eq 0 ]; then

          line_nr=$((i - 1))

          line_dict1=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict1)
          line_dict2=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict2)

          if [ ${pass_only} -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &> /dev/null

          if [ "${?}" -ne 0 ]; then

            ret=10

          fi

        fi

        status ${ret}

      fi

      if [ "${i}" -eq ${max} ]; then break; fi

      ((i++))

    done 9< ${OUTD}/${hash_type}_hashes.txt

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 6, Mode single, Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi

  # multihash
  if [ ${MODE} -ne 0 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    max=9

    if   [ ${hash_type} -eq 2500 ]; then
      max=5
    elif [ ${hash_type} -eq 3000 ]; then
      max=8
    elif [ ${hash_type} -eq 7700 ]; then
      max=8
    elif [ ${hash_type} -eq 8500 ]; then
      max=8
    fi

    if ! contains ${hash_type} ${TIMEOUT_ALGOS}; then

      max=5

      if [ "${hash_type}" -eq 3200 ]; then

        max=3

      fi

    fi

    for ((i = 2; i < ${max}; i++)); do

      hash_file=${OUTD}/${hash_type}_hashes_multi_${i}.txt

      # if file_only -> decode all base64 "hashes" and put them in the temporary file

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
        rm -f ${temp_file}

        hash_file=${temp_file}

        while read base64_hash; do

          echo -n ${base64_hash} | base64 -d >> ${temp_file}

        done < ${OUTD}/${hash_type}_hashes_multi_${i}.txt

      fi

      CMD="./${BIN} ${OPTS} -a 6 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1_multi_${i} ${mask_6[$i]}"

      echo "> Testing hash type $hash_type with attack mode 6, markov ${MARKOV}, multi hash with word len ${i}." &>> ${OUTD}/logfull.txt

      output=$(./${BIN} ${OPTS} -a 6 -m ${hash_type} ${hash_file} ${OUTD}/${hash_type}_dict1_multi_${i} ${mask_6[$i]} 2>&1)

      ret=${?}

      echo "${output}" >> ${OUTD}/logfull.txt

      if [ "${ret}" -eq 0 ]; then

        j=1

        while read -u 9 hash; do

          line_dict1=$(sed -n ${j}p ${OUTD}/${hash_type}_dict1_multi_${i})
          line_dict2=$(sed -n ${j}p ${OUTD}/${hash_type}_dict2_multi_${i})

          if [ ${pass_only} -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &> /dev/null

          if [ "${?}" -ne 0 ]; then

            ret=10

            break

          fi

          j=$((j + 1))

        done 9< ${OUTD}/${hash_type}_hashes_multi_${i}.txt

      fi

      status ${ret}

    done

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 6, Mode multi,  Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi
}

function attack_7()
{
  file_only=0

  if ! contains ${hash_type} ${FILE_BASED_ALGOS}; then

    file_only=1

  fi

  # single hash
  if [ ${MODE} -ne 1 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    echo "> Testing hash type $hash_type with attack mode 7, markov ${MARKOV}, single hash, Device-Type ${TYPE}, vector-width ${VECTOR}." &>> ${OUTD}/logfull.txt

    max=8

    if [ "${hash_type}" -eq 2500 ]; then

      max=5

    fi

    i=1

    while read -u 9 hash; do

      if [ $i -gt 1 ]; then

        if [ "${file_only}" -eq 1 ]; then

          temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
          echo ${hash} | base64 -d > ${temp_file}
          hash="${temp_file}"

        fi

        mask=${mask_7[$i]}

        # adjust mask if needed

        if [ "${hash_type}" -eq 2500 ]; then

          line_nr=$((i - 1))

          pass_part_1=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict1)
          pass_part_2=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict2)

          pass_part_2_len=${#pass_part_2}

          pass=${pass_part_1}${pass_part_2}
          pass_len=${#pass}

          # add first x chars of password to mask and append the (old) mask

          mask_len=${#mask}
          mask_len=$((mask_len / 2))

          mask_prefix=$(echo ${pass} | cut -b -$((pass_len - ${mask_len} - ${pass_part_2_len})))
          mask=${mask_prefix}${mask}

        fi

        CMD="./${BIN} ${OPTS} -a 7 -m ${hash_type} '${hash}' ${mask} ${OUTD}/${hash_type}_dict2"

        echo -n "[ len $i ] " &>> ${OUTD}/logfull.txt

        output=$(./${BIN} ${OPTS} -a 7 -m ${hash_type} "${hash}" ${mask} ${OUTD}/${hash_type}_dict2 2>&1)

        ret=${?}

        echo "${output}" >> ${OUTD}/logfull.txt

        if [ "${ret}" -eq 0 ]; then

          line_nr=$((i - 1))

          line_dict1=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict1)
          line_dict2=$(sed -n ${line_nr}p ${OUTD}/${hash_type}_dict2)

          if [ ${pass_only} -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &> /dev/null

          if [ "${?}" -ne 0 ]; then

            ret=10

          fi

        fi

        status ${ret}

      fi

      if [ $i -eq ${max} ]; then break; fi

      ((i++))

    done 9< ${OUTD}/${hash_type}_hashes.txt

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 7, Mode single, Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi

  # multihash
  if [ ${MODE} -ne 0 ]; then

    e_to=0
    e_nf=0
    e_nm=0
    cnt=0

    max=9

    if   [ ${hash_type} -eq 2500 ]; then
      max=5
    elif [ ${hash_type} -eq 3000 ]; then
      max=8
    elif [ ${hash_type} -eq 7700 ]; then
      max=8
    elif [ ${hash_type} -eq 8500 ]; then
      max=8
    fi

    if ! contains ${hash_type} ${TIMEOUT_ALGOS}; then

      max=7

      if [ "${hash_type}" -eq 3200 ]; then

        max=4

      fi

    fi

    for ((i = 2; i < ${max}; i++)); do

      hash_file=${OUTD}/${hash_type}_hashes_multi_${i}.txt
      dict_file=${OUTD}/${hash_type}_dict2_multi_${i}

      mask=${mask_7[$i]}

      # if file_only -> decode all base64 "hashes" and put them in the temporary file

      if [ "${file_only}" -eq 1 ]; then

        temp_file="${OUTD}/${hash_type}_filebased_only_temp.txt"
        rm -f ${temp_file}

        hash_file=${temp_file}

        while read base64_hash; do

          echo -n ${base64_hash} | base64 -d >> ${temp_file}

        done < ${OUTD}/${hash_type}_hashes_multi_${i}.txt

        # a little hack: since we don't want to have a very large mask (and wpa has minimum length of 8),
        # we need to create a temporary dict file on-the-fly and use it like this: [small mask] [long(er) words in dict]

        dict_file=${OUTD}/${hash_type}_dict2_multi_${i}_longer
        rm -f ${dict_file}

        mask_len=${#mask}
        mask_len=$((mask_len / 2))

        j=1

        while read -u 9 hash; do

          pass_part_1=$(sed -n ${j}p ${OUTD}/${hash_type}_dict1_multi_${i})
          pass_part_2=$(sed -n ${j}p ${OUTD}/${hash_type}_dict2_multi_${i})

          pass="${pass_part_1}${pass_part_2}"

          pass_suffix=$(echo "${pass}" | cut -b $((mask_len + 1))-)

          echo "${pass_suffix}" >> ${dict_file}

          j=$((j + 1))

        done 9< ${OUTD}/${hash_type}_hashes_multi_${i}.txt

      fi

      CMD="./${BIN} ${OPTS} -a 7 -m ${hash_type} ${hash_file} ${mask} ${dict_file}"

      echo "> Testing hash type $hash_type with attack mode 7, markov ${MARKOV}, multi hash with word len ${i}." &>> ${OUTD}/logfull.txt

      output=$(./${BIN} ${OPTS} -a 7 -m ${hash_type} ${hash_file} ${mask} ${dict_file} 2>&1)

      ret=${?}

      echo "${output}" >> ${OUTD}/logfull.txt

      if [ "${ret}" -eq 0 ]; then

        j=1

        while read -u 9 hash; do

          line_dict1=$(sed -n ${j}p ${OUTD}/${hash_type}_dict1_multi_${i})
          line_dict2=$(sed -n ${j}p ${OUTD}/${hash_type}_dict2_multi_${i})

          if [ ${pass_only} -eq 1 ]; then
            search=":${line_dict1}${line_dict2}"
          else
            search="${hash}:${line_dict1}${line_dict2}"
          fi

          echo "${output}" | grep -F "${search}" &> /dev/null

          if [ "${?}" -ne 0 ]; then

            ret=10

            break

          fi

          j=$((j + 1))

        done 9< ${OUTD}/${hash_type}_hashes_multi_${i}.txt

      fi

      status ${ret}

    done

    msg="OK"

    if [ "${e_nf}" -ne 0 -o "${e_nm}" -ne 0 ]; then

      msg="Error"

    elif [ "${e_to}" -ne 0 ]; then

      msg="Warning"

    fi

    echo "[ ${OUTD} ] [ Type ${hash_type}, Attack 7, Mode multi,  Device-Type ${TYPE}, Vector-Width ${VECTOR} ] > $msg : ${e_nf}/${cnt} not found, ${e_nm}/${cnt} not matched, ${e_to}/${cnt} timeout"

  fi
}

function usage()
{
cat << EOF
> Usage : ${0} <options>

OPTIONS:

  -V    OpenCL vector-width (either 1, 2, 4 or 8), overrides value from device query :
        '1'      => vector-width 1
        '2'      => vector-width 2 (default)
        '4'      => vector-width 4
        '8'      => vector-width 8
        'all'    => test sequentially vector-width ${VECTOR_WIDTHS}

  -T    OpenCL device-types to use :
        'gpu'    => gpu devices (default)
        'cpu'    => cpu devices
        'all'    => gpu and cpu devices

  -t    Select test mode :
        'single' => single hash (default)
        'multi'  => multi hash
        'all'    => single and multi hash

  -m    Select hash type :
        'all'    => all hash type supported
        (int)    => hash type integer code (default : 0)

  -a    Select attack mode :
        'all'    => all attack modes
        (int)    => attack mode integer code (default : 0)

  -x    Select cpu architecture :
        '32'     => 32 bit architecture
        '64'     => 64 bit architecture (default)

  -o    Select operating system :
        'win'    => windows operating system (use .exe file extension etc)
        'linux'  => *nix based operating systems (.bin for binaries)
        'osx'    => mac osx operating systems (.app for binaries)

  -c    Disables markov-chains

  -p    Package the tests into a .7z file

  -d    Use this folder as input/output folder for packaged tests
        (string) => path to folder

  -h    Show this help

EOF

  exit 1
}

BIN="hashcat"
MARKOV="enabled"
ATTACK=0
MODE=0
TYPE="null"
VECTOR="default"
HT=0
PACKAGE=0

while getopts "V:T:t:m:a:b:hcpd:x:o:" opt; do

  case ${opt} in
    "V")
      if [ ${OPTARG} == "1" ]; then
        VECTOR=1
      elif [ ${OPTARG} == "2" ]; then
        VECTOR=2
      elif [ ${OPTARG} == "4" ]; then
        VECTOR=4
      elif [ ${OPTARG} == "8" ]; then
        VECTOR=8
      elif [ ${OPTARG} == "16" ]; then
        VECTOR=16
      elif [ ${OPTARG} == "all" ]; then
        VECTOR="all"
      else
        usage
      fi
      ;;

    "T")
      if [ ${OPTARG} == "gpu" ]; then
        OPTS="${OPTS} --opencl-device-types 2"
        TYPE="Gpu"
      elif [ ${OPTARG} == "cpu" ]; then
        OPTS="${OPTS} --opencl-device-types 1"
        TYPE="Cpu"
      elif [ ${OPTARG} == "all" ]; then
        OPTS="${OPTS} --opencl-device-types 1,2"
        TYPE="Cpu + Gpu"
      else
        usage
      fi
      ;;

    "t")
      if [ ${OPTARG} == "single" ]; then
        MODE=0
      elif [ ${OPTARG} == "multi" ]; then
        MODE=1
      elif [ ${OPTARG} == "all" ]; then
        MODE=2
      else
        usage
      fi
      ;;

    "m")
      if [ ${OPTARG} == "all" ]; then
        HT=65535
      else
        HT=${OPTARG}
      fi
      ;;

    "a")
      if [ ${OPTARG} == "all" ]; then
        ATTACK=65535
      elif [ ${OPTARG} == "0" ]; then
        ATTACK=0
      elif [ ${OPTARG} == "1" ]; then
        ATTACK=1
      elif [ ${OPTARG} == "3" ]; then
        ATTACK=3
      elif [ ${OPTARG} == "6" ]; then
        ATTACK=6
      elif [ ${OPTARG} == "7" ]; then
        ATTACK=7
      else
        usage
      fi
      ;;

    "c")
      OPTS="${OPTS} --markov-disable"
      MARKOV="disabled"
      ;;

    "d")
      PACKAGE_FOLDER=$( echo ${OPTARG} | sed 's!/$!!g' )
      ;;

    "p")
      PACKAGE=1
      ;;

    "x")
      if [ ${OPTARG} == "32" ]; then
        ARCHITECTURE=32
      elif [ ${OPTARG} == "64" ]; then
        ARCHITECTURE=64
      else
        usage
      fi
      ;;

    "o")
      if [ ${OPTARG} == "win" ]; then
        EXTENSION="exe"
      elif [ ${OPTARG} == "linux" ]; then
        EXTENSION="bin"
      elif [ ${OPTARG} == "osx" ]; then
        EXTENSION="app"
      else
        usage
      fi
      ;;

    \?)
      usage
      ;;

    "h")
      usage
      ;;
  esac

done

if [ "${TYPE}" == "null" ]; then
   TYPE="Gpu"
   OPTS="${OPTS} --opencl-device-types 2"
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

if [ "${PACKAGE}" -eq 0 -o -z "${PACKAGE_FOLDER}" ]; then

  # check existence of binary
  if [ ! -e "${BIN}" ]; then
    echo "! ${BIN} not found, please build binary before run test."
    exit 1
  fi

  # filter by hash_type
  if [ ${HT} -ne 65535 ]; then

    # validate filter
    check=0
    for hash_type in $(echo ${HASH_TYPES}); do

      if [ ${HT} -ne ${hash_type} ]; then continue; fi

      check=1

      break

    done

    if [ ${check} -ne 1 ]; then
      echo "! invalid hash type selected ..."
      usage
    fi

  fi

  if [ -z "${PACKAGE_FOLDER}" ]; then

    # make new dir
    mkdir -p ${OUTD}

    # generate random test entry
    if [ ${HT} -eq 65535 ]; then
      perl tools/test.pl single > ${OUTD}/all.sh
    else
      perl tools/test.pl single ${HT} > ${OUTD}/all.sh
    fi

  else

    OUTD=${PACKAGE_FOLDER}

  fi

  rm -rf ${OUTD}/logfull.txt && touch ${OUTD}/logfull.txt

  # populate array of hash types where we only should check if pass is in output (not both hash:pass)
  IFS=';' read -ra PASS_ONLY <<< "${MATCH_PASS_ONLY}"
  IFS=';' read -ra TIMEOUT_ALGOS <<< "${SLOW_ALGOS}"

  IFS=';' read -ra NEVER_CRACK_ALGOS <<< "${NEVER_CRACK}"

  # for these particular algos we need to save the output to a temporary file
  IFS=';' read -ra FILE_BASED_ALGOS <<< "${HASHFILE_ONLY}"

  for hash_type in $(echo $HASH_TYPES); do

    if [[ ${HT} -ne 65535 ]] && [[ ${HT} -ne ${hash_type} ]]; then continue; fi

    if [ -z "${PACKAGE_FOLDER}" ]; then

      # init test data
      init

    else

      echo "[ ${OUTD} ] > Run packaged test for hash type $hash_type."

    fi

    if [ "${PACKAGE}" -eq 0 ]; then

      # should we check only the pass?
      contains ${hash_type} ${PASS_ONLY}
      pass_only=$?

      contains ${hash_type} ${SLOW_ALGOS}
      IS_SLOW=$?

      if [[ ${hash_type} -eq 400 ]]; then
         # we use phpass as slow hash for testing the AMP kernel
         IS_SLOW=0
      fi

      OPTS_OLD=${OPTS}
      VECTOR_OLD=${VECTOR}
      for CUR_WIDTH in $(echo $VECTOR_WIDTHS); do

        if [ "${VECTOR_OLD}" == "all" ] || [ "${VECTOR_OLD}" == "default" ] || [ "${VECTOR_OLD}" == "${CUR_WIDTH}" ]; then

          if [ "${VECTOR_OLD}" == "default" ] && \
             [ "${CUR_WIDTH}" != "1" ] && \
             [ "${CUR_WIDTH}" != "4" ]; then

             continue
          fi

          VECTOR=${CUR_WIDTH}
          OPTS="${OPTS_OLD} --opencl-vector-width ${VECTOR}"

          if [[ ${IS_SLOW} -eq 1 ]]; then

            # run attack mode 0 (stdin)
            if [[ ${ATTACK} -eq 65535 ]] || [[ ${ATTACK} -eq 0 ]]; then attack_0; fi

          else

            # run attack mode 0 (stdin)
            if [[ ${ATTACK} -eq 65535 ]] || [[ ${ATTACK} -eq 0 ]]; then attack_0; fi

            # run attack mode 1 (combinator)
            if [[ ${ATTACK} -eq 65535 ]] || [[ ${ATTACK} -eq 1 ]]; then attack_1; fi

            # run attack mode 3 (bruteforce)
            if [[ ${ATTACK} -eq 65535 ]] || [[ ${ATTACK} -eq 3 ]]; then attack_3; fi

            # run attack mode 6 (dict+mask)
            if [[ ${ATTACK} -eq 65535 ]] || [[ ${ATTACK} -eq 6 ]]; then attack_6; fi

            # run attack mode 7 (mask+dict)
            if [[ ${ATTACK} -eq 65535 ]] || [[ ${ATTACK} -eq 7 ]]; then attack_7; fi

          fi
        fi
      done
      OPTS="${OPTS_OLD}"
      VECTOR="${VECTOR_OLD}"
    fi
  done

else

  OUTD=${PACKAGE_FOLDER}

fi

# fix logfile
if [ "${PACKAGE}" -eq 0 ]; then

  cat -A ${OUTD}/logfull.txt | sed -e 's/\^M                                             \^M//g' | sed -e 's/\$$//g' > ${OUTD}/test_report.log

fi

rm -rf ${OUTD}/logfull.txt

if [ "${PACKAGE}" -eq 1 ]; then

  echo "[ ${OUTD} ] > Generate package ${OUTD}/${OUTD}.7z"

  cp "${BASH_SOURCE[0]}" ${OUTD}/test.sh

  # if we package from a given folder, we need to check if e.g. the files needed for multi mode are there

  if [ -n "${PACKAGE_FOLDER}" ]; then

    MODE=2

    ls "${PACKAGE_FOLDER}"/*multi* &> /dev/null

    if [ "${?}" -ne 0 ]
    then

      MODE=0

    fi

    HT=$(grep -o -- "-m  *[0-9]*" ${PACKAGE_FOLDER}/all.sh | sort -u | sed 's/-m  //' 2> /dev/null)

    if [ -n "${HT}" ]; then

      HT_COUNT=$(echo "${HT}" | wc -l)

      if [ "${HT_COUNT}" -gt 1 ]; then

        HT=65535

      fi

    fi

    #ATTACK=65535 # more appropriate ?
  fi

  # for convenience: 'run package' is default action for packaged test.sh ( + add other defaults too )

  sed -i -e 's/^\(PACKAGE_FOLDER\)=""/\1="$( echo "${BASH_SOURCE[0]}" | sed \"s!test.sh\\$!!\" )"/' \
    -e "s/^\(HT\)=0/\1=${HT}/" \
    -e "s/^\(MODE\)=0/\1=${MODE}/" \
    -e "s/^\(ATTACK\)=0/\1=${ATTACK}/" \
    ${OUTD}/test.sh

  ${PACKAGE_CMD} ${OUTD}/${OUTD}.7z ${OUTD}/ &> /dev/null

fi
