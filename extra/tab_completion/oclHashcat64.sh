OCLHASHCAT_ROOT="."

# helper functions
_oclHashcat_get_permutations ()
{
  local num_devices=${1}
  oclHashcat_devices_permutation=""

  # Formula: Sum (k=1...num_devices) (num_devices! / (k! * (num_devices - k)!))
  # or ofc (2 ^ num_devices) - 1
  if [ "${num_devices}" -gt 0 ]; then

    oclHashcat_devices_permutation=$(seq 1 $num_devices)

    local k

    for k in $(seq 2 $num_devices); do

      if [ "${k}" -eq ${num_devices} ];then

        oclHashcat_devices_permutation="${oclHashcat_devices_permutation} $(seq 1 $num_devices | tr '\n' ',' | sed 's/, *$//')"

      else

        local j
        local max_pos=$((num_devices - ${k} + 1))

        for j in $(seq 1 ${max_pos}); do

          local max_value=$((j + ${k} - 1))

          # init
          local out_str=""

          local l
          for l in $(seq ${j} ${max_value}); do

            if [ ${l} -gt ${j} ]; then
              out_str=${out_str},
            fi

            out_str=${out_str}${l}

          done

          local chg_len=0
          local last=$((k - 1))
          local max_device=$((num_devices + 1))
          local pos_changed=0

          while [ "${chg_len}" -lt ${last} ]; do

            local had_pos_changed=${pos_changed}
            local old_chg_len=${chg_len}

            local idx=$(((k - chg_len)))
            local cur_num=$(echo ${out_str} | cut -d, -f ${idx})
            local next_num=$((cur_num + 1))

            if [ "${pos_changed}" -eq 0 ]; then

              oclHashcat_devices_permutation="${oclHashcat_devices_permutation} ${out_str}"

            else

              pos_changed=0

            fi

            if [ "${next_num}" -lt ${max_device} -a "${next_num}" -le "${num_devices}" ]; then

              out_str=$(echo ${out_str} | sed "s/,${cur_num},/,${next_num},/;s/,${cur_num}\$/,${next_num}/")
              
            else

              pos_changed=1
              max_device=${cur_num}
              chg_len=$((chg_len + 1))

            fi

            if [ "${had_pos_changed}" -eq 1 ];then

              local changed=0
              local m

              for m in $(seq 1 ${old_chg_len}); do

                local reset_idx=$((k - ${old_chg_len} + ${m}))
                local last_num=$(echo ${out_str} | cut -d, -f ${reset_idx})
                next_num=$((next_num + 1))

                if [ "${next_num}" -lt ${max_device} -a "${next_num}" -le "${num_devices}" ]; then

                  out_str=$(echo ${out_str} | sed "s/,${last_num},/,${next_num},/;s/,${last_num}\$/,${next_num}/")
                  max_device=$((next_num + 2))
                  changed=$((changed + 1))

                else
                  break
                fi

              done

              if [ "${changed}" -gt 0 ]; then

                max_device=$((num_devices + 1))
                chg_len=0

              fi

            fi

          done

        done

      fi

    done
  fi
}

_oclHashcat_gpu_devices ()
{
  local num_devices=0

  if which clinfo &> /dev/null; then

    num_devices=$(clinfo 2>/dev/null |  grep -c CL_DEVICE_TYPE_GPU 2> /dev/null)

  elif which nvidia-smi &> /dev/null; then

    num_devices=$(nvidia-smi --list-gpus | wc -l)

  fi

  return ${num_devices}
}

_oclHashcat_cpu_devices ()
{
  local num_devices=0

  if [ -f "/proc/cpuinfo" ]; then

    num_devices=$(cat /proc/cpuinfo | grep -c processor 2> /dev/null)

  fi

  return ${num_devices}
}

_oclHashcat_contains ()
{
  local haystack=${1}
  local needle="${2}" 

  if   echo "${haystack}" | grep -q " ${needle} " 2> /dev/null; then
    return 0
  elif echo "${haystack}" | grep -q "^${needle} " 2> /dev/null; then
    return 0
  elif echo "${haystack}" | grep -q " ${needle}\$" 2> /dev/null; then
    return 0
  fi

  return 1
}

_oclHashcat ()
{
  local VERSION=1.20

  local HASH_MODES="0 10 11 12 20 21 22 23 30 40 50 60 100 101 110 111 112 120 121 122 124 130 131 132 133 140 141 150 160 190 200 300 400 500 501 900 1000 1100 1400 1410 1420 1421 1430 1440 1441 1450 1460 1500 1600 1700 1710 1711 1720 1722 1730 1731 1740 1750 1760 1800 2100 2400 2410 2500 2600 2611 2612 2711 2811 3000 3100 3200 3710 3711 3800 4300 4400 4500 4700 4800 4900 5000 5100 5200 5300 5400 5500 5600 5700 5800 6000 6100 6211 6221 6231 6241 6300 6400 6500 6600 6700 6800 6900 7100 7200 7300 7400 7500 7600 7700 7800 7900 8000 8100 8200 8300 8400 8500 8600 8700 8900 9000 9100 9200 9300 9400 9500 9600 9700 9710 9720 9800 9810 9820 9900 10000 10100 10200 10300 10400 10410 10420 10500 10600 10700 10800 10900 11000 11100 11200 11300 11400 11500 11600 11700 11800 11900 12000 12100 12200 12300 12400 12500 12600"
  local ATTACK_MODES="0 1 3 6 7"
  local OUTFILE_FORMATS="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"
  local BENCHMARK_MODE="0 1"
  local DEBUG_MODE="1 2 3 4"
  local WORKLOAD_PROFILE="1 2 3"
  local GPU_ACCEL="1 8 16 24 32 40 48 56 64 62 80 88 96 104 112 120 128 136 144 152 160"
  local GPU_LOOPS="8 16 32 64 128 256 512 1024"
  local HIDDEN_FILES="exe|bin|pot|hcstat|dictstat|accepted|sh|cmd|bat|restore"
  local HIDDEN_FILES_AGGRESIVE="exe|bin|pot|hcstat|dictstat|hcmask|hcchr|accepted|sh|cmd|restore"
  local BUILD_IN_CHARSETS='?l ?u ?d ?a ?b ?s'

  local SHORT_OPTS="-m -a -V -v -h -b -t -o -p -c -d -w -n -u -j -k -r -g -1 -2 -3 -4 -i -s -l"
  local LONG_OPTS="--hash-type --attack-mode --version --help --eula --quiet --benchmark --benchmark-mode --hex-salt --hex-wordlist --hex-charset --force --status --status-timer --status-automat --loopback --weak-hash-threshold --markov-hcstat --markov-disable --markov-classic --markov-threshold --runtime --session --restore --restore-disable --outfile --outfile-format --outfile-autohex-disable --outfile-check-timer --outfile-check-dir --separator --show --left --username --remove --remove-timer --potfile-disable --debug-mode --debug-file --induction-dir --segment-size --bitmap-min --bitmap-max --cpu-affinity --gpu-async --gpu-devices --workload-profile --gpu-accel --gpu-loops --gpu-temp-disable --gpu-temp-abort --gpu-temp-retain --powertune-enable --skip --limit --keyspace --rule-left --rule-right --rules-file --generate-rules --generate-rules-func-min --generate-rules-func-max --generate-rules-seed --rules-cleanup --custom-charset1 --custom-charset2 --custom-charset3 --custom-charset4 --increment --increment-min --increment-max --logfile-disable --scrypt-tmto --truecrypt-keyfiles"
  local OPTIONS="-m -a -t -o -p -c -d -w -n -u -j -k -r -g -1 -2 -3 -4 -s -l --hash-type --attack-mode --benchmark-mode --status-timer --markov-hcstat --markov-threshold --runtime --session --timer --outfile --outfile-format --outfile-check-timer --outfile-check-dir --separator --remove-timer --debug-mode --debug-file --induction-dir --segment-size --bitmap-min --bitmap-max --cpu-affinity --gpu-devices --workload-profile --gpu-accel --gpu-loops --gpu-temp-abort --gpu-temp-retain -disable --skip --limit --rule-left --rule-right --rules-file --generate-rules --generate-rules-func-min --generate-rules-func-max --generate-rules-seed --custom-charset1 --custom-charset2 --custom-charset3 --custom-charset4 --increment-min --increment-max --scrypt-tmto --truecrypt-keyfiles"

  COMPREPLY=()
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local prev="${COMP_WORDS[COMP_CWORD-1]}"

  # if cur is just '=', ignore the '=' and treat it as only the prev was provided
  if [[ "${cur}" == '=' ]]; then

    cur=""

  elif [[ "${prev}" == '=' ]]; then

    if [ "${COMP_CWORD}" -gt 2 ]; then

      prev="${COMP_WORDS[COMP_CWORD-2]}"

    fi

  fi

  case "${prev}" in

    -m|--hash-type)
      COMPREPLY=($(compgen -W "${HASH_MODES}" -- ${cur}))
      return 0
      ;;

    -a|--attack-mode)
      COMPREPLY=($(compgen -W "${ATTACK_MODES}" -- ${cur}))
      return 0
      ;;

    --outfile-format)
      COMPREPLY=($(compgen -W "${OUTFILE_FORMATS}" -- ${cur}))
      return 0
      ;;

    --benchmark-mode)
      COMPREPLY=($(compgen -W "${BENCHMARK_MODE}" -- ${cur}))
      return 0
      ;;

    -w|--workload-profile)
      COMPREPLY=($(compgen -W "${WORKLOAD_PROFILE}" -- ${cur}))
      return 0
      ;;

    -n|--gpu-accel)
      COMPREPLY=($(compgen -W "${GPU_ACCEL}" -- ${cur}))
      return 0
      ;;

    -u|--gpu-loops)
      COMPREPLY=($(compgen -W "${GPU_LOOPS}" -- ${cur}))
      return 0
      ;;

    -o|--outfile|-r|--rules-file|--debug-file)
      local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
      COMPREPLY=($(compgen -W "${files}" -- ${cur})) # or $(compgen -f -X '*.+('${HIDDEN_FILES_AGGRESIVE}')' -- ${cur})
      return 0
      ;;

    --markov-hcstat)
      local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES}')' 2> /dev/null)
      COMPREPLY=($(compgen -W "${files}" -- ${cur})) # or $(compgen -f -X '*.+('${HIDDEN_FILES_AGGRESIVE}')' -- ${cur})
      return 0
      ;;

     -d|--gpu-devices)
      _oclHashcat_gpu_devices
      local num_devices=${?}

      _oclHashcat_get_permutations ${num_devices}

      COMPREPLY=($(compgen -W "${oclHashcat_devices_permutation}" -- ${cur}))
      return 0
      ;;

    --cpu-affinity)
      _oclHashcat_cpu_devices
      local num_devices=${?}

      _oclHashcat_get_permutations ${num_devices}

      COMPREPLY=($(compgen -W "${oclHashcat_devices_permutation}" -- ${cur}))
      return 0
      ;;

    -1|-2|-3|-4|--custom-charset1|--custom-charset2|--custom-charset3|--custom-charset4)
      local mask=${BUILD_IN_CHARSETS}

      if [ -e "${cur}" ]; then # should be hcchr file (but not enforced)

        COMPREPLY=($(compgen -W "${cur}" -- ${cur}))
        return 0

      fi

      if [ -n "${cur}" ]; then

        local cur_var=$(echo "${cur}" | sed 's/\?$//')

        mask="${mask} ${cur_var}"
        local h
        for h in ${mask}; do

          if ! echo ${cur} | grep -q ${h} 2> /dev/null; then

            if echo ${cur} | grep -q '?a' 2> /dev/null; then

              if   [[ "${h}" == "?l" ]] ; then
                continue
              elif [[ "${h}" == "?u" ]] ; then
                continue
              elif [[ "${h}" == "?d" ]] ; then
                continue
              elif [[ "${h}" == "?s" ]] ; then
                continue
              elif [[ "${h}" == "?b" ]] ; then
                continue
              fi

            fi

            mask="${mask} ${cur_var}${h}"

          fi

        done
      fi

      local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES}')' 2> /dev/null)

      mask="${mask} ${files}"

      COMPREPLY=($(compgen -W "${mask}" -- ${cur}))
      return 0
      ;;

    -t|-p|-c|-j|-k|-g| \
      --status-timer|--markov-threshold|--runtime|--session|--separator|--segment-size|--rule-left|--rule-right| \
      --gpu-temp-abort|--gpu-temp-retain|--generate-rules|--generate-rules-func-min|--generate-rules-func-max| \
      --increment-min|--increment-max|--remove-timer|--bitmap-min|--bitmap-max|--skip|--limit|--generate-rules-seed)
      return 0
      ;;

    --debug-mode)
      COMPREPLY=($(compgen -W "${DEBUG_MODE}" -- ${cur}))
      return 0
      ;;

    --truecrypt-keyfiles)
      # first: remove the quotes such that file matching is possible

      local cur_part0=$(echo "${cur}" | grep -Eo '^("|'"'"')')

      local cur_mod=$(echo "${cur}" | sed 's/^["'"'"']//')
      local cur_part1=$(echo "${cur_mod}" | grep ',' 2> /dev/null | sed 's/^\(.*, *\)[^,]*$/\1/')
      local cur_part2=$(echo "${cur_mod}" | sed 's/^.*, *\([^,]*\)$/\1/')

      # generate lines with the file name and a duplicate of it with a comma at the end

      local files=$(ls -d ${cur_part2}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null | sed 's/^\(.*\)$/\1\n\1,\n/' | sed "s/^/${cur_part0}${cur_part1}/" | sed "s/$/${cur_part0}/")
      COMPREPLY=($(compgen -W "${files}" -- ${cur}))
      return 0

  esac

  # allow also the VARIANTS w/o spaces
  # we could use compgen -P prefix, but for some reason it doesn't seem to work always

  case "$cur" in

    -m*)
      local hash_modes_var="$(echo -n "-m ${HASH_MODES}" | sed 's/ / -m/g')"
      COMPREPLY=($(compgen -W "${hash_modes_var}" -- ${cur}))
      return 0
      ;;

    -a*)
      local attack_modes_var="$(echo -n "-a ${ATTACK_MODES}" | sed 's/ / -a/g')"
      COMPREPLY=($(compgen -W "${attack_modes_var}" -- ${cur}))
      return 0
      ;;

    -w*)
      local workload_profile_var="$(echo -n "-w ${WORKLOAD_PROFILE}" | sed 's/ / -w/g')"
      COMPREPLY=($(compgen -W "${workload_profile_var}" -- ${cur}))
      return 0
      ;;

    -n*)
      local gpu_accel_var="$(echo -n "-n ${GPU_ACCEL}" | sed 's/ / -n/g')"
      COMPREPLY=($(compgen -W "${gpu_accel_var}" -- ${cur}))
      return 0
      ;;

    -u*)
      local gpu_loops_var="$(echo -n "-u ${GPU_LOOPS}" | sed 's/ / -u/g')"
      COMPREPLY=($(compgen -W "${gpu_loops_var}" -- ${cur}))
      return 0
      ;;

    -o*)
      local outfile_var=$(ls -d ${cur:2}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
      outfile_var="$(echo -e "\n${outfile_var}" | sed 's/^/-o/g')"
      COMPREPLY=($(compgen -W "${outfile_var}" -- ${cur}))
      return 0
      ;;

    -r*)
      local outfile_var=$(ls -d ${cur:2}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
      outfile_var="$(echo -e "\n${outfile_var}" | sed 's/^/-r/g')"
      COMPREPLY=($(compgen -W "${outfile_var}" -- ${cur}))
      return 0
      ;;

    -d*)
      _oclHashcat_gpu_devices
      local num_devices=${?}

      _oclHashcat_get_permutations ${num_devices}

      local gpu_devices_var="$(echo "  "${oclHashcat_devices_permutation} | sed 's/ / -d/g')"
      COMPREPLY=($(compgen -W "${gpu_devices_var}" -- ${cur}))
      return 0
      ;;
  esac

  # Complete options/switches (not the arguments)

  if [[ "${cur}" == -* ]]; then

      COMPREPLY=($(compgen -W "${SHORT_OPTS} ${LONG_OPTS}" -- ${cur}))
      return 0

  fi

  # additional parameter, no switch nor option but maybe hash file, dictionary, mask, directory

  # check if first option out of (hash.txt and dictionary|mask|directory)
  # is first option iff: here
  # is second option iff: COMP_CWORD > 2 and no switch before (-*) if no option afterwards (for mask -a 3, -a 6, -a 7 - but possible for dicts!) 

  local h=1
  local no_opts=0
  local attack_mode=0 # also default of oclHashcat
  local has_charset_1=0
  local has_charset_2=0
  local has_charset_3=0
  local has_charset_4=0

  while [ ${h} -le ${COMP_CWORD} ]; do

    if   [[ "${COMP_WORDS[h]}" == "-a" ]]; then

      attack_mode=${COMP_WORDS[$((h + 1))]}

    elif   [[ "${COMP_WORDS[h]}" == -a* ]]; then

      attack_mode=${COMP_WORDS[h]:2}

    elif [[ "${COMP_WORDS[h]}" == "--attack-mode" ]]; then

      attack_mode=${COMP_WORDS[$((h + 1))]}

    elif [[ "${COMP_WORDS[h]}" == "-1" ]]; then

      has_charset_1=1

    elif [[ "${COMP_WORDS[h]}" == "--custom-charset1" ]]; then

      has_charset_1=1

    elif [[ "${COMP_WORDS[h]}" == "-2" ]]; then

      has_charset_2=1

    elif [[ "${COMP_WORDS[h]}" == "--custom-charset2" ]]; then

      has_charset_2=1

    elif [[ "${COMP_WORDS[h]}" == "-3" ]]; then

      has_charset_3=1

    elif [[ "${COMP_WORDS[h]}" == "--custom-charset3" ]]; then

      has_charset_3=1

    elif [[ "${COMP_WORDS[h]}" == "-4" ]]; then

      has_charset_4=1

    elif [[ "${COMP_WORDS[h]}" == "--custom-charset4" ]]; then

      has_charset_4=1

    fi

    if _oclHashcat_contains "${OPTIONS}" "${COMP_WORDS[h]}"; then

      h=$((h + 2))

    else

      if ! _oclHashcat_contains "${LONG_OPTS}${SHORT_OPTS}" "${COMP_WORDS[h]}"; then
        local variants="-m -a -w -n -u -o -r -d"
        local skip=0
        local v
        for v in ${variants}; do

          if [[ "${COMP_WORDS[h]:0:2}" == "${v}" ]]; then
            skip=1
          fi

        done

        if [ "${skip}" -eq 0 ]; then

          no_opts=$((no_opts + 1))

        fi
      fi

      h=$((h + 1))

    fi

  done

  case "${no_opts}" in 

    0)
      return 0
      ;;

    1)
      local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
      COMPREPLY=($(compgen -W "${files}" -- ${cur}))
      return 0
      ;;

    *)
      case "${attack_mode}" in

        0)
          # dict/directory are files here
          local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
          COMPREPLY=($(compgen -W "${files}" -- ${cur}))
          return 0
          ;;

        1)
          if [ "${no_opts}" -gt 4 ]; then
            return 0
          fi

          local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
          COMPREPLY=($(compgen -W "${files}" -- ${cur}))
          return 0
          ;;

        3)
          if [ "${no_opts}" -eq 2 ]; then
            local mask=${BUILD_IN_CHARSETS}

            if [ "${has_charset_1}" -eq 1 ]; then

              mask="${mask} ?1"

            fi

            if [ "${has_charset_2}" -eq 1 ]; then

              mask="${mask} ?2"

            fi

            if [ "${has_charset_3}" -eq 1 ]; then

              mask="${mask} ?3"

            fi

            if [ "${has_charset_4}" -eq 1 ]; then

              mask="${mask} ?4"

            fi

            if [ -e "${cur}" ]; then # should be hcmask file (but not enforced)

              COMPREPLY=($(compgen -W "${cur}" -- ${cur}))
              return 0

            fi

            if [ -n "${cur}" ]; then

              local cur_var=$(echo "${cur}" | sed 's/\?$//')

              mask="${mask} ${cur_var}"

              local h
              for h in ${mask}; do

                  mask="${mask} ${cur_var}${h}"

              done
            fi

            local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES}')' 2> /dev/null)

            mask="${mask} ${files}"

            COMPREPLY=($(compgen -W "${mask}" -- ${cur}))
            return 0
          fi
          ;;

        6)
          if [ "${no_opts}" -eq 2 ]; then

            local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
            COMPREPLY=($(compgen -W "${files}" -- ${cur}))

          elif [ "${no_opts}" -eq 3 ]; then
            local mask=${BUILD_IN_CHARSETS}

            if [ "${has_charset_1}" -eq 1 ]; then

              mask="${mask} ?1"

            fi

            if [ "${has_charset_2}" -eq 1 ]; then

              mask="${mask} ?2"

            fi

            if [ "${has_charset_3}" -eq 1 ]; then

              mask="${mask} ?3"

            fi

            if [ "${has_charset_4}" -eq 1 ]; then

              mask="${mask} ?4"

            fi

            if [ -e "${cur}" ]; then # should be hcmask file (but not enforced)

              COMPREPLY=($(compgen -W "${cur}" -- ${cur}))
              return 0

            fi

            if [ -n "${cur}" ]; then

              local cur_var=$(echo "${cur}" | sed 's/\?$//')

              mask="${mask} ${cur_var}"

              local h
              for h in ${mask}; do

                  mask="${mask} ${cur_var}${h}"

              done
            fi

            local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES}')' 2> /dev/null)

            mask="${mask} ${files}"

            COMPREPLY=($(compgen -W "${mask}" -- ${cur}))
            return 0

          fi
          ;;

        7)
          if [ "${no_opts}" -eq 2 ]; then
            local mask=${BUILD_IN_CHARSETS}

            if [ "${has_charset_1}" -eq 1 ]; then

              mask="${mask} ?1"

            fi

            if [ "${has_charset_2}" -eq 1 ]; then

              mask="${mask} ?2"

            fi

            if [ "${has_charset_3}" -eq 1 ]; then

              mask="${mask} ?3"

            fi

            if [ "${has_charset_4}" -eq 1 ]; then

              mask="${mask} ?4"

            fi

            if [ -e "${cur}" ]; then # should be hcmask file (but not enforced)

              COMPREPLY=($(compgen -W "${cur}" -- ${cur}))
              return 0

            fi

            if [ -n "${cur}" ]; then

              local cur_var=$(echo "${cur}" | sed 's/\?$//')

              mask="${mask} ${cur_var}"

              local h
              for h in ${mask}; do

                  mask="${mask} ${cur_var}${h}"

              done
            fi

            local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES}')' 2> /dev/null)

            mask="${mask} ${files}"

            COMPREPLY=($(compgen -W "${mask}" -- ${cur}))
            return 0

          elif [ "${no_opts}" -eq 3 ]; then

            local files=$(ls -d ${cur}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESIVE}')' 2> /dev/null)
            COMPREPLY=($(compgen -W "${files}" -- ${cur}))
            return

          fi
          ;;

      esac

    esac
}

complete -F _oclHashcat -o filenames ${OCLHASHCAT_ROOT}/oclHashcat64.bin "${OCLHASHCAT_ROOT}"/oclHashcat32.bin "${OCLHASHCAT_ROOT}"/cudaHashcat64.bin "${OCLHASHCAT_ROOT}"/cudaHashcat32.bin
