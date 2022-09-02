##
## Author......: See docs/credits.txt
## License.....: MIT
##

HASHCAT_ROOT="."

# helper functions

_hashcat_backend_devices ()
{
  local cur_selection="${1}"
  hashcat_device_list=""

  local executable="${HASHCAT_ROOT}"/hashcat

  if [ ! -x "${executable}" ]; then
    executable="${HASHCAT_ROOT}"/hashcat.bin
  fi

  if [ ! -x "${executable}" ]; then
    local which_hashcat=$(which hashcat 2>/dev/null)

    if [ -n "${which_hashcat}" ]; then
      executable="${which_hashcat}"
    fi
  fi

  if [ ! -x "${executable}" ]; then
    return
  fi

  # remove separator at the end (if present)

  cur_selection=$(echo "${cur_selection}" | sed 's/,$//')

  # sanity check, all device ids must be numerical

  if [ -n "${cur_selection}" ]; then
    if echo "${cur_selection}" | sed 's/,/\n/g' | grep -q -v '^[0-9]\+$'; then
      return
    fi
  fi

  local hashcat_I=$("${executable}" -I 2>/dev/null | grep "Backend Device ID #[0-9]\+" | sed 's/^ *Backend Device ID #//')

  if [ -z "${hashcat_I}" ]; then
    return
  fi

  local aliases=$(echo "${hashcat_I}" | grep "(Alias: #[0-9]\+)" | sed 's/ *(Alias: #\([0-9]\+\))/ \1/')

  local aliases_num=$(echo "${aliases}" | wc -l)

  local aliases_deduplicate=""

  local alias_pos=""

  for alias_pos in $(seq 1 ${aliases_num}); do
    local alias_sorted=$(echo "${aliases}" | sed -n "${alias_pos}p" | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ *$//')

    if [ -n "${aliases_deduplicate}" ]; then
      aliases_deduplicate=$(echo -e "${aliases_deduplicate}\n${alias_sorted}")
    else
      aliases_deduplicate="${alias_sorted}"
    fi
  done

  aliases_deduplicate=$(echo "${aliases_deduplicate}" | sort -u)

  aliases_num=$(echo "${aliases_deduplicate}" | wc -l)

  local device_list=$(echo "${hashcat_I}" | grep -o "^[0-9]*" | sort -n -u)

  local cur_device_list=$(echo "${cur_selection}" | sed 's/,/\n/g' | grep "^[0-9]\+\$" | sort -nu)

  # make sure that every device in the current selected device list (parameter) is within our backend device list

  local device=""

  for device in ${cur_device_list}; do
    if ! echo "${device_list}" | grep -q "^${device}\$" 2>/dev/null; then
      return # error
    fi
  done

  local appended_device_list=${device_list}

  for device in ${cur_device_list}; do
    appended_device_list=$(echo "${appended_device_list}" | grep -v "^${device}\$")
  done

  local hashcat_backend_list=""

  if [ -n "${cur_selection}" ]; then
    hashcat_backend_list="${cur_selection}"
  fi

  for device in ${appended_device_list}; do
    if [ -z "${hashcat_backend_list}" ]; then
      if [ -z "${cur_selection}" ]; then
        hashcat_backend_list="${device}"
      else
        hashcat_backend_list="${cur_selection},${device}"
      fi
    else
      if [ -z "${cur_selection}" ]; then
        hashcat_backend_list=$(echo -e "${hashcat_backend_list}\n${device}")
      else
        hashcat_backend_list=$(echo -e "${hashcat_backend_list}\n${cur_selection},${device}")
      fi
    fi
  done

  # finally, blacklist all devices that are just aliases

  local device_str=""

  for device_str in ${hashcat_backend_list}; do
    local devices=$(echo "${device_str}" | tr ',' '\n')

    local conflict=0

    for alias_pos in $(seq 1 ${aliases_num}); do
      local alias=$(echo "${aliases_deduplicate}" | sed -n "${alias_pos}p" | tr ' ' '\n')

      # currently, an alias always consists of 2 devices:

      local alias1=$(echo "${alias}" | sed -n "1p") # head -n 1
      local alias2=$(echo "${alias}" | sed -n "2p") # tail -n 1

      if echo "${devices}" | grep -q "^${alias1}\$"; then
        if echo "${devices}" | grep -q "^${alias2}\$"; then
          conflict=1
          break
        fi
      fi
    done

    if [ "${conflict}" -eq 1 ]; then
      continue
    fi

    # we add it because we didn't find any conflicts:

    if [ -z "${hashcat_device_list}" ]; then
      hashcat_device_list="${device_str}"
    else
      hashcat_device_list=$(echo -e "${hashcat_device_list}\n${device_str}")
    fi
  done
}

_hashcat_cpu_devices ()
{
  local cur_selection="${1}"

  hashcat_device_list=""

  if [ ! -f "/proc/cpuinfo" ]; then
    return
  fi

  local num_devices=$(cat /proc/cpuinfo 2> /dev/null | grep -c processor 2> /dev/null)

  local device_list=$(seq 1 ${num_devices})

  # remove separator at the end (if present)

  cur_selection=$(echo "${cur_selection}" | sed 's/,$//')

  # sanity check, all device ids must be numerical

  if [ -n "${cur_selection}" ]; then
    if echo "${cur_selection}" | sed 's/,/\n/g' | grep -q -v '^[0-9]\+$'; then
      return
    fi
  fi

  local cur_device_list=$(echo "${cur_selection}" | sed 's/,/\n/g' | grep "^[0-9]\+\$" | sort -nu)

  # make sure that every device in the current selected device list (parameter) is within our cpu device list

  local device=""

  for device in ${cur_device_list}; do
    if ! echo "${device_list}" | grep -q "^${device}\$" 2>/dev/null; then
      return # error
    fi
  done

  local appended_device_list=${device_list}

  for device in ${cur_device_list}; do
    appended_device_list=$(echo "${appended_device_list}" | grep -v "^${device}\$")
  done

  if [ -n "${cur_selection}" ]; then
    hashcat_device_list="${cur_selection}"
  fi

  for device in ${appended_device_list}; do
    if [ -z "${hashcat_device_list}" ]; then
      if [ -z "${cur_selection}" ]; then
        hashcat_device_list="${device}"
      else
        hashcat_device_list="${cur_selection},${device}"
      fi
    else
      if [ -z "${cur_selection}" ]; then
        hashcat_device_list=$(echo -e "${hashcat_device_list}\n${device}")
      else
        hashcat_device_list=$(echo -e "${hashcat_device_list}\n${cur_selection},${device}")
      fi
    fi
  done
}

_hashcat_files_replace_home ()
{
  local cur_select="${1}"
  local  cur_files="${2}"

  hashcat_select="${cur_select}"
  hashcat_file_list="${cur_files}"

  if echo ${cur_select} | grep -q "^~/"; then
    home_dir="${HOME}"

    if [ -n "${home_dir}" ]; then
      hashcat_file_list=$(echo -n "${cur_files}" | sed "s!^${home_dir}!~\\\\!")
      hashcat_select=$(echo -n "${cur_select}" | sed "s!^~/!~\\\\/!")
    fi
  fi
}

_hashcat_recursive_file_search ()
{
  local  allow_dir="${1}"
  local is_include="${2}"
  local  file_list="${3}"
  local cur_filter="${4}"

  local grep_flags="-Ei"

  if [ "${is_include}" -eq 0 ]; then
    grep_flags="-Eiv"
  fi

  hashcat_file_list=""

  local dir_loop=""

  for dir_loop in "${file_list}"; do
    if [ -d "${dir_loop}" ]; then
      # check subdirs:

      local subdir="${dir_loop}"
      local loop_cnt=0

      for loop_cnt in $(seq 1 35); do # maximum number of recursive (subdir) tests
        local subdir_files=$(bash -c "ls -d ${subdir}/*" 2> /dev/null | grep ${grep_flags} '*\.('${cur_filter}')' 2> /dev/null)

        if [ "${allow_dir}" -eq 1 ]; then
          if [ -n "${hashcat_file_list}" ]; then
            hashcat_file_list="${hashcat_file_list} "
          fi

          hashcat_file_list="${hashcat_file_list}${subdir}"
        fi

        if [ -z "${subdir_files}" ]; then
          break
        fi

        local subdir_file=""

        for subdir_file in "${subdir_files}"; do
          if [ "${allow_dir}" -eq 1 ]; then
            if [ -n "${hashcat_file_list}" ]; then
              hashcat_file_list="${hashcat_file_list} "
            fi

            hashcat_file_list="${hashcat_file_list}${subdir_file}"
          else
            if [ ! -d "${subdir_file}" ]; then
              if [ -n "${hashcat_file_list}" ]; then
                hashcat_file_list="${hashcat_file_list} "
              fi

              hashcat_file_list="${hashcat_file_list}${subdir_file}"
            fi
          fi
        done

        local amount=$(echo "${subdir_files}" | wc -l)

        if [ "${amount}" -gt 1 ]; then
          break
        fi

        subdir="${subdir_files}"
      done
    else
      if [ -n "${hashcat_file_list}" ]; then
        hashcat_file_list="${hashcat_file_list} "
      fi

      hashcat_file_list="${hashcat_file_list}${dir_loop}"
    fi
  done
}

_hashcat_include ()
{
  local  allow_dir="${1}"
  local cur_select="${2}"
  local cur_filter="${3}"

  # allow starting/ending quotes (" and '):

  cur_select=$(echo -n "${cur_select}" | sed 's/^["'"'"']//' | sed 's/["'"'"']\$//')

  local file_list=$(bash -c "ls -d ${cur_select}*" 2> /dev/null | grep -Ei "${cur_filter}" 2> /dev/null)

  _hashcat_recursive_file_search "${allow_dir}" 1 "${file_list}" "${cur_filter}"

  if [ "${allow_dir}" -eq 1 ]; then
    if [ -d "${cur_select}" ]; then
      if [ -n "${hashcat_file_list}" ]; then
        hashcat_file_list="${hashcat_file_list} "
      fi

      hashcat_file_list="${hashcat_file_list}${cur_select}"
    fi
  fi

  # handle special case for $HOME directory (~/)

  _hashcat_files_replace_home "${cur_select}" "${hashcat_file_list}"

  # (hashcat_select and hashcat_file_list are modified and "returned")
}

_hashcat_files_include ()
{
  _hashcat_include 0 "${1}" "${2}"
}

_hashcat_files_folders_include ()
{
  _hashcat_include 1 "${1}" "${2}"
}

_hashcat_exclude ()
{
  local  allow_dir="${1}"
  local cur_select="${2}"
  local cur_filter="${3}"

  # allow starting/ending quotes (" and '):

  cur_select=$(echo -n "${cur_select}" | sed 's/^["'"'"']//' | sed 's/["'"'"']\$//')

  local file_list=$(bash -c "ls -d ${cur_select}*" 2> /dev/null | grep -Eiv '*\.('${cur_filter}')' 2> /dev/null)

  _hashcat_recursive_file_search "${allow_dir}" 0 "${file_list}" "${cur_filter}"

  if [ "${allow_dir}" -eq 1 ]; then
    if [ -d "${cur_select}" ]; then
      if [ -n "${hashcat_file_list}" ]; then
        hashcat_file_list="${hashcat_file_list} "
      fi

      hashcat_file_list="${hashcat_file_list}${cur_select}"
    fi
  fi

  # handle special case for $HOME directory (~/)

  _hashcat_files_replace_home "${cur_select}" "${hashcat_file_list}"

  # (hashcat_select and hashcat_file_list are modified and "returned")
}

_hashcat_files_exclude ()
{
  _hashcat_exclude 0 "${1}" "${2}"
}

_hashcat_files_folders_exclude ()
{
  _hashcat_exclude 1 "${1}" "${2}"
}

_hashcat_contains ()
{
  local haystack=${1}
  local needle="${2}"

  if   echo "${haystack}" | grep -q " ${needle} "  2> /dev/null; then
    return 0
  elif echo "${haystack}" | grep -q "^${needle} "  2> /dev/null; then
    return 0
  elif echo "${haystack}" | grep -q " ${needle}\$" 2> /dev/null; then
    return 0
  fi

  return 1
}

_hashcat ()
{
  local VERSION=6.2.6

  local ATTACK_MODES="0 1 3 6 7 9"
  local HCCAPX_MESSAGE_PAIRS="0 1 2 3 4 5"
  local OUTFILE_FORMATS="1 2 3 4 5 6"
  local OPENCL_DEVICE_TYPES="1 2 3"
  local BACKEND_VECTOR_WIDTH="1 2 4 8 16"
  local DEBUG_MODE="1 2 3 4"
  local WORKLOAD_PROFILE="1 2 3 4"
  local BRAIN_CLIENT_FEATURES="1 2 3"
  local HIDDEN_FILES="exe|bin|potfile|hcstat2|dictstat2|sh|cmd|bat|restore"
  local HIDDEN_FILES_AGGRESSIVE="${HIDDEN_FILES}|hcmask|hcchr"
  local BUILD_IN_CHARSETS='?l ?u ?d ?a ?b ?s ?h ?H'

  local SHORT_OPTS="-m -a -V -h -b -t -T -o -p -c -d -D -w -n -u -j -k -r -g -1 -2 -3 -4 -i -I -s -l -O -S -z -M"
  local LONG_OPTS="--hash-type --attack-mode --version --help --quiet --benchmark --benchmark-all --hex-salt --hex-wordlist --hex-charset --force --status --status-json --status-timer --stdin-timeout-abort --machine-readable --loopback --markov-hcstat2 --markov-disable --markov-inverse --markov-classic --markov-threshold --runtime --session --speed-only --progress-only --restore --restore-file-path --restore-disable --outfile --outfile-format --outfile-autohex-disable --outfile-check-timer --outfile-check-dir --wordlist-autohex-disable --separator --show --deprecated-check-disable --left --username --remove --remove-timer --potfile-disable --potfile-path --debug-mode --debug-file --induction-dir --segment-size --bitmap-min --bitmap-max --cpu-affinity --example-hashes --hash-info --backend-ignore-cuda --backend-ignore-opencl --backend-ignore-hip --backend-ignore-metal --backend-info --backend-devices --opencl-device-types --backend-vector-width --workload-profile --kernel-accel --kernel-loops --kernel-threads --spin-damp --hwmon-disable --hwmon-temp-abort --skip --limit --keyspace --rule-left --rule-right --rules-file --generate-rules --generate-rules-func-min --generate-rules-func-max --generate-rules-func-sel --generate-rules-seed --custom-charset1 --custom-charset2 --custom-charset3 --custom-charset4 --hook-threads --increment --increment-min --increment-max --logfile-disable --scrypt-tmto --keyboard-layout-mapping --truecrypt-keyfiles --veracrypt-keyfiles --veracrypt-pim-start --veracrypt-pim-stop --stdout --keep-guessing --hccapx-message-pair --nonce-error-corrections --encoding-from --encoding-to --optimized-kernel-enable --multiply-accel-disable --self-test-disable --slow-candidates --brain-server --brain-server-timer --brain-client --brain-client-features --brain-host --brain-port --brain-session --brain-session-whitelist --brain-password --identify"
  local OPTIONS="-m -a -t -o -p -c -d -w -n -u -j -k -r -g -1 -2 -3 -4 -s -l --hash-type --attack-mode --status-timer --stdin-timeout-abort --markov-hcstat2 --markov-threshold --runtime --session --outfile --outfile-format --outfile-check-timer --outfile-check-dir --separator --remove-timer --potfile-path --restore-file-path --debug-mode --debug-file --induction-dir --segment-size --bitmap-min --bitmap-max --cpu-affinity --backend-devices --opencl-device-types --backend-vector-width --workload-profile --kernel-accel --kernel-loops --kernel-threads --spin-damp --hwmon-temp-abort --skip --limit --rule-left --rule-right --rules-file --generate-rules --generate-rules-func-min --generate-rules-func-max --generate-rules-func-sel --generate-rules-seed --custom-charset1 --custom-charset2 --custom-charset3 --custom-charset4 --hook-threads --increment-min --increment-max --scrypt-tmto --keyboard-layout-mapping --truecrypt-keyfiles --veracrypt-keyfiles --veracrypt-pim-start --veracrypt-pim-stop --hccapx-message-pair --nonce-error-corrections --encoding-from --encoding-to --brain-server-timer --brain-client-features --brain-host --brain-password --brain-port --brain-session --brain-session-whitelist"

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

    -a|--attack-mode)
      COMPREPLY=($(compgen -W "${ATTACK_MODES}" -- ${cur}))
      return 0
      ;;

    --hccapx-message-pair)
      COMPREPLY=($(compgen -W "${HCCAPX_MESSAGE_PAIRS}" -- ${cur}))
      return 0
      ;;

    --outfile-format)
      local outfile_format_list=""

      local filter_list=$(echo -n "${OUTFILE_FORMATS}" | sed 's/ //g')

      if echo "${cur}" | grep -q "^[,${filter_list}]*$"; then
        outfile_format_list="${cur}"

        # remove formats already used in the command line:
        local formats_used=$(echo -n "${cur}" | sed 's/,/\n/g')
        local allowed_formats=$(echo -n "${OUTFILE_FORMATS}" | sed 's/ /\n/g')

        local i
        for i in $formats_used; do
          allowed_formats=$(echo -n "${allowed_formats}" | grep -v "${formats_used}")
        done

        outfile_format_list="${cur}"
        for i in $allowed_formats; do
          outfile_format_list="${outfile_format_list} ${cur},${i}"
        done
      fi

      COMPREPLY=($(compgen -W "${outfile_format_list}" -- ${cur}))
      return 0
      ;;

    -w|--workload-profile)
      COMPREPLY=($(compgen -W "${WORKLOAD_PROFILE}" -- ${cur}))
      return 0
      ;;

    --brain-client-features)
      COMPREPLY=($(compgen -W "${BRAIN_CLIENT_FEATURES}" -- ${cur}))
      return 0
      ;;

    -o|--outfile|-r|--rules-file|--debug-file|--potfile-path| --restore-file-path)
      _hashcat_files_exclude "${cur}" "${HIDDEN_FILES_AGGRESSIVE}"
      COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select})) # or $(compgen -f -X '*.+('${HIDDEN_FILES_AGGRESSIVE}')' -- ${cur})
      return 0
      ;;

    --markov-hcstat2)
      _hashcat_files_include "${cur}" '.*\.hcstat2$'
      COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select}))
      return 0
      ;;

     -d|--backend-devices)
      _hashcat_backend_devices ${cur}

      COMPREPLY=($(compgen -W "${hashcat_device_list}" -- ${cur}))
      return 0
      ;;

    --opencl-device-types)
      COMPREPLY=($(compgen -W "${OPENCL_DEVICE_TYPES}" -- ${cur}))
      return 0
      ;;

    --backend-vector-width)
      COMPREPLY=($(compgen -W "${BACKEND_VECTOR_WIDTH}" -- ${cur}))
      return 0
      ;;

    --cpu-affinity)
      _hashcat_cpu_devices ${cur}

      COMPREPLY=($(compgen -W "${hashcat_device_list}" -- ${cur}))
      return 0
      ;;

    --keyboard-layout-mapping)
      _hashcat_files_include "${cur}" '.*\.hckmap$'
      COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select}))
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

        mask="${mask} ${cur_var}"
      fi

      _hashcat_files_exclude "${cur}" "${HIDDEN_FILES}"

      mask="${mask} ${hashcat_file_list}"

      COMPREPLY=($(compgen -W "${mask}" -- ${hashcat_select}))
      return 0
      ;;

    --brain-session)
      local cur_session=$(echo "${cur}" | grep -Eo '^0x[0-9a-fA-F]*' | sed 's/^0x//')

      local session_var="0x${cur_session}"

      if [ "${#cur_session}" -lt 8 ]
      then
        session_var="${session_var}0 ${session_var}1 ${session_var}2 ${session_var}3 ${session_var}4
                     ${session_var}5 ${session_var}6 ${session_var}7 ${session_var}8 ${session_var}9
                     ${session_var}a ${session_var}b ${session_var}c ${session_var}d ${session_var}e
                     ${session_var}f"
      fi

      COMPREPLY=($(compgen -W "${session_var}" -- ${cur}))

      return 0
      ;;

    --brain-session-whitelist)
      local session_list=$(echo "${cur}" | grep -Eo '^0x[0-9a-fA-F,x]*' | sed 's/^0x//')

      local cur_session=$(echo "${session_list}" | sed 's/^.*0x//')

      local session_var="0x${session_list}"

      if [ "${#cur_session}" -eq 8 ]
      then
        cur_session=""
        session_var="${session_var},0x"
      fi

      if [ "${#cur_session}" -lt 8 ]
      then
        session_var="${session_var}0 ${session_var}1 ${session_var}2 ${session_var}3 ${session_var}4
                     ${session_var}5 ${session_var}6 ${session_var}7 ${session_var}8 ${session_var}9
                     ${session_var}a ${session_var}b ${session_var}c ${session_var}d ${session_var}e
                     ${session_var}f"
      fi

      COMPREPLY=($(compgen -W "${session_var}" -- ${cur}))

      return 0
      ;;

    --debug-mode)
      COMPREPLY=($(compgen -W "${DEBUG_MODE}" -- ${cur}))
      return 0
      ;;

    --truecrypt-keyfiles|--veracrypt-keyfiles)
      # first: remove the quotes such that file matching is possible

      local cur_part0=$(echo "${cur}" | grep -Eo '^("|'"'"')')

      local cur_sel=$(echo "${cur}" | sed 's/["'"'"']//g')

      local cur_part1=$(echo "${cur_sel}" | grep ',' 2> /dev/null | sed 's/^\(.*, *\)[^,]*$/\1/')
      local cur_part2=$(echo "${cur_sel}" | sed 's/^.*, *\([^,]*\)$/\1/')

      _hashcat_files_exclude "${cur_part2}" "${HIDDEN_FILES_AGGRESSIVE}"


      # generate lines with the file name and a duplicate of it with a comma at the end

      hashcat_file_list=$(echo "${hashcat_file_list}"  | \
                          sed  "s/^/${cur_part1}/"     | \
                          sed  "s/^/${cur_part0}/"     | \
                          sed  's/^\(.*\)$/\1\n\1,\n/' | \
                          sed  's/,\+$/,/g'            | \
                          sed  's/^\(.*\)$/\1\n\1"/'   | \
                          sed  's/,\+"$/"/')

      COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${cur_sel}))
      return 0
  esac

  # allow also the VARIANTS w/o spaces
  # we could use compgen -P prefix, but for some reason it doesn't seem to work always

  case "$cur" in

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

    -o*)
      local outfile_var=$(ls -d ${cur:2}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESSIVE}')' 2> /dev/null)
      outfile_var="$(echo -e "\n${outfile_var}" | sed 's/^/-o/')"
      COMPREPLY=($(compgen -W "${outfile_var}" -- ${cur}))
      return 0
      ;;

    -r*)
      local outfile_var=$(ls -d ${cur:2}* 2> /dev/null | grep -Eiv '*\.('${HIDDEN_FILES_AGGRESSIVE}')' 2> /dev/null)
      outfile_var="$(echo -e "\n${outfile_var}" | sed 's/^/-r/')"
      COMPREPLY=($(compgen -W "${outfile_var}" -- ${cur}))
      return 0
      ;;

    -d*)
      _hashcat_backend_devices $(echo ${cur} | sed 's/^-d//')

      local hashcat_devices_permutation="$(echo -e "\n${hashcat_device_list}" | sed 's/^/-d/')"
      COMPREPLY=($(compgen -W "${hashcat_devices_permutation}" -- ${cur}))
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
  local attack_mode=0 # also default of hashcat
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

    if _hashcat_contains "${OPTIONS}" "${COMP_WORDS[h]}"; then

      h=$((h + 2))

    else

      if ! _hashcat_contains "${LONG_OPTS}${SHORT_OPTS}" "${COMP_WORDS[h]}"; then
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
      _hashcat_files_exclude "${cur}" "${HIDDEN_FILES_AGGRESSIVE}"
      COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select}))
      return 0
      ;;

    *)
      case "${attack_mode}" in

        0|9)
          # dict/directory are files here
          _hashcat_files_folders_exclude "${cur}" "${HIDDEN_FILES_AGGRESSIVE}"
          COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select}))
          return 0
          ;;

        1)
          if [ "${no_opts}" -gt 4 ]; then
            return 0
          fi

          _hashcat_files_folders_exclude "${cur}" "${HIDDEN_FILES_AGGRESSIVE}"
          COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select}))
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

              local h
              for h in ${mask}; do
                mask="${mask} ${cur_var}${h}"
              done

              mask="${mask} ${cur_var}"
            fi

            _hashcat_files_exclude "${cur}" "${HIDDEN_FILES}"

            mask="${mask} ${hashcat_file_list}"

            COMPREPLY=($(compgen -W "${mask}" -- ${hashcat_select}))

            return 0
          fi
          ;;

        6)
          if [ "${no_opts}" -eq 2 ]; then

            _hashcat_files_folders_exclude "${cur}" "${HIDDEN_FILES_AGGRESSIVE}"
            COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select}))

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

              local h
              for h in ${mask}; do
                mask="${mask} ${cur_var}${h}"
              done

              mask="${mask} ${cur_var}"
            fi

            _hashcat_files_folders_exclude "${cur}" "${HIDDEN_FILES}"

            mask="${mask} ${hashcat_file_list}"

            COMPREPLY=($(compgen -W "${mask}" -- ${hashcat_select}))
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

              local h
              for h in ${mask}; do
                mask="${mask} ${cur_var}${h}"
              done

              mask="${mask} ${cur_var}"
            fi

            _hashcat_files_folders_exclude "${cur}" "${HIDDEN_FILES}"

            mask="${mask} ${hashcat_file_list}"

            COMPREPLY=($(compgen -W "${mask}" -- ${hashcat_select}))
            return 0

          elif [ "${no_opts}" -eq 3 ]; then

            _hashcat_files_folders_exclude "${cur}" "${HIDDEN_FILES_AGGRESSIVE}"
            COMPREPLY=($(compgen -W "${hashcat_file_list}" -- ${hashcat_select}))
            return 0

          fi
          ;;

      esac

    esac
}

complete -F _hashcat "${HASHCAT_ROOT}"/hashcat.bin  "${HASHCAT_ROOT}"/hashcat hashcat
