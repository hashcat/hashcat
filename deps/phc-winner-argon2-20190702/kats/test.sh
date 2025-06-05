#!/bin/sh

for opttest in "" "OPTTEST=1"
do
  if [ "" = "$opttest" ]
  then
    printf "Default build\n"
  else
    printf "Force OPTTEST=1\n"
  fi

  make genkat $opttest > /dev/null
  if [ $? -ne 0 ]
  then
    exit $?
  fi

  i=0
  for version in 16 19
  do
    for type in i d id
    do
      i=$(($i+1))

      printf "argon2$type v=$version: "

      if [ 19 -eq $version ]
      then
        kats="kats/argon2"$type
      else
        kats="kats/argon2"$type"_v"$version
      fi

      ./genkat $type $version > tmp
      if diff tmp $kats
      then
        printf "OK"
      else
        printf "ERROR"
        exit $i
      fi
      printf "\n"
    done
  done
done

rm -f tmp

exit 0
