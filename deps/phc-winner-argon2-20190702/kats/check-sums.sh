#!/bin/sh

for file in `ls | grep '^[a-z2]*\(_v\)\?[0-9]*$' | xargs`
do
    new=`shasum -a 256 $file`
    old=`cat $file.shasum`
    if [ "$new" = "$old" ]
    then
        echo $file "\t" OK
    else
        echo $file "\t" ERROR
    fi
done
