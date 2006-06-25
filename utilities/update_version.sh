#!/bin/bash
##This little utility function is used to update the version information in all files:

DIRS="src"
NEWVERSION=0.82

exp="s/\\\$Version:.*\\\$/\\\$Version: $NEWVERSION Date: "`date`"\\\$/"

FILES=''
for dir in $DIRS; do FILES="$FILES "`find $dir -name \*.py  -o -name \*.c -o -name \*.h`; done

for f in `echo $FILES`; do 
    echo Updating $f
    sed -e "$exp" "$f" >"$f.tmp"
    mv "$f.tmp" "$f"
done
