#!/bin/bash
##This little utility function is used to update the version information in all files:

#DIRS=`ls -d plugins pyflag`
DIRS="plugins pyflag"
NEWVERSION=0.75

exp="s/\\\$Version:.*\\\$/\\\$Version: $NEWVERSION Date: "`date`"\\\$/"

FILES=''
for dir in $DIRS; do FILES="$FILES "`find $dir -name \*.py`; done

for f in `echo $FILES`; do 
    sed -e "$exp" "$f" >"$f.tmp"
    mv "$f.tmp" "$f"
done

