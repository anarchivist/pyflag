#!/bin/bash
# Script to produce a self-contained binary distribution of pyflag
# After running this script, change flag.sh to run in binary distro mode.
#
# Author Michael Cohen

#echo This script is to be run by hand... its too fragile at the moment.
#exit;

cp -ar /usr/lib/python2.3/ ./
cp `which python` bin/

## Reset all the time stamps to 0
find . -exec touch -a -d19700000 \{\} \;

## This causes all of pyflag to be loaded so it should touch all the imports from python core.
export PYTHONHOME=`pwd`/python2.3/
export PYTHONPATH=`pwd`:`pwd`/python2.3/:`pwd`/python2.3/site-packages/:`pwd`/python2.3/lib-dynload
./bin/python pyflag/unit_test.py

## Now we cleanup python core (any files that were not touched)
find python2.3/ -atime +1 -exec rm {} \;

## Delete source directories
rm -rf sources sgzip regtools raidtools patches libevf iosubsys indextools exgrep docs virustools imagingtools

## General cleanups
find . -depth -name CVS -exec rm -rf {} \;
find . -depth -empty -exec rmdir \{\} \; 

## Strip all binaries
find . -perm +0111 -exec strip {} \;

## Remove python bytecode:
## find pyflag -name \*.pyc -exec rm {} \;
