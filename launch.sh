#!/bin/bash

#export LD_LIBRARY_PATH=$PREFIX/libs/
export PYTHONPATH=`pwd`:$LD_LIBRARY_PATH:$PREFIX/lib/python2.4/site-packages/pyflag/

#echo $PYTHONPATH

python2.4 "$@"
