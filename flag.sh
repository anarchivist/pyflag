#!/bin/bash
PYFLAG_DIR=`dirname $0`

cd $PYFLAG_DIR
./launch.sh pyflag/FlagHTTPServer.py $1 $2 $3 $4 $5 $6 $7
