#!/bin/bash
PYFLAG_DIR=`dirname $0`

cd $PYFLAG_DIR
./launch.sh pyflag/FlagHTTPServer.py "$@"
