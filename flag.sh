#!/bin/bash

PYFLAG_SCRIPT=$0

if [ -L $0 ]; then
# Change directory to the link dir so that we can handle
# relative links
PYFLAG_DIR=`dirname $PYFLAG_SCRIPT`;
cd $PYFLAG_DIR
# Read the link target filename
PYFLAG_SCRIPT=`readlink $0`;
fi

PYFLAG_DIR=`dirname $PYFLAG_SCRIPT`

cd $PYFLAG_DIR
./launch.sh pyflag/FlagHTTPServer.py "$@"
