#!/bin/bash

DATADIR=`pwd`/mysql/data
UNIX_SOCKET=$DATADIR/pyflag.sock

## Note: If you wish to put the data directory somewhere else you will need to symlink it.
## This will be executed if the mysql directory exists (then we are running in a pyflag+mysql distribution)
if [ -e mysql ]; then
    cd mysql &&   ./bin/mysqld_safe --skip-networking --socket=$UNIX_SOCKET --skip-grant-tables  --datadir=$DATADIR &
    ## This will override the socket in the config file
    export UNIX_SOCKET

fi

./launch.sh FlagHTTPServer.py $1 $2 $3 $4 $5 $6 $7
