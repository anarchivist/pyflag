#!/bin/bash

if [ -e mysql ]; then
    cd mysql && ./bin/mysqld_safe --skip-networking --socket=/tmp/pyflag.sock &
fi

./launch.sh FlagHTTPServer.py $1 $2 $3 $4 $5 $6 $7
