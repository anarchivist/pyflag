#!/bin/bash

if [ -d uploads ]; then
    export PYFLAG_UPLOADDIR=uploads
fi

## Note: If you wish to put the data directory somewhere else you will need to symlink it.
## This will be executed if the mysql directory exists (then we are running in a pyflag+mysql distribution)
if [ -e mysql* ]; then
    ## Start up the mysql server if needed.
    PYFLAG_DATADIR=`pwd`/`ls -d mysql*/data`
    PYFLAG_UNIX_SOCKET=$PYFLAG_DATADIR/pyflag.sock

    cd mysql* &&   ./bin/mysqld_safe --skip-networking --socket=$PYFLAG_UNIX_SOCKET --skip-grant-tables  --datadir=$PYFLAG_DATADIR --user=root > /dev/null &
    ## This will override the socket in the config file (This passwd and username may be bogus to force the DB handle to fall back onto the socket to connect if there is a mysql local server)
    export PYFLAG_USER=bogus_user
    export PYFLAG_PASSWD=password
    export PYFLAG_HOST=127.0.0.1
    export PYFLAG_PORT=0
    export PYFLAG_UNIX_SOCKET
    export PYFLAG_MYSQL_BIN=`pwd`/`ls mysql*/bin/mysql`
fi

if [ -e python2.3 ] ; then 
	export PYTHONHOME=`pwd`/python2.3/
	export LD_LIBRARY_PATH=`pwd`/libs/
	export PYTHONPATH=`pwd`:`pwd`/python2.3/:`pwd`/python2.3/site-packages/:`pwd`/python2.3/lib-dynload:`pwd`/libs/
	./bin/python $1 $2 $3 $4 $5 $6 $7
else
	# start pyflag, very simple for now
	export PYTHONPATH=`pwd`:`pwd`/libs/
	# Add our libs dir to the LD_LIBRARY_PATH to run our hooker.
	export LD_LIBRARY_PATH=`pwd`/libs/
	env python $1 $2 $3 $4 $5 $6 $7
fi