#!/bin/bash

binary=no

if [ "$binary" == 'yes' ] ; then 
	export PYTHONHOME=`pwd`/python2.3/
	export PYTHONPATH=`pwd`:`pwd`/python2.3/:`pwd`/python2.3/site-packages/:`pwd`/python2.3/lib-dynload
	./bin/python pyflag/FlagGTKServer.py $1 $2 $3 $4 $5 $6 $7
else
	# start pyflag, very simple for now
	export PYTHONPATH=`pwd`
	pyflag/FlagGTKServer.py $1 $2 $3 $4 $5 $6 $7
fi

