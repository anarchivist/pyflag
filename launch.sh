#!/bin/bash

if [ -e python2.3 ] ; then 
	export PYTHONHOME=`pwd`/python2.3/
	export LD_LIBRARY_PATH=`pwd`:`pwd`/libs/
	export PYTHONPATH=`pwd`:`pwd`/python2.3/:`pwd`/python2.3/site-packages/:`pwd`/python2.3/lib-dynload
	./bin/python pyflag/$1 $2 $3 $4 $5 $6 $7
else
	# start pyflag, very simple for now
	export PYTHONPATH=`pwd`
	env python pyflag/$1 $2 $3 $4 $5 $6 $7
fi