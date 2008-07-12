#! /bin/sh

echo PyFlag autogen.sh
echo

res=`type libtoolize`
if [ $0 = 0 ]; then
	echo please install libtoolize
	exit 1
else
	echo starting libtoolize
	libtoolize
	echo finished libtoolize
fi

echo

res=`type aclocal`
if [ $0 = 0 ]; then
	echo please install aclocal
	exit 1
else
	echo starting aclocal
	aclocal -I config
	echo finished aclocal
fi

echo

res=`type autoheader`
if [ $0 = 0 ]; then
    echo please install autoheader
    exit 1
else
    echo starting autoheader
	autoheader
    echo finished autoheader
fi

echo

res=`type automake`
if [ $0 = 0 ]; then
    echo please install automake
    exit 1
else
    echo starting automake
	automake --add-missing --copy
	echo finished automake
fi

echo

res=`type autoconf`
if [ $0 = 0 ]; then
    echo please install autoconf
    exit 1
else
    echo starting autoconf
	autoconf
	echo finished autoconf
fi

echo

## Fix up permissions of some files:
chmod +x tests/pyflag tests/pyflash debian/rules
chmod +x utilities/*.py

echo everything done...
echo
echo next steps are running configure, make, make install
