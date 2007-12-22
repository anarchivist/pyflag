#! /bin/sh

libtoolize
aclocal -I config
autoheader
automake --add-missing --copy
autoconf

## Fix up permissions of some files:
chmod +x tests/pyflag tests/pyflash debian/rules
