#! /bin/sh

libtoolize
aclocal-1.9 -I config
autoheader
automake-1.9 --add-missing --copy
autoconf

## Fix up permissions of some files:
chmod +x tests/pyflag tests/pyflash debian/rules
