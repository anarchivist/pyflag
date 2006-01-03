#! /bin/sh

aclocal-1.9 -I config
#autoheader
automake-1.9 --add-missing --copy
autoconf
