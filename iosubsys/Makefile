SHELL	= /bin/sh
DIRS	= hashtools misc magic sgzip lib
STATIC_LIB_PATH = /usr/i586-mingw32msvc/lib/
WIN32PATHS = misc hashtools sgzip lib

all:	
	for dir in $(DIRS); do\
	(echo Entering directory `pwd`/$$dir; cd $$dir; make "CC=$(CC)" MAKELEVEL= ; echo leaving directory `pwd`/$$dir ); done

win32:
	for dir in $(WIN32PATHS); do\
	(echo Entering directory `pwd`/$$dir; cd $$dir; make CC=$(CC) MAKELEVEL= $@ STATIC_LIB_PATH=$(STATIC_LIB_PATH); echo leaving directory `pwd`/$$dir ); done


clean:
	for dir in $(DIRS); do\
          (cd $$dir; make clean "CC=$(CC)" MAKELEVEL=); done

