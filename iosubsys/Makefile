SHELL	= /bin/sh
CC	= gcc
DIRS	= hashtools misc magic sgzip lib

all:	
	for dir in $(DIRS); do\
	(echo Entering directory `pwd`/$$dir; cd $$dir; make "CC=$(CC)" MAKELEVEL= ; echo leaving directory `pwd`/$$dir ); done

clean:
	for dir in $(DIRS); do\
          (cd $$dir; make clean "CC=$(CC)" MAKELEVEL=); done

