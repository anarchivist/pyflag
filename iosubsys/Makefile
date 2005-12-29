include ../Makefile.in

SHELL	= /bin/sh
DIRS	= hashtools misc sgzip lib network
STATIC_LIB_PATH = /usr/i586-mingw32msvc/lib/
WIN32PATHS = misc hashtools sgzip lib
CWD = `pwd`
LIB_TARGET=$(CWD)/../../libs/
BIN_DIR=$(CWD)/../../bin/

all:	
	for dir in $(DIRS); do\
	(echo Entering directory $(CWD)/$$dir; (cd $$dir; make "CC=$(CC)" MAKELEVEL= LIB_TARGET=$(LIB_TARGET) BIN_DIR=$(BIN_DIR)) || exit -1; echo leaving directory `pwd`/$$dir ); done

win32:
	for dir in $(WIN32PATHS); do\
	(echo Entering directory `pwd`/$$dir; cd $$dir; make CC=$(CC) MAKELEVEL= $@ STATIC_LIB_PATH=$(STATIC_LIB_PATH); echo leaving directory `pwd`/$$dir ); done


clean:
	for dir in $(DIRS); do\
          (cd $$dir; make clean "CC=$(CC)" MAKELEVEL= LIB_TARGET=$(LIB_TARGET) BIN_DIR=$(BIN_DIR)); done

