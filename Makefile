## Top level makefile
BIN	= bin/
DIRS	= iosubsys imagingtools/dd_rescue/ raidtools indextools regtools virustools sources
SYSBINS = cjpeg djpeg

all:	bins
	for dir in $(DIRS); do\
          (echo Entering directory `pwd`/$$dir; cd $$dir; make "CC=$(CC)" MAKELEVEL= ; echo leaving directory `pwd`/$$dir ); done

## Copy binaries from the system to put into the flag bin dir
bins:
	for i in $(SYSBINS); do cp `which $$i` $(BIN); done

clean:
	for dir in $(DIRS); do\
          (cd $$dir; make clean "CC=$(CC)" MAKELEVEL=); done
