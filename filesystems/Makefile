include $(TOPLEVEL)/Makefile.in

SLEUTHKITSRC = "$(shell find ../sources/ -name sleuthkit\* -type d | head -n1 )"/src/fstools/

SRC = dbtool.c fatfs_dent.c

all:
	if [ ! -d $(SLEUTHKITSRC) ] ; then echo -e \\n\\n Unable to find sleuthkit sources... Please download the latest sleuthkit sources and place in $(TOPLEVEL)/sources; false; fi
	## Now copy the new files over and compile: (SK has a really stupid build system which relies on the makefile being Makefile. The first target is not actually "all" - it simply calls a shell script which calls make with the required parameters.) We need to move the original makefile out of the way, put our makefile instead and then move it back.
	mv $(SLEUTHKITSRC)/Makefile $(SLEUTHKITSRC)/Makefile.sleuthkit
	cp Makefile.dbtool $(SLEUTHKITSRC)/Makefile
	cp $(SRC) $(SLEUTHKITSRC)
	cd $(SLEUTHKITSRC) && make
	mv $(SLEUTHKITSRC)/Makefile.sleuthkit $(SLEUTHKITSRC)/Makefile
	cp $(SLEUTHKITSRC)/dbtool $(TOPLEVEL)/$(BIN)

clean:
	rm -f $(TOPLEVEL)/$(BIN)/dbtool
