# this is bit hacking for the shiny new autoconf system, but what can you do?

SKVER		= sleuthkit-2.03
bin_SCRIPTS 	= $(SKVER)/src/fstools/dbtool
EXTRA_DIST	= dbtool.c Makefile.dbtool

DBTOOL_SRC  	= dbtool.c
SLEUTHKITSRC 	= $(SKVER)/src/fstools/

$(SKVER)/src/fstools/dbtool: sleuthkit
	## Now copy the new files over and compile: (SK has a really stupid build system which relies on the makefile being Makefile. The first target is not actually "all" - it simply calls a shell script which calls make with the required parameters.) We need to move the original makefile out of the way, put our makefile instead and then move it back.
	mv $(SLEUTHKITSRC)/Makefile $(SLEUTHKITSRC)/Makefile.sleuthkit
	cp Makefile.dbtool $(SLEUTHKITSRC)/Makefile
	cp $(DBTOOL_SRC) $(SLEUTHKITSRC)
	cd $(SLEUTHKITSRC) && make
	mv $(SLEUTHKITSRC)/Makefile.sleuthkit $(SLEUTHKITSRC)/Makefile

# sk also includes 'file', so we will use its python-magic binding (and hope it compiles against the system)
pkgpyexec_LTLIBRARIES 	= magic.la
nodist_magic_la_SOURCES	= $(SKVER)/src/file/python/py_magic.h $(SKVER)/src/file/python/py_magic.c
magic_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
magic_la_LDFLAGS 	= -module -lmagic

$(SKVER)/src/file/python/py_magic.c: sleuthkit

sleuthkit:
	if [ ! -d $(SKVER) ] ; then tar -xvzf $(SKVER).tar.gz || (echo -e "--------------------------\\r\\nYou must have $(SKVER).tar.gz in the src/filesystems directory\\r\\nYou can get it from http://sleuthkit.sf.net\\r\\n--------------------------" && exit -1); fi
	cd $(SKVER) && make

clean-local:
	-rm -rf $(SKVER)
