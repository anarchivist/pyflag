## Top level makefile
BIN	= bin/
DIRS	= iosubsys imagingtools/dd_rescue/ raidtools indextools regtools virustools mailtools sources
SYSBINS = cjpeg djpeg
PYTHONLIB = /usr/lib/python2.3/
PYTHONBIN = `which python2.3`
DATA_DIR = `grep -i DATA_DIR pyflag/pyflagrc | cut -d= -f2`
MYSQLCOMMAND =./bin_dist/mysql/bin/mysql --socket=bin_dist/mysql/data/pyflag.sock
MISC_LIBS = /usr/lib/libgmp.so.3 /usr/lib/libmysqlclient_r.so.10 /usr/lib/libmagic.so.1

all:	bins
	for dir in $(DIRS); do\
          (echo Entering directory `pwd`/$$dir; cd $$dir; make "CC=$(CC)" MAKELEVEL= ; echo leaving directory $$dir ); done

## Copy binaries from the system to put into the flag bin dir
bins:
	for i in $(SYSBINS); do cp `which $$i` $(BIN); done

clean:
	for dir in $(DIRS); do\
          (cd $$dir; make clean "CC=$(CC)" MAKELEVEL=); done

bin-dist:
#	rm -rf bin_dist
	mkdir -p bin_dist
	cp -ar $(PYTHONLIB) bin_dist/
	for i in `find . -maxdepth 1 | egrep -v '(darcs|sources|bin_dist|^.$$)'`; do cp -a $$i bin_dist/; done
	cp $(PYTHONBIN) bin_dist/bin/python
	## Reset all the time stamps to 0
	find bin_dist/ -exec touch -a -d19700000 \{\} \;
	## Run the unit test to touch all the files
	cd bin_dist/ && ./launch.sh pyflag/unit_test.py
	## Now we cleanup python core (any files that were not touched)
	find bin_dist/python2.3/ -atime +1 -exec rm {} \;

	## Delete source directories
	cd bin_dist/ && rm -rf sources sgzip regtools raidtools patches libevf iosubsys indextools exgrep docs virustools imagingtools mailtools

	## General cleanups
	find bin_dist/ -depth -name CVS -exec rm -rf {} \;
	find bin_dist/ -depth -type d -empty -exec rmdir \{\} \; 
	find bin_dist/ -depth -name \*~ -exec rm -f \{\} \; 

	## Strip all binaries:
	find bin_dist/ -perm +0111 -exec strip {} \; 2> /dev/null

	## Adding miscelaneous libraries that need to be present in the binary distribution to work.
	for i in $(MISC_LIBS); do cp $$i bin_dist/libs/; done

mysql:
	mkdir -p bin_dist
	rm -rf bin_dist/mysql/
	cd bin_dist/ && tar -xvzf ../sources/mysql*.tar.gz || (echo -e "**********************\n\nIn order to build embedded mysql support you will need the mysql binary distribution for your platform placed in the sources directory. This can be downloaded from mysql.com.\n\nFor example mysql-max-4.0.21-pc-linux-i686.tar.gz or mysql-standard-4.1.7-pc-linux-i686.tar.gz\n\n*****************************" && false)
	cd bin_dist/mysql* && ./scripts/mysql_install_db
	## Now we launch the database in the background
	bash -c ' cd bin_dist/mysql* &&  ./bin/mysqld_safe --skip-networking --socket=pyflag.sock --skip-grant-tables  --datadir=./data/ &'
	## Wait a bit for the server to start up
	sleep 1
	## Now we create the database:
	export MYSQL=`ls -d ./bin_dist/mysql*` && echo 'CREATE DATABASE pyflag;' | $$MYSQL/bin/mysql --socket=$$MYSQL/data/pyflag.sock	
	export MYSQL=`ls -d ./bin_dist/mysql*` && cat db.setup | $$MYSQL/bin/mysql --socket=$$MYSQL/data/pyflag.sock pyflag
