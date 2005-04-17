## Top level makefile
include Makefile.in

all:	pyflag-target

pyflag-target:	bins
	for dir in $(DIRS); do\
          (echo Entering directory `pwd`/$$dir; cd $$dir; make "CC=$(CC)" MAKELEVEL= ; echo leaving directory $$dir ); done

## Copy binaries from the system to put into the flag bin dir
bins:
	for i in $(SYSBINS); do cp `which $$i` $(BIN); done

clean:
	for dir in $(DIRS); do\
          (cd $$dir; make clean "CC=$(CC)" MAKELEVEL=); done
	for dir in $(CLEAN_DIRS); do rm -rf $$dir; done
	  
deb-pkg:	pkg-bin-distro

	#Put the package control file in the right place
	cp pkg_files/control $(BASE_DIR)/flag_deb/debian/DEBIAN
	cp pkg_files/conffiles $(BASE_DIR)/flag_deb/debian/DEBIAN
	#Put the post install script in the right place
	cp pkg_files/postinst $(BASE_DIR)/flag_deb/debian/DEBIAN
	cp pkg_files/preinst $(BASE_DIR)/flag_deb/debian/DEBIAN
	cp pkg_files/postrm $(BASE_DIR)/flag_deb/debian/DEBIAN
	cp pkg_files/prerm $(BASE_DIR)/flag_deb/debian/DEBIAN

	#Fix all the permissions
	for exec in $(EXECUTABLE_SCRIPTS); do chmod 755 $(BASE_DIR)/flag_deb/debian/usr/share/pyflag/$$exec; done

	#Build .deb package
	fakeroot dpkg-deb --build flag_deb/debian
	mv $(BASE_DIR)/flag_deb/debian.deb $(BASE_DIR)/flag_deb/pyflag_$(PACKAGE_VERSION)_$(PACKAGE_ARCH).deb

	#Clean up
	rm -r $(BASE_DIR)/flag_deb/debian

	######### Package in flag_deb directory #########


pkg-bin-distro: pyflag-target
	#Remove old distro
	rm -rf $(BASE_DIR)/pkg_bin_dist
	rm -rf $(BASE_DIR)/flag_deb

	#Create a new temporary dir for our distro
	mkdir -p $(BASE_DIR)/pkg_bin_dist
	for i in `find . -maxdepth 1 | egrep -v '(darcs|sources|mailtools|flag_deb|bin_dist|pkg_bin_dist|pkg_files|^.$$)'`; do cp -a $$i pkg_bin_dist/; done

	## Delete source directories
	cd pkg_bin_dist/ && rm -rf sources sgzip regtools raidtools patches libevf iosubsys indextools exgrep docs virustools imagingtools

	## Delete compiled python files
	find $(BASE_DIR)/pkg_bin_dist -name *.pyc -exec rm {} \;

	## Strip all binaries:
	find pkg_bin_dist/ -perm +0111 -exec strip -R '.comment' {} \; 2> /dev/null

	#Clean up
	find pkg_bin_dist/ -depth -type d -empty -exec rmdir \{\} \; 
	find pkg_bin_dist/ -depth -name \*~ -exec rm -f \{\} \; 

	#Build the required package hierarchy
	mkdir -p $(BASE_DIR)/flag_deb/debian/usr/share/pyflag

	#Move the bin_dist into the package hierarchy
	mv $(BASE_DIR)/pkg_bin_dist/* $(BASE_DIR)/flag_deb/debian/usr/share/pyflag
#	rmdir $(BASE_DIR)/pkg_bin_dist

	mkdir -p $(BASE_DIR)/flag_deb/debian/usr/share/man/man1
	mkdir -p $(BASE_DIR)/flag_deb/debian/usr/bin
	mkdir -p $(BASE_DIR)/flag_deb/debian/DEBIAN

	####UNDER DEVEL - for pyflag service
	#Create directories necessary for pyflag service

	mkdir -p $(BASE_DIR)/flag_deb/debian/etc/pyflag
	mkdir -p $(BASE_DIR)/flag_deb/debian/var/lib/pyflag
	mkdir -p $(BASE_DIR)/flag_deb/debian/etc/init.d
	cp pkg_files/pyflag_service $(BASE_DIR)/flag_deb/debian/etc/init.d/pyflag
	cp pkg_files/debian-start $(BASE_DIR)/flag_deb/debian/etc/pyflag
	mkdir -p $(BASE_DIR)/flag_deb/debian/var/run/pyflagd

	######
	#Make doco links	
	gzip -9c pkg_files/changelog > pkg_files/changelog.gz
	mkdir -p $(BASE_DIR)/flag_deb/debian/usr/share/doc/pyflag
	cp pkg_files/copyright pkg_files/changelog.gz $(BASE_DIR)/flag_deb/debian/usr/share/doc/pyflag
	rm pkg_files/changelog.gz
	for doc in $(DOC_LIST); do (ln -s ../../pyflag/$$doc $(BASE_DIR)/flag_deb/debian/usr/share/doc/pyflag); done

	#Copy man page to correct location
	gzip -9c pkg_files/pyflag.1 > pkg_files/pyflag.1.gz
	mv pkg_files/pyflag.1.gz $(BASE_DIR)/flag_deb/debian/usr/share/man/man1

	#Create /usr/bin link
	ln -s ../share/pyflag/flag.sh $(BASE_DIR)/flag_deb/debian/usr/bin/pyflag

	#Change pyflagrc to put in the package stuff
	sed -f pkg_files/pyflagrc_changes --in-place $(BASE_DIR)/flag_deb/debian/usr/share/pyflag/pyflag/pyflagrc

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
	find bin_dist/python$(PYTHONVER)/ -atime +1 -exec rm {} \;

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
