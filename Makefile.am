SUBDIRS = src debian

my_images	 	=	$(shell find images -not -name .\*)
my_data			=	$(shell find data -not -name .\*)
my_utilities		=	$(shell find utilities -not -name .\*)
my_examples		=	$(shell find examples -not -name .\*)
bin_SCRIPTS		=	pyflag pyflash pyflag_launch src/pyflag/conf.py
pkgdata_DATA		=	$(my_data) \
				data/magic.mgc data/magic.mime.mgc
pkgpython_PYTHON        =       src/pyflag/conf.py
nobase_pkgdata_DATA	=	$(my_images) $(my_utilities) $(my_examples)
man_MANS		=	pyflag.1
EXTRA_DIST		=	pyflag.in pyflash.in \
				pyflag_launch.in $(nobase_pkgdata_DATA) $(pkgdata_DATA) $(man_MANS) \
				src/pyflag/conf.py.in

# perform subs in scripts and config files
edit = sed \
	-e 's,@datadir\@,$(pkgdatadir),gi' \
	-e 's,@sysconfdir\@,$(sysconfdir),gi' \
	-e 's,@pkgpyexec\@,$(pkgpyexecdir),gi' \
	-e 's,@pythondir\@,$(pythondir),gi' \
	-e 's,@prefix\@,$(prefix),gi' \
	-e 's,@bin\@,$(bindir),gi' \
	-e 's,@VERSION\@,$(VERSION),gi' \
	-e 's,@ploticus\@,@PLOTICUS@,gi' \
	-e 's,@mysql\@,@MYSQL@,gi' \
	-e 's,@magic\@,@magic@,gi' \
	-e 's,@python\@,$(PYTHON),gi'

src/pyflag/%.py: $(top_srcdir)/src/pyflag/%.py.in Makefile
	rm -f $@ $@.tmp
	$(edit) $< > $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@

utilities/%: $(top_srcdir)/utilities/%.in Makefile
	rm -f $@ $@.tmp
	$(edit) $< > $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@

%: $(top_srcdir)/%.in Makefile
	rm -f $@ $@.tmp
	$(edit) $< > $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@

clean-local:
	-rm -rf $(bin_SCRIPTS) $(sysconf_DATA)

deb-pkg:	
	chmod 744 debian/rules
	dpkg-buildpackage -rfakeroot

data/magic.mgc: data/magic
	cd data && file -C -m magic

data/magic.mime.mgc: data/magic.mime
	cd data && file -C -m magic.mime

# This will not be installed automatically - it will be installed
# using the install-data-hook below only if it does not already exist.
# sysconf_DATA		=	pyflagrc

#DEFAULT_CONFIG_FILE = $(sysconfdir)/pyflagrc

#install-data-hook: pyflagrc
#	@if test -f $(DESTDIR)$(DEFAULT_CONFIG_FILE) ; then \
#		echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_CONFIG_FILE)" ; \
#	else \
#		echo "$(INSTALL_DATA) -D pyflagrc $(DESTDIR)$(DEFAULT_CONFIG_FILE)"; \
#		$(INSTALL_DATA) -D pyflagrc $(DESTDIR)$(DEFAULT_CONFIG_FILE); \
#	fi
