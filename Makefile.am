SUBDIRS = src examples debian

my_images	 	=	$(shell find images -not -name .\*)
my_data			=	$(shell find data -not -name .\*)
my_utilities		=	$(shell find utilities -not -name .\*)
bin_SCRIPTS		=	pyflag pyflash pyflag_launch
sysconf_DATA		=	pyflagrc
pkgdata_DATA		=	$(my_data)
nobase_pkgdata_DATA	=	$(my_images) $(my_utilities)
man_MANS		=	pyflag.1
EXTRA_DIST		=	pyflag.in pyflagrc.in pyflash.in \
				pyflag_launch.in $(nobase_pkgdata_DATA) $(pkgdata_DATA) $(man_MANS)

# perform subs in scripts and config files
edit = sed \
	-e 's,@datadir\@,$(pkgdatadir),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@pkgpyexec\@,$(pkgpyexecdir),g' \
	-e 's,@pythondir\@,$(pythondir),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@bin\@,$(bindir),g' \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@ploticus\@,@PLOTICUS@,g' \
	-e 's,@mysql\@,@MYSQL@,g' \
	-e 's,@magic\@,@magic@,g' \
	-e 's,@python\@,$(PYTHON),g'

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

