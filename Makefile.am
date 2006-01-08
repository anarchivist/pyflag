SUBDIRS = src

bin_SCRIPTS		=	pyflag
sysconf_DATA		=	pyflagrc
nobase_pkgdata_DATA	=	images/* data/db.setup
EXTRA_DIST		=	pyflag.in pyflagrc.in

# perform subs in scripts and config files
edit = sed \
	-e 's,@datadir\@,$(pkgdatadir),g' \
	-e 's,@sysconf\@,$(sysconfdir),g' \
	-e 's,@pkgpyexec\@,$(pkgpyexecdir),g' \
	-e 's,@pythondir\@,$(pythondir),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@bin\@,$(bindir),g' \
	-e 's,@ploticus\@,@PLOTICUS@,g' \
	-e 's,@mysql\@,@MYSQL@,g' \
	-e 's,@python\@,$(PYTHON),g'

pyflagrc: Makefile $(top_srcdir)/pyflagrc.in
	rm -f pyflagrc pyflagrc.tmp
	$(edit) $(top_srcdir)/pyflagrc.in >pyflagrc.tmp
	mv pyflagrc.tmp pyflagrc

pyflag: Makefile $(top_srcdir)/pyflag.in
	rm -f pyflag pyflag.tmp
	$(edit) $(top_srcdir)/pyflag.in >pyflag.tmp
	chmod +x pyflag.tmp
	mv pyflag.tmp pyflag

clean-local:
	-rm -rf pyflag pyflagrc
