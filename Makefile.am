SUBDIRS = src

bin_SCRIPTS		=	pyflag pyflash pyflag_launch
sysconf_DATA		=	pyflagrc
pkgdata_DATA		=	data/magic data/magic.mime data/db.setup
nobase_pkgdata_DATA	=	images/*
EXTRA_DIST		=	pyflag.in pyflagrc.in pyflash.in \
				pyflag_launch.in images/* data/* _darcs/*

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
	-e 's,@magic\@,@magic@,g' \
	-e 's,@python\@,$(PYTHON),g'

%: $(top_srcdir)/%.in Makefile
	rm -f $@ $@.tmp
	$(edit) $< > $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@

clean-local:
	-rm -rf $(bin_SCRIPTS)
