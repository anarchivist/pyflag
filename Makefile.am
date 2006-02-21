SUBDIRS = src examples debian

my_images	 	=	\
				images/arrow_left_grey.gif images/arrow_right_grey.gif images/back.png images/broken.png \
				images/button_delete.xpm images/cornerplus.png images/corner.png images/defence.png \
				images/down.png images/examine.png images/favicon.ico images/flag.png images/floppy.png \
				images/folder.png images/forward.png images/functions.js images/g_back.png images/g_forward.png \
				images/glasses.png images/greenbarfill.gif images/greenbarleft.gif images/greenbarrgt.gif \
				images/help.png images/home_grey.png images/home.png images/logo.png images/menu.js \
				images/metbarend.gif images/metbarfill.gif images/metbarleft.gif images/msoffice.png \
				images/new_preset.png images/next_line.png images/no.png images/page.png images/pdf.png \
				images/pie.png images/pyflag_logo.png images/pyflag.png images/question.png images/red-plus.png \
				images/reset_grey.png images/reset.png images/sidebarleft.gif images/sidebarrgt.gif images/spacer.png \
				images/spanner.png images/stock_down-with-subpoints.png images/stock_left_gray.png images/stock_left.png \
				images/stock_next-page.png images/stock_previous-page.png images/stock_right_gray.png images/stock_right.png \
				images/stop.png images/topfill.jpg images/unknown.png images/up.png images/whois.png images/yes.png
my_data			=	data/db.setup data/magic data/magic.mime data/regkeys.txt

bin_SCRIPTS		=	pyflag pyflash pyflag_launch
sysconf_DATA		=	pyflagrc
pkgdata_DATA		=	$(my_data)
nobase_pkgdata_DATA	=	$(my_images)
#This breaks the make, but all the doco says this is how to do it.  No man page for now.
man_MANS		=	pyflag.1
EXTRA_DIST		=	pyflag.in pyflagrc.in pyflash.in \
				pyflag_launch.in $(my_images) $(my_data) $(man_MANS)

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
	dpkg-buildpackage -rfakeroot

