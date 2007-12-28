SUBDIRS = lib mailtools indextools_ng network filesystems include pyflag remote mmedia

my_javascript		=       $(shell find javascript -not -name .\*)
nobase_pkgdata_DATA	=	$(my_javascript)
EXTRA_DIST		= 	$(nobase_pkgdata_DATA)

# main pyflag (python) application
## The pyflag directory goes in the system site-packages
pkgpython_PYTHON 	=	$(shell find pyflag -name \*.py -not -name .\* ) 

## The plugins go in site-packages/pyflag/
nobase_pkgpython_PYTHON 	=	$(shell find plugins -name \*.py -not -name .\*) \
				$(shell find FileFormats -name \*.py -not -name .\*)