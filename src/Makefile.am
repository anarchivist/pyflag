SUBDIRS = lib mailtools indextools_ng indextools network regtools virustools filesystems include
#SUBDIRS = lib mailtools indextools network regtools virustools filesystems include

# main pyflag (python) application
## The pyflag directory goes in the system site-packages
pkgpython_PYTHON 	=	$(shell find pyflag -name \*.py -not -name .\* )

## The plugins go in site-packages/pyflag/
nobase_pkgpython_PYTHON 	=	$(shell find plugins -name \*.py -not -name .\*) \
				$(shell find FileFormats -name \*.py -not -name .\*)