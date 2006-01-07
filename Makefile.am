SUBDIRS = src

# main pyflag (python) application
# not sure how to do this recursively
# might just have to maintain this list
pkgpython_PYTHON	= 	pyflag/*.py \
				pyflag/FileFormats/*.py

nobase_pkgpython_PYTHON = 	plugins/*.py \
				plugins/Flash/*.py \
				plugins/NetworkForensics/*.py \
				plugins/NetworkForensics/ProtocolHandlers/*.py \
				plugins/LogAnalysis/*.py \
				plugins/DiskForensics/*.py \
				plugins/DiskForensics/FileHandlers/*.py \
				plugins/DiskForensics/FileSystems/*.py \
				plugins/Themes/*.py

nobase_pkgdata_DATA	=	images/*
