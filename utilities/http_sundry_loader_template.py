#!/usr/bin/env python
# download a list of URLs into a zip archive. A base64 encoded version of the
# URL is used as the filenames in the archive

import urllib
import zipfile
import sys

# downloads is a list of URLs
downloads = """
http://www.pyflag.net
"""

if len(sys.argv) < 2:
	print "Usage: %s zipfile" % sys.argv[0]
	sys.exit(0)

zfilename = sys.argv[1]
zfile = zipfile.ZipFile(zfilename, "w", compression=zipfile.ZIP_DEFLATED)

for line in downloads.splitlines():
    if not line: continue

    print "Downloading: %s" % line
    try:
        data = urllib.urlopen(urllib.unquote(line))
        zfile.writestr(line.encode("base64"), data.read())
    except IOError, e:
        print "Download Failed: %s" % e

zfile.close()

print "Data saved into %s, import using: http_sundry_loader.py --case casename --load %s" % (zfilename, zfilename)
