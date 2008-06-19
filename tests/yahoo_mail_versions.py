#!/usr/bin/env python
""" A script which goes through a case and reports the yahoo mail
version encountered
"""
import pyflag.Registry as Registry
import pyflag.conf
config = pyflag.conf.ConfObject()
from optparse import OptionParser
import sys, re
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
import FileFormats.HTML as HTML

Registry.Init()

config.set_usage(usage = """%prog [options]

Detect Yahoo mail versions.  """)

config.add_option('case', short_option='c', default=None, help='Case to inspect')
config.add_option('inode',short_option='i', default=None, help='Only test this inode')

config.parse_options()

if not config.case:
    print "You must specify a case"
    sys.exit(1)

## Get a handle to the YahooMailScan scanner for testing
YahooMailScan = Registry.SCANNERS.dispatch("YahooMailScan")

## Dynamically patch the class for instrumentation - gotta love
## python...
def insert_message(self, result, inode_template = "l%s"):
    ## We dont really want to touch the db in here - just print it out
    ## nicely:
    try:
        ## Try to render the html as text:
        message = unicode(result['Message'])
        p = HTML.HTMLParser(tag_class = HTML.TextTag)
        p.feed(message)
        p.close()

        result['Message'] = p.root.__str__()
        
    except KeyError:
        pass
    
    for k,v in result.items():
        print "   %s: %r" % (k,v)

    return True

def test_inode(inode_id, url, factory, fsfd):
    print "-----------------------------"
    print "Inode_id = %s" % inode_id
    print "URL = %s" % url
    fd = fsfd.open(inode_id = inode_id)
    data = fd.read()

    m=re.search(r"<!-- (v\d+\.\d+\.\d+) (\d+) -->", data)
    if m:
        print "Version %s - Released %s" % (m.group(1), m.group(2))
    else:
        print "*** Warning - Unexpected page found possible version change"

    fd.seek(0)
    ## Let the scanner do it:
    scanner = factory.Scan(fd.inode, fsfd, factory, factories=[factory,], fd=fd)
    scanner.process(data, metadata = {})
    scanner.finish()
            
YahooMailScan.Scan.insert_message = insert_message

fsfd = FileSystem.DBFS(config.case)
factory = YahooMailScan(fsfd)

if config.inode:
    path, inode, inode_id = fsfd.lookup(inode = config.inode)
    test_inode(inode_id, '', factory, fsfd)
else:
    dbh = DB.DBO(config.case)
    dbh.execute("select * from http where url like '%yahoo.com/ym/%'")

    for row in dbh:
        if not row['inode_id']: continue
        test_inode(row['inode_id'], row['url'], factory, fsfd)
