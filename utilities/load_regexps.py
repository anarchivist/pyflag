#! /usr/bin/python
# $Id: load_regexps.py,v 1.2 2005/02/24 14:28:34 george Exp george $
#
# $Log: load_regexps.py,v $
# Revision 1.2  2005/02/24 14:28:34  george
# * Added command line options parsing
# * Allow drop of old table with "-d"
# * Updated usage message
# * Print items loaded during verbose
#
# Revision 1.1  2005/02/24 14:12:43  george
# Initial revision
#

""" A small script to load a list of regular expresions
into the regexp table within pyflag """

import pyflag.DB as DB
import getopt,sys,os

def usage():
    print """This script loads a list of named regular expressions into the pyflag
regular expression table. These regular expressions will then be indexed
during scanning.

  Usage: %s [options] RegExpFile

The format of the regexp file is:

  OneWordDescrition Regexp

for example

  IPAddress \d+\.\d+\.\d+\.\d+
  EmailAddress \w+@[\w\.]+\n

Options:

  -d|--drop	Drop old regexp table before loading
  -h|--help	Print help (this message)
  -v|--verbose	Be verbose
  """ % os.path.basename(sys.argv[0])
    sys.exit(2)

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdv", ["help", "drop","verbose"])
    except getopt.GetoptError:
        # print help information and exit:
        usage()
        sys.exit(2)

    if not args:
        usage()
        sys.exit(1)
        
    drop = False
    verbose = False
    for o, a in opts:
        if o in ("-v", "--verbose"):
            verbose = True
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        if o in ("-d", "--drop"):
            drop = True

    dbh=DB.DBO(None)

    if drop:
        print "Dropping old regexps table"
        dbh.execute("DROP TABLE regexps")
    
    dbh.execute("CREATE TABLE if not exists `regexps` (`pattern` VARCHAR( 50 ) NOT NULL ,`class` VARCHAR( 50 ) NOT NULL ,`encoding` SET( 'all', 'asci', 'ucs16' ) NOT NULL,PRIMARY KEY  (`pattern`))")


    count=0
    for file in args[0:]:
        fd=open(file)
        print "Reading File %s" % file
        for line in fd:
            line = line.strip();
            myclass,pattern = line.split(None,1)
            
            if (myclass != "") and (pattern != ""):
                try:
                    dbh.execute("insert into regexps set class=%r,pattern=%r;", (myclass, pattern))
                    count+=1
                    if verbose:
                        print "Added class=%s,pattern=%s" % (myclass,pattern)
                except DB.DBError:
                    pass
                
                if (count % 1000) == 0:
                    sys.stdout.write("Added %s words\r" % count)
                    sys.stdout.flush()
                    
                    fd.close()
                    
                    sys.stdout.write("Added %s words\rDone\r" % count)
                    sys.stdout.flush()
                    
if __name__ == "__main__":
    main()
