""" A small script to load all 4 letter words or more from the english
dictionary into the dictionary table within pyflag """

import pyflag.DB as DB
import sys,os

if len(sys.argv)<2:
    print "This script loads a dictionary of words into the pyflag word dictionary. These words will then be indexed during scanning.\n\nUsage: %s [Dictionary files]\n" % os.path.basename(sys.argv[0])
    sys.exit(0)

dbh=DB.DBO(None)
dbh.execute("CREATE TABLE if not exists `dictionary` (`word` VARCHAR( 50 ) NOT NULL ,`class` VARCHAR( 50 ) NOT NULL ,`encoding` SET( 'all', 'asci', 'ucs16' ) NOT NULL,PRIMARY KEY  (`word`))")

count=0
for file in sys.argv[1:]:
    fd=open(file)
    print "Reading File %s" % file
    for line in fd:
        if len(line)>3 and not "'" in line:
            try:
                dbh.execute("insert into dictionary set word=%r,class=\"English\";" % line[:-1])
                count+=1
            except DB.DBError:
                pass

            if (count % 1000) == 0:
                sys.stdout.write("Added %s words\r" % count)
                sys.stdout.flush()
                
    fd.close()
