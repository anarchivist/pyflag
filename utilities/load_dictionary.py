""" A small script to load all 4 letter words or more from the english
dictionary into the dictionary table within pyflag """

import pyflag.DB as DB
import getopt,sys,os

#
# Usage
# 

def usage():
    print """This script loads a list of words into the pyflag
dictionary. These words will then be indexed during scanning.

  Usage: %s [options] dictionary.txt 

The dictionary is expected to have one word per line, for example

  andy
  andies
  andrews

Options:

  -c|--class	Specify a class for the words.  The default class is 'English'.
  -d|--drop	Drop old table before loading
  -r|--regex    Add entries as regular expressions rather than strings.
  -h|--help	Print help (this message)
  -v|--verbose	Be verbose
  """ % os.path.basename(sys.argv[0])
    sys.exit(2)

#
# Main routine
#

try:
    opts, args = getopt.getopt(sys.argv[1:], "rhdvc:", ["regex","help", "drop","verbose","class"])
except getopt.GetoptError:
    # print help information and exit:
    usage()
    sys.exit(2)

if not args:
    usage()
    sys.exit(1)

# option defaults

drop = False
verbose = False
wordclass = "English"
type="literal"

# parse options

for o, a in opts:
    if o in ("-c", "--class"):
        wordclass = a
    if o in ("-v", "--verbose"):
        verbose = True
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    if o in ("-d", "--drop"):
        drop = True
    if o in ("-r", "--regex"):
        type="regex"
        
print "wordclass is /%s/" % wordclass

dbh=DB.DBO(None)

if drop:
    print "Dropping old dictionary"
    dbh.execute("DROP TABLE dictionary")

dbh.execute(
    """ CREATE TABLE if not exists `dictionary` (
    `id` int auto_increment,
    `word` VARCHAR( 50 ) NOT NULL ,
    `class` VARCHAR( 50 ) NOT NULL ,
    `encoding` SET( 'all', 'asci', 'ucs16' ) NOT NULL,
    `type` set ( 'literal','regex' ),
    PRIMARY KEY  (`id`)
    )""")

count=0
for file in args[0:]:
    fd=open(file)
    print "Reading File %s" % file
    for line in fd:
        if len(line)>3 and not "'" in line:
            try:
                dbh.execute("insert into dictionary set word=%r,class=\"%s\",type=%r" % (line[:-1],wordclass,type))
                count+=1
            except DB.DBError:
                pass

            if (count % 1000) == 0:
                sys.stdout.write("Added %s words\r" % count)
                sys.stdout.flush()
                
    fd.close()
