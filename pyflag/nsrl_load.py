#!/usr/bin/env python
"""
Loads a NSRL database into flag.

Use this program like so:

>>> nsrl_load.py path_to_nsrl_directory/

An NSRL directory is one of the CDs, and usually has in it NSRLFile.txt,NSRLProd.txt.

IMPORTANT:
The first time the database is used (in loading a case) the index will be automatically built. This may take a long time, but is only done once.
"""

import DB,conf,sys
import csv
import sys,os

if len(sys.argv)<2:
    print "Usage: %s path_to_nsrl_directory\n\nAn NSRL directory is one of the CDs, and usually has in it NSRLFile.txt,NSRLProd.txt.\n" % os.path.basename(sys.argv[0])
    sys.exit(0)
    
#Get a handle to our database
dbh=DB.DBO(None)
dbh.execute("""CREATE TABLE if not exists `NSRL_hashes` (
  `md5` char(16) NOT NULL default '',
  `filename` varchar(60) NOT NULL default '',
  `productcode` int NOT NULL default '',
  `oscode` varchar(60) NOT NULL default ''
)""")

dbh.execute("""CREATE TABLE if not exists `NSRL_products` (
`Code` MEDIUMINT NOT NULL ,
`Name` VARCHAR( 250 ) NOT NULL ,
`Version` VARCHAR( 20 ) NOT NULL ,
`OpSystemCode` VARCHAR( 20 ) NOT NULL ,
`ApplicationType` VARCHAR( 250 ) NOT NULL
) COMMENT = 'Stores NSRL Products'
""")

try:
    dirname = sys.argv[1]
except IndexError:
    print "Usage: %s path_to_nsrl" % sys.argv[0]
    sys.exit(0)

def to_md5(string):
    result=[]
    for i in range(0,32,2):
        result.append(chr(int(string[i:i+2],16)))
    return "".join(result)

## First do the main NSRL hash table
def MainNSRLHash(dirname):
    fd=csv.reader(file(dirname+"/NSRLFile.txt"))
    print "Starting to import %s/NSRLFile.txt" % dirname
    ## Ensure the NSRL tables do not have any indexes - this speeds up insert significantly
    try:
        dbh.execute("alter table NSRL_hashes drop index md5");
    except:
        pass

    for row in fd:
        try:
            dbh.execute("insert into NSRL_hashes set md5=%r,filename=%r,productcode=%r,oscode=%r",(to_md5(row[1]),row[3],row[5],row[6]))
        except (ValueError,DB.DBError),e:
            print "SQL Error skipped %s" %e

## Now insert the product table:
def ProductTable(dirname):
    fd=csv.reader(file(dirname+"/NSRLProd.txt"))
    print "Starting to import %s/NSRLProd.txt" % dirname
    ## Ensure the NSRL tables do not have any indexes - this speeds up insert significantly
    
    try:
        dbh.execute("alter table NSRL_products drop index Code");
    except:
        pass
    
    for row in fd:
        try:
            dbh.execute("insert into NSRL_products set Code=%r,Name=%r,Version=%r,OpSystemCode=%r,ApplicationType=%r",(row[0],row[1],row[2],row[3],row[6]))
        except (ValueError,DB.DBError),e:
            print "SQL Error skipped %s" %e

if __name__=="__main__":
    MainNSRLHash(dirname)
    ProductTable(dirname)    
    print "You may wish to run this program with the -i arg to create indexes now. Otherwise indexes will be created the first time they are needed."
