#!/usr/bin/env python
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
"""
Loads a NSRL database into flag.

Use this program like so:

>>> pyflag_launch nsrl_load.py path_to_nsrl_directory/

An NSRL directory is one of the CDs, and usually has in it NSRLFile.txt,NSRLProd.txt.

IMPORTANT:
The first time the database is used (in loading a case) the index will be automatically built. This may take a long time, but is only done once.

You can build the index using the -i parameter.
"""
from optparse import OptionParser
import DB,conf,sys
import csv
import sys,os
import pyflag.conf
config=pyflag.conf.ConfObject()
import gzip

parser = OptionParser(usage="""%prog path_to_nsrl_directory path_to_nsrl_directory

Loads the NSRL hashes stored in the specified paths.""",
                      version="Version: %prog PyFlag "+config.VERSION)

parser.add_option("-d", "--db", default=None,
                  help = "The Database to load NSRL into")

parser.add_option('-i', '--index', default=False, action='store_true',
                  help = "Create indexes on the NSRL table instead")

parser.add_option('-r', '--reset',action="store_true", default=False,
                  help = "Drops (deletes) the NSRL tables from the database")

(options, args) = parser.parse_args()

dbh=DB.DBO(options.db)
dbh.cursor.ignore_warnings = True

#Get a handle to our database
if options.reset:
    print "Dropping NSRL tables"
    dbh.execute("drop table if exists NSRL_hashes")
    dbh.execute("drop table if exists NSRL_products")
    sys.exit(-1)

if options.index:
    print "Creating indexes on NSRL hashs (This could take several hours!!!)"
    dbh.check_index("NSRL_hashes","md5",4)
    print "Done!!"
    sys.exit(0)

def to_md5(string):
    result=[]
    for i in range(0,32,2):
        result.append(chr(int(string[i:i+2],16)))
    return "".join(result)

## First do the main NSRL hash table
def MainNSRLHash(dirname):
    try:
        file_fd = gzip.open(dirname+"/NSRLFile.txt.gz")
    except IOError:
        file_fd = open(dirname+"/NSRLFile.txt")
        
    ## Work out the size:
    try:
        file_fd.seek(0,2)
        size = file_fd.tell()
        file_fd.seek(0)
    except TypeError:
        size = None
    
    fd=csv.reader(file_fd)
    print "Starting to import %s/NSRLFile.txt" % dirname
    ## Ensure the NSRL tables do not have any indexes - this speeds up insert significantly
    try:
        dbh.execute("alter table NSRL_hashes drop index md5");
    except:
        pass

    count = 0
    dbh.mass_insert_start('NSRL_hashes')
    for row in fd:
        if size and not count % 10000:
            sys.stdout.write(" Progress %02u%% Done - %uk rows\r" % (file_fd.tell()*100/size,count/1000))
            sys.stdout.flush()
        count+=1

        try:
            dbh.mass_insert(
#                md5=to_md5(row[1]),
                ## This should be faster:
                md5=row[1].decode("hex"),
                filename=row[3],
                productcode=row[5],
                oscode=row[6],
                )
        except (ValueError,DB.DBError, TypeError),e:
            print "SQL Error skipped %s" %e
        except IndexError:
            continue

    dbh.mass_insert_commit()

## Now insert the product table:
def ProductTable(dirname):
    try:
        file_fd=gzip.open(dirname+"/NSRLProd.txt.gz")
    except IOError:
        file_fd=open(dirname+"/NSRLProd.txt")
        
    ## Work out the size:
    try:
        file_fd.seek(0,2)
        size = file_fd.tell()
        file_fd.seek(0)
    except TypeError:
        size = None
    
    fd=csv.reader(file_fd)
    print "Starting to import %s/NSRLProd.txt" % dirname
    ## Ensure the NSRL tables do not have any indexes - this speeds up insert significantly
    
    try:
        dbh.execute("alter table NSRL_products drop index Code");
    except:
        pass

    count = 0
    dbh.mass_insert_start('NSRL_products')
    for row in fd:
        if size and not count % 10000:
            sys.stdout.write(" Progress %02u%% Done - %uk rows\r" % (file_fd.tell()*100/size,count/1000))
            sys.stdout.flush()
        count+=1

        try:
            dbh.mass_insert(
                Code=row[0],
                Name=row[1],
                Version=row[2],
                OpSystemCode=row[3],
                ApplicationType=row[6],
                )
        except (TypeError, ValueError,DB.DBError),e:
            print "SQL Error skipped %s" %e

    dbh.mass_insert_commit()
        
if __name__=="__main__":
    if not args:
        print "You didn't specify any NSRL directories to operate on. Nothing to do!!!"
    else:
        dbh.execute("""CREATE TABLE if not exists `NSRL_hashes` (
          `md5` char(16) binary NOT NULL default '',
          `filename` varchar(250) NOT NULL default '',
          `productcode` int NOT NULL default 0,
          `oscode` varchar(250) NOT NULL default ''
        ) DEFAULT CHARACTER SET latin1 """)

        dbh.execute("""CREATE TABLE if not exists `NSRL_products` (
        `Code` MEDIUMINT NOT NULL ,
        `Name` VARCHAR( 250 ) NOT NULL ,
        `Version` VARCHAR( 250 ) NOT NULL ,
        `OpSystemCode` VARCHAR( 250 ) NOT NULL ,
        `ApplicationType` VARCHAR( 250 ) NOT NULL
        ) COMMENT = 'Stores NSRL Products'
        """)
        
        for arg in args:
            try:
                MainNSRLHash(arg)
            except IOError:
                print "Unable to read main hash db, doing product table only"

            ProductTable(arg)    
            print "You may wish to run this program with the -i arg to create indexes now. Otherwise indexes will be created the first time they are needed."
