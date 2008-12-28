#!/usr/bin/env python
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
import pyflag.Registry as Registry

config.set_usage(usage="""%prog path_to_nsrl_directory path_to_nsrl_directory

Loads the NSRL hashes stored in the specified paths.""",
                      version="Version: %prog PyFlag "+str(config.VERSION))

config.add_option('index', short_option='i', default=False,
                  action='store_true',
                  help = "Create indexes on the NSRL table instead")

config.add_option('reset', short_option='r', action="store_true",
                  default=False,
                  help = "Drops (deletes) the NSRL tables from the database")

config.add_option('stats' , short_option='s', action='store_true',
                  default = False,
                  help = "Prints statistics about the NSRL database loaded")

Registry.Init()
config.parse_options()

try:
    dbh = DB.DBO(config.hashdb)
    ## Check for the tables
    dbh.execute("desc NSRL_hashes")
    for row in dbh: pass
    dbh.execute("desc NSRL_products")
    for row in dbh: pass
except Exception,e:
    ## Check if the nsrl db exists:
    hash_table_event_handler = Registry.EVENT_HANDLERS.dispatch("HashTables")()
    hash_table_event_handler.init_default_db(DB.DBO(),None)
    dbh = DB.DBO(config.hashdb)

dbh.cursor.ignore_warnings = True

if config.stats:
    dbh.execute("select count(*) as c from NSRL_hashes")
    hashes = dbh.fetch()['c']
    dbh.execute("select count(*) as c from NSRL_products")
    products = dbh.fetch()['c']

    print "There are %s hashes and %s products loaded" % (hashes, products)
    sys.exit(0)

#Get a handle to our database
if config.reset:
    print "Dropping NSRL tables"
    dbh.execute("delete from NSRL_hashes")
    dbh.execute("delete from NSRL_products")
    sys.exit(-1)

if config.index:
    print "Creating indexes on NSRL hashs (This could take several hours!!!)"
    dbh.check_index("NSRL_hashes","md5",4)
    print "Done!!"
    sys.exit(0)

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
                ## This should be faster:
                __md5=row[1].decode("hex"),
                filename=row[3].decode("utf8","ignore")[:60],
                productcode=row[5],
                oscode=row[6], 
                )
        except (ValueError,DB.DBError, TypeError),e:
            result = "SQL Error skipped %s" % e
            print result
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
    if not config.args:
        print "You didn't specify any NSRL directories to operate on. Nothing to do!!!"
        sys.exit(0)
        
    for arg in config.args:
        try:
            MainNSRLHash(arg)
        except IOError:
            print "Unable to read main hash db, doing product table only"
            
        ProductTable(arg)    
        print "You may wish to run this program with the -i arg to create indexes now. Otherwise indexes will be created the first time they are needed."
