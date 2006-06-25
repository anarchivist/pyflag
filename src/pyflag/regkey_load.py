#!/usr/bin/env python
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
Loads a table of interesting registry keys into flag from a CSV File.

Default regkeys.txt is in data directory

"""

import DB,conf,sys
import csv
import re
import sys,os

if len(sys.argv)<2:
    print "Usage: %s path_to_regkey_csv_file.  Default regkeys.txt is in data directory\n" % os.path.basename(sys.argv[0])
    sys.exit(0)

#Get a handle to our database
dbh=DB.DBO(None)

#This is in db.setup - uncomment if you need it.
#dbh.execute("""CREATE TABLE `registrykeys` (
#	`id` int auto_increment,
#	`path` VARCHAR( 250 ) ,
#	`reg_key` VARCHAR( 200 ) ,
#	`category` VARCHAR( 100 ),
#	`description` VARCHAR( 200 ) ,
#	PRIMARY KEY  (`id`)
#)""")

if __name__=="__main__":

    try:
        filename = sys.argv[1]
        fd=csv.reader(file(filename))
    except (IndexError,IOError),e:
        print "Usage: %s path_to_regkey_csv_file.  Default regkeys.txt is in data directory\n" % sys.argv[0]
        sys.exit(0)
    print "Importing %s" % filename
    for row in fd:
        #Ignore comments
        if not (row[0].startswith('#')):
            #Replace backslashes with windows fwd slash
            path=row[0].replace('\\','/')
            #Take the key to be everything after the last /
            try:
            	key=path[path.rindex('/')+1:]
            except ValueError,e:
                print "Key should come after the last / here is the error: %s" %e
            #Remove the key section and trailing / to just leave the path
            path=path.replace(key,'')
            path=path.rstrip('/')
            #Also strip off the first string before the first / (including /) - flag doesn't handle HKLM HKCU etc. yet.
            try:
            	start=path[:path.index('/')+1]
            except ValueError,e:
                print "Key should come after the last / here is the error: %s" %e
            path=path.replace(start,'')
            try:
                dbh.execute("insert into registrykeys SET id=DEFAULT,path=%r,reg_key=%r,category=%r,description=%r",(path,key,row[1],row[2]))
            except (IndexError,ValueError,DB.DBError),e:
                print "SQL Error skipped %s. path: %s key: %s" %(e,path,key)
