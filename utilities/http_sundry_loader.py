# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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

""" This utility allows users to download sundry HTTP objects to
improve page rendering
"""
import pyflag.conf
config = pyflag.conf.ConfObject()
import pyflag.DB as DB
import sys,urllib
import shutil

config.set_usage(usage = """%prog --case casename regex

Will download all the missing objects from the sundry table into case casename.

NOTE: We will be making web requests to the missing objects, make sure
you understand the ramifications of this. This is mostly suitable only
for static objects.
""", version = "Version: %%prog PyFlag %s" % config.VERSION)

config.add_option("case", default=None,
                  help = "The case to load (mandatory)")

config.add_option("copy", default=None,
                  help = "The case to copy to. If this is specified, we just copy all the sundry objects from the specified case to this one")

config.add_option("list", short_option='l', default=False, action='store_true',
                  help = "List the urls matching the regexes but do not fetch them")

config.parse_options(True)

if not config.case:
    print "You must select a case..."
    sys.exit(1)

def make_filename(id, case):
    return "%s/case_%s/xHTTP%s" % (config.RESULTDIR, case, id)

dbh = DB.DBO(config.case)
if config.copy:
    dest_dbh = DB.DBO(config.copy)
    dbh.execute("select *  from http_sundry")
    for row in dbh:
        original_id = row['id']
        
        ## We need to reorder the sundry objects into the inode table
        ## ids and thus get a new inode id:
        dest_dbh.insert("inode", inode = "x", _fast=True)
        inode_id = dest_dbh.autoincrement()
        dest_dbh.execute("update inode set inode = 'xHTTP%s' where inode_id = %s " %(inode_id, inode_id))
        row['id'] = inode_id
        
        dest_dbh.insert("http_sundry", **row)
        ## Now copy the file:
        src = make_filename(original_id, config.case)
        dest = make_filename(inode_id, config.copy)

        print "Copying %s to %s" % (src,dest)
        shutil.copy(src, dest)

    sys.exit(0)
        

dbh2 = DB.DBO(config.case)
if config.list:
    for regex in config.args:
        dbh.execute("select url from http_sundry where url rlike %r and present='no'", regex)
        for row in dbh:
            print row['url']

    sys.exit(0)

for regex in config.args:
    dbh.execute("select id,url from http_sundry where url rlike %r and present='no'", regex)
    for row in dbh:
        new_filename = make_filename(row['id'], config.case)
        print "Retriving %s into %s" % (row['url'], new_filename) ,
        try:
            url = urllib.unquote(row['url'])
            filanem, headers = urllib.urlretrieve(url, new_filename)
            dbh2.update("http_sundry", where="id = %s" % row['id'],
                       _fast = True,
                       present = 'yes')
            print "Ok"
        except Exception,e:
            print "Error: %s" % e
