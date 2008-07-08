#!/usr/bin/env python
# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
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

""" This utility allows users to download sundry HTTP objects to
improve page rendering
"""
import pyflag.conf
config = pyflag.conf.ConfObject()
import pyflag.DB as DB
import sys,urllib
import shutil
import zipfile
import pyflag.FileSystem as FileSystem


config.set_usage(usage = """%prog --case casename [--offline scriptfile] regex
       %prog --case casename --load zipfile

Will download all the missing objects from the sundry table into case casename.

The --offline arguement will generate a stand-alone python script which can be
used on another (internet-connected) computer. The zipfile can then be loaded
using this program with the --load arguement.

NOTE: We will be making web requests to the missing objects, make sure
you understand the ramifications of this. This is mostly suitable only
for static objects.
""", version = "Version: %%prog PyFlag %s" % config.VERSION)

config.add_option("case", default=None,
                  help = "The case to load (mandatory)")

config.add_option("copy", default=None,
                  help = "The case to copy to. If this is specified, we just copy all the sundry objects from the specified case to this one")

config.add_option("offline", short_option='o', default=False, action='store_true',
                  help = "Generate a script for retrieval from an internet-connected machine (does not require pyflag)")

config.add_option("load", short_option='i', default=False, action='store_true',
                  help = "import a sundry archive generated using an offline script")

config.add_option("export", default=None, 
                  help = "A filename to export the sundry from the current case. The file will be a zip file suitable for use with --load")

config.add_option("list", short_option='l', default=False, action='store_true',
                  help = "List the urls matching the regexes but do not fetch them")

config.parse_options(True)

if not config.case:
    print "You must select a case..."
    sys.exit(1)

def make_filename(id, case):
    return "%s/case_%s/xHTTP%s" % (config.RESULTDIR, case, id)

dbh = DB.DBO(config.case)
if config.export:
    ## Export the sundry objects into a zip file
    zfile = zipfile.ZipFile(config.export, "w", compression=zipfile.ZIP_DEFLATED)
    dbh.execute("select * from http_sundry")
    for row in dbh:
        if row['present']=='yes':
            try:
                fd = open(make_filename(row['id'], config.case))
                zfile.writestr(row['url'].encode("base64"), fd.read())
                fd.close()
            except IOError,e:
                print "Skipping %s: %s" % (row['id'], e)

    sys.exit(0)
    
elif config.copy:
    dest_dbh = DB.DBO(config.copy)
    dbh.execute("select *  from http_sundry")
    for row in dbh:
        original_id = row['id']

        ## Check if the destination case already has it in its sundry table
        dest_dbh.execute("select id from http_sundry where url = %r and present='yes' limit 1", row['url'])
        tmp_row = dest_dbh.fetch()
        if tmp_row: continue

        ## Maybe its in the http table?
        dest_dbh.execute("select inode_id from http where url = %r and inode_id>0 limit 1", row['url'])
        tmp_row = dest_dbh.fetch()
        if tmp_row: continue
        
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
        try:
            shutil.copy(src, dest)
        except IOError:
            print "Failed"

    sys.exit(0)
        

if config.list:
    for regex in config.args:
        dbh.execute("select url from http_sundry where url rlike %r and present='no'", regex)
        for row in dbh:
            print row['url']

    sys.exit(0)

if config.offline:
    urls = []
    regex_list = config.args[1:] or [".*"]
    for regex in regex_list:
        dbh.execute("select url from http_sundry where url rlike %r and present='no'", regex)
        urls += [ row['url'] for row in dbh ]

    # read the template
    fd = open("%s/utilities/http_sundry_loader_template.py" % config.datadir)
    template = fd.read()
    fd.close()

    # sub in the URLS
    template = template.replace("http://www.pyflag.net", "\n".join(urls))

    # write out the script
    fd = open(config.args[0], "w")
    fd.write(template)
    fd.close()

    print "Written download script to: %s" % config.args[0]
    sys.exit(0)

dbh2 = DB.DBO(config.case)
if config.load:
    zfile = zipfile.ZipFile(config.args[0])
    namelist = zfile.namelist()

    sundry = {}
    fsfd = FileSystem.DBFS(config.case)
    dbh.execute("select * from http_sundry")
    for row in dbh:
        sundry[row['url']] = row['id']

    for name in zfile.namelist():
    	url = name.decode("base64")
    	if url in sundry:
            filename = make_filename(sundry[url], config.case)
            dbh2.update("http_sundry", where="id = %s" % sundry[url],
                       _fast = True,
                       present = 'yes')
        else:
            ## Sundry object does not exist, we need to VFSCreate it
            filename = make_filename(dbh2.autoincrement(), config.case)
            
            ## Make a null call to get an inode id
            inode_id = fsfd.VFSCreate(None, None, None)

            ## Use the id to really insert now
            fsfd.VFSCreate(None, "xHTTP%s" % inode_id, "/_Sundry_/xHTTP%s" % inode_id,
                           inode_id = inode_id, update_only = True)

            ## Update the sundry table
            dbh2.insert("http_sundry", id=inode_id, url=url, present="yes")

        print "Writing %s into %s" % (url, filename)
        fd = open(filename, "w")
        fd.write(zfile.read(name))
        fd.close()

    zfile.close()
    sys.exit()

for regex in config.args:
    dbh.execute("select id,url from http_sundry where url rlike %r and present='no'", regex)
    for row in dbh:
        new_filename = make_filename(row['id'], config.case)
        print "Retriving %s into %s" % (row['url'], new_filename)
        try:
            url = urllib.unquote(row['url'])
            filanem, headers = urllib.urlretrieve(url, new_filename)
            dbh2.update("http_sundry", where="id = %s" % row['id'],
                       _fast = True,
                       present = 'yes')
            print "Ok"
        except Exception,e:
            print "Error: %s" % e
