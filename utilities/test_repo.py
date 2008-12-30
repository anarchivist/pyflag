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

""" This script is used to update the test repository """

import pyflag.conf, md5, zipfile
config = pyflag.conf.ConfObject()
import urllib2, sys, os
import pyflag.pyflaglog as pyflaglog
import plugins.Images as Images
import pyflag.FlagFramework as FlagFramework

config.set_usage(usage = """%prog [options]

update the test repository (The test repository is a repository of test images).
""")

config.add_option("repo", short_option='r', default="http://www.pyflag.net/images/testimages/",
                  help = 'The main repository to update against')

config.add_option("target", short_option='t', default=os.getcwd(),
                  help = 'The target directory to build in')

config.parse_options(True)

def parse_inventory():
    """ A function to obtain and parse the inventory """
    try:
        inventory_path = "%s/inventory" % config.REPO
        fd = urllib2.urlopen(inventory_path)
    except Exception, e:
        print e
        print "Unable to open %s - is this a real repository?" % inventory_path
        sys.exit(-1)

    result = []
    count = 0
    for line in fd.readlines():
        line = line.strip()
        count +=1
        if line.startswith("#"): continue

        columns = line.split()

        try:
            hash = columns[0]
        except: continue

        try:
            file = columns[1]
        except: continue

        try:
            action = " ".join(columns[2:])
        except: action = ''
        
        result.append(dict(hash = hash,
                           file = file,
                           action = action))

    return result

def copy(infd, outfd):
    while 1:
        data = infd.read(1024*1024)
        if len(data)==0: break
        
        outfd.write(data)

def create(path):
    """ Return a writable fd relative to the target repo with all
    intermediate directories created"""
    path = "%s/%s" % (config.target, path)
    dirname = os.path.dirname(path)
    try:
        os.makedirs(dirname)
    except: pass
    
    return open(path, 'w')

def resolve_path(url):
    """ Return a readable fd

    We support all the standard url schemes as well as local:// which
    means the localrepository.
    """
    if url.startswith("local://"):
        url = "file://%s/%s" % (config.REPO, url[len("local://"):])

    try:
        ## If url is an absolute name it can be opened now
        return urllib2.urlopen(url)
    except:
        ## Or else it was probably given relative to the repo:
        return urllib2.urlopen("%s/%s" % (config.REPO, url))
    
def process_file(file_record):
    """ Process the file given the file_record """
    try:
        action, arg = file_record['action'].split(None, 1)
    except:
        action = file_record['action']
        arg = None

    ## A direct copy of the source
    if action=='fetch' or action=='':
        path = arg or file_record['file']
        pyflaglog.log(pyflaglog.DEBUG, "Fetching %s" % path)
        copy(resolve_path(path),
             create(file_record['file']))

    elif action=='unzip':
        path = arg or file_record['file']
        pyflaglog.log(pyflaglog.DEBUG, "Unzipping %s" % path)
        copy(resolve_path(path),
             create(file_record['file']))

        fd = zipfile.ZipFile("%s/%s" % (config.TARGET, file_record['file']))
        for info in fd.infolist():
            if info.filename.endswith("/"): continue
            
            outfd = create(info.filename)
            pyflaglog.log(pyflaglog.DEBUG, "Extracting %s" % outfd.name)
            outfd.write(fd.read(info.filename))
            outfd.close()
                
    elif action=='ewfextract':
        ## We just grab the local file:
        if arg.startswith("local://"):
            path = "%s/%s" % (config.TARGET, arg[len("local://"):])
            pyflaglog.log(pyflaglog.DEBUG, "EWF Decompressing %s" % path)
            iosource = Images.EWF()
            infd = iosource.open(None, None,
                                 FlagFramework.query_type(filename = path))
            copy(infd,
                 create(file_record['file']))

    pyflaglog.log(pyflaglog.DEBUG, "Done")

inventory = parse_inventory() + [dict(hash = "-",
                                      file = "inventory",
                                      action = "fetch inventory"),]

for file_record in inventory:
    ## Check the md5sum to see if the file needs to be updated
    if file_record['hash'] != '-':
        try:
            m = md5.new()
            fd = open("%s/%s" % (config.target, file_record['file']))
            while 1:
                data = fd.read(1024 * 1024)
                if len(data)==0: break
                
                m.update(data)

            if file_record['hash'].lower() != m.hexdigest():
                process_file(file_record)
                
        except IOError:
            process_file(file_record)
    else:
        process_file(file_record)
