# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.87-pre1 Date: Tue Jun 10 13:18:41 EST 2008$
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
    Flag IO subsystem
    =================
    
    This module presents a file like object using the pyflag iosubsys
    module.

    The base Image class provides the 

"""
import iosubsys
import pexpect
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import query_type
import pyflag.conf
config=pyflag.conf.ConfObject()
import cPickle
import os,re
import pyflag.pyflaglog as pyflaglog
import pyflag.Store as Store
import pyflag.Registry as Registry
import sk
import pyflag.DB as DB

class Image:
    """ The image base class abstracts access to different types of images """
    ## This holds the global cache for all images
    mandatory_parameters = ['filename',]
    def form(self,query,result):
        """ This method is called to render a specialised form for
        this particular image
        """

    def open(self, name, case, query=None):
        """ This is a factory class for the Image. If query is None we
        try to retrieve our configuration parameters from the db.
        """

def IODrawForm(query, result, subsys='subsys'):
    """ draws the correct form on the result depending on the
    query['subsys']. Returns true if all parameters are filled in,
    False otherwise.
    """
    io=subsystems[query[subsys]]
    io = io(query, result, subsys)
    return io.form(query,result)

import pyflag.DB as DB

## This caches the io subsys
IO_Cache = Store.Store()


class FileHandler:
    """ This is a base class for handling files.

    PyFlag needs to access different kinds of files all the time. Its
    convenient to have a single function which can be used to access
    files regardless of the method. This is provided by implementors
    of this class.

    The open factory function below takes a URL to access the file in
    the form:

    method:/name/path

    where method is provided by the method property of this class, the
    name and path are both given to the constructor.
    """
    method = "file"

    def __init__(self, name, path):
        self.name = name
        self.path = path

    def open(self):
        """ This is called to return a file like handle to the
        resource
        """
        return None

url_re = re.compile("([^:]+)://([^/]*)(/.*)")

def open_URL(url):
    """ Uses the FileHandler methods to open the URL. """
    match = url_re.match(url)
    
    ## By default we use the URL as a file handler if it doesnt look
    ## like a proper URL
    if not match:
        method = 'file'
        path = url
        name = ''
    else:
        method = match.group(1)
        name = match.group(2)
        path = match.group(3)

    try:
        driver = Registry.FILE_HANDLERS.dispatch(method)
    except ValueError:
        raise RuntimeError("No handler for method %s" % method)
    
    return driver(name, path).open()

def open(case, iosource):
    """ Opens the named iosource from the specified case """
    ## Try to get it from the cache first:
    key = "%s|%s" % (case, iosource)
    
    try:
        image =IO_Cache.get(key)
    except KeyError:
        dbh = DB.DBO(case)
        dbh.execute("select name,parameters from iosources where name=%r",  iosource)
        row = dbh.fetch()
        if not row:
            raise IOError("IO Source (%r) not created yet" % key)
    
        query = query_type(string=row['parameters'])
        image = Registry.IMAGES.dispatch(query['subsys'])()
        IO_Cache.put(image, key=key)

    return image.open(iosource,case)

## IO subsystem unit tests:
import unittest
import md5,random,time

def test_read_random(io1,io2, size, sample_size, number):
    """ Tests if both ios return the same data for random input """
    for i in range(0,number):
        offset = long(random.random()*size)
        length = long(random.random()*sample_size)
        data1 = io1.read_random(length,offset)
        data2 = io2.read_random(length,offset)

        if data1!=data2:
            data1 = io1.read_random(length,offset)
            data2 = io2.read_random(length,offset)
            for i in range(len(data1)):
                if data1[i]!=data2[i]:
                    print "Error is at position %s" % i
                    raise IOError("Data read does not match. Offset %s. length %s iteration %s " % (offset,length,i))

        #print "Offset %s. length %s iteration %s " % (offset,length,i)
        
class IOSubsystemTests(unittest.TestCase):
    """ IO Subsystem tests """
    def test01LowerLevelSGZIP(self):
        """ Test lower level access to sgzip files """
        io = iosubsys.iosource([['subsys','sgzip'],
                            ['filename','%s/pyflag_stdimage_0.4.sgz' % config.UPLOADDIR]])
        m = md5.new()
        m.update(io.read_random(1000000,0))
        self.assertEqual(m.hexdigest(),'944d08ba21426b5821e759517bc68737')

    def test02HandlingErrors(self):
        """ test Handling of errors correctly """
        ## Tests errors in reading file:
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','sgzip'],
                                                           ['filename','/dev/null'],]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','sgzip'],
                                                           ['filename','/tmp/fgggsddfssdg'],]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','sgzip'],]))
        
        ## Test failour to open a file:
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','sgzip'],
                                                           ['filename','%s/pyflag_stdimage_0.4.dd' % config.UPLOADDIR],]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','ewf'],
                                                           ['filename','%s/pyflag_stdimage_0.4.dd' % config.UPLOADDIR],]))

        ## Test weird parameters:
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','raid'],
                                                           ['filename','%s/pyflag_stdimage_0.4.dd' % config.UPLOADDIR],]))
        
        ## Test weird values:
        self.assertRaises(RuntimeError, lambda : iosubsys.iosource([['subsys','standard'],
                                                                ['filename','/etc/passwd'],['offset',100]]))
        ## Negative Offsets:
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','advanced'],
                                                           ['filename','/etc/passwd'],['offset',-100]]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','sgzip'],
                                                           ['filename','%s/pyflag_stdimage_0.4.sgz' % config.UPLOADDIR],['offset',-100]]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','ewf'],
                                                           ['filename','%s/ntfs_image.e01' % config.UPLOADDIR],['offset',-100]]))

    def test03DataReadAccuracy(self):
        """ Test data accuracy in image decompression (takes a while) """
        io1 = iosubsys.iosource([['subsys','advanced'],
                             ['filename','%s/pyflag_stdimage_0.4.dd' % config.UPLOADDIR]])
        io2 = iosubsys.iosource([['subsys','sgzip'],
                             ['filename','%s/pyflag_stdimage_0.4.sgz' % config.UPLOADDIR]])
        io3 = iosubsys.iosource([['subsys','ewf'],
                             ['filename','%s/pyflag_stdimage_0.4.e01' % config.UPLOADDIR]])

        t = time.time()
        test_read_random(io1,io2, io1.size, 1000000, 200)
        print "Sgzip vs advanced took %s sec" % (time.time()-t)
        t = time.time()
        test_read_random(io1,io3, io1.size, 1000000, 200)
        print "EWF vs advanced took %s sec" % (time.time()-t)
