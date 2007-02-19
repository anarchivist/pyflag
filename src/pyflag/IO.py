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
#  Version: FLAG  $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
    
    This module presents a file like object using the python iosubsys
    module.
"""
import iosubsys
import pexpect
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import cPickle
import os,re
import pyflag.pyflaglog as pyflaglog
import pyflag.Store as Store

import sk

def mmls_popup(query,result,orig_query=None, subsys=None, offset=None):
    result.decoration = "naked"
    
    del orig_query['io_offset']
    io = IOFactory(orig_query)
    try:
        parts = sk.mmls(io)
    except IOError, e:
        result.heading("No Partitions found")
        result.text("Sleuthkit returned: %s" % e)
        return

    result.heading("Possible IO Sources")
    result.start_table(border=True)
    result.row("Chunk", "Start", "End", "Size", "Description")
    del query[offset]
    for i in range(len(parts)):
        new_query = query.clone()
        tmp = result.__class__(result)
        new_query[offset] = "%ds" % parts[i][0]
        tmp.link("%010d" % parts[i][0], new_query, pane='parent')
        result.row(i, tmp, "%010d" % (parts[i][0] + parts[i][1]), "%010d" % parts[i][1] , parts[i][2])
    result.end_table()
        
class IO:
    """ class for IO subsystem, provides basic contructor and read/seek functions

    This returns file-like objects for use in other python code. This object behaves as follows:

          1) The init method gets called,
          2) if the parameters are bad (i.e. an IO subsystem can not be initialised with them),
                - the form is written on the result.
                - it raises an error and fails to create the object
          4) if the parameters are good, it writes the form again on the result, and returns

    Callers of this object should be prepared to catch IOError exceptions in case this object fails to instantiate. If callers suppy a ui object for result, a form will be drawn on the ui object to assist the user with selecting appropriate parameters for this IO subsystem.

    @Note: The actual subsystem that will be instatiated is query[subsys].
    """
    readptr=0
    parameters=()
    options = []

    def make_parameter_list(self):
        """ Returns a parameter list formatted as parameter=value,parameter=value """
        return ','.join([ '%s=%s' % (k,v) for (k,v) in self.options])

    def set_options(self,key,value):
        """ Sets key and value to the subsystem """

    def get_options(self):
        """ returns a marshalled representation of options to cache in the database """
        return cPickle.dumps(self.options)
        
    def form(self,query,result):
        """ Draw a form in result (ui object) to obtain all the needed parameters from query """

    def __init__(self, query=None,result=None,subsys='subsys',options=None, clone=None):
        """ initialise the object before use.

        if clone is specified we clone the object specified which is also an IO object.
        """
        if clone:
            self.options = clone.options
            self.io = clone.io
            self.size = clone.size
            
            return
        
        try:
            if not options:
                options = []
                for i in self.parameters:
                    for j in query.getarray(i):
                        if i.startswith('io_'):
                            i=i[3:]
                        options.append([i, j])
                        
            self.options = options

            #Try and make the subsystem based on the args
            self.io=iosubsys.iosource(options)
            self.size = self.io.size

            if not self.io:
                raise IOError("Unable to open iosource")
#                print "ERROR: %s" % e

            self.readptr = 0
            
        except (KeyError, IOError, RuntimeError):
            if(query and result):
                self.form(query,result)
            raise
            
        if(query and result):
            self.form(query,result)
  
    def seek(self, offset, whence=0):
        """ fake seeking routine """
        if whence==0:
            readptr = offset
        elif whence==1:
            readptr+=offset
        elif whence==2:
            readptr = self.size

        if readptr<0:
            raise IOError("Seek before start of file")
        self.readptr = readptr

    def tell(self):
        """ return current read pointer """
        return self.readptr

    def read(self, length=None):
        """ read length bytes from subsystem starting at readptr """            
        if length==None:
            return ""
        buf = self.io.read_random(length,self.readptr)
        self.readptr += len(buf)
        return buf

    def close(self):
        """ close subsystem """
        pass
      
#    def set_options(self,key,value):
#        iosubsys.parse_options(self.io,"%s=%s" % (key[3:],value))

    def explain(self,result):
        """ Give some information about our IO Source """
        result.row("IOSubsys Driver", self.__class__.__name__)
        for i in range(len(self.parameters)-1):
            for j in range(len(self.options[i+1])):
                tmp = result.__class__(result)
                tmp.text(self.options[i+1][j], color="red", font="bold")
                result.row(self.parameters[i+1][3:], tmp, valign="top")

    def __getitem__(self, name):
        """ allow dictionary style option access """
        for k,v in self.options:
            if k == name:
                return v
        raise KeyError, name

class sgzip(IO):
    parameters=('subsys','io_filename','io_offset')

    def form(self,query,result):
        if not query.has_key('io_offset'):
            query['io_offset']='0'
        result.fileselector("Select %s image:" % self.__class__.__name__.split(".")[-1], name="io_filename")

        tmp = result.__class__(result)
        tmp2 = result.__class__(result)
        tmp2.popup(
            FlagFramework.Curry(mmls_popup,orig_query=query,
                                subsys=query['subsys'],
                                offset="io_offset"),
            "Survey the partition table",
            icon="examine.png")

        tmp.row(tmp2,"Enter partition offset:")
        result.textfield(tmp,'io_offset')
  
class standard(sgzip):
    parameters=('subsys','io_filename')

class raid(sgzip):
    """ Subsystem used to access raid devices """
    parameters=('subsys','io_filename','io_blocksize','io_slots','io_map','io_offset')

    def form(self,query,result):
        sgzip.form(self,query,result)
        result.textfield("Blocksize:",'blocksize')
        result.textfield("Numberr of slots:",'slots')
        result.para("The map is given as a set series of logical blocks delimited with . and with P for the parity block (e.g. 0.1.2.3.4.5.P.P.6.7.8.9.10.11.17.P.12.13.14.15.16.22.23.P.18.19.20.21.27.28.29.P.24.25.26.32.33.34.35.P.30.31.37.38.39.40.41.P.36)")
        result.textfield("map:",'map')

class advanced(sgzip):
    parameters=('subsys','io_filename','io_offset')

class remote(IO):
    parameters=('subsys','io_host','io_user','io_server_path','io_device')

    def form(self,query,result):
        if not query.has_key('io_offset'):
            query['io_offset']='0'

        result.textfield("Host",'io_host');
        result.textfield("User to logon as:",'io_user')
        result.textfield("Full servlet path:",'io_server_path')
        result.textfield("Remote device:",'io_device')
        

class ewf(sgzip):
    parameters=('subsys','io_filename','io_offset')
    
class mounted(IO):
    parameters=('subsys','io_directory')

    def form(self,query,result):
        result.text("Note that you must have full read permissions for the mounted directory. You may need to run pyflag as root for this!!!",color="red")
        result.textfield("Enter mount point:",'io_directory')

    def read(self, length=None):
        raise FlagFramework.FlagException("Reading of raw mounted IOSources does not make sense - You probably want to load the raw image file as a standard IOSubsystem !!!")

    def __init__(self, query=None,result=None,subsys='subsys',options=None):
        """ Here we implement a dumb constructor which just checks if the directory is valid """
        if not options:
            options=tuple([query.getarray(i) for i in self.parameters])

        self.options = options
        if(query and result):
            self.form(query,result)

        try:
            self.mount_point=self.options[1][0]
            os.listdir(self.mount_point)
        except OSError,e:                
            raise IOError("%s"%e)
        except IndexError:
            raise KeyError

def IOFactory(query,result=None, subsys='subsys'):
    """ Dispatcher for the correct form depending on query['subsys'] """
    io=subsystems[query[subsys]]
    return io(query,result,subsys)

import pyflag.DB as DB

subsystems=FlagFramework.query_type([
            ('advanced',advanced),
            ('sgzip',sgzip),
            ('ewf',ewf),
            ('standard',standard),
            ('mounted',mounted),
            ## This is currently broken
#            ('remote',remote),
            ('raid',raid),
            ])

del subsystems['case']

## This caches the io subsys
IO_Cache = Store.Store()

def open(case, iosource):
    """ lookup iosource in database and return an IO object.

    This uses function memoization to speed it up.
    """
    try:
        type, io_obj = IO_Cache.get("%s|%s" % (case,iosource))
        io=subsystems[type](clone=io_obj)
        io.name = iosource
        return io
    except KeyError:
        dbh = DB.DBO(case)
        try:
            optstr = dbh.get_meta(iosource)
        except TypeError:
            raise IOError, "Not a valid IO Data Source: %s" % iosource

        if not optstr:
            raise IOError("IO source %s not found" % iosource)
        # unmarshal the option tuple from the database
        opts = cPickle.loads(optstr)
        io=subsystems[opts[0][1]](options=opts)
        io.name = iosource

        ## Cache the option string:
        IO_Cache.put((opts[0][1], io),key = "%s|%s" % (case,iosource))
        return io
 
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
                            ['filename','%s/pyflag_stdimage_0.2.sgz' % config.UPLOADDIR]])
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
                                                           ['filename','%s/pyflag_stdimage_0.2' % config.UPLOADDIR],]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','ewf'],
                                                           ['filename','%s/pyflag_stdimage_0.2' % config.UPLOADDIR],]))

        ## Test weird parameters:
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','raid'],
                                                           ['filename','%s/pyflag_stdimage_0.2' % config.UPLOADDIR],]))
        
        ## Test weird values:
        self.assertRaises(RuntimeError, lambda : iosubsys.iosource([['subsys','standard'],
                                                                ['filename','/etc/passwd'],['offset',100]]))
        ## Negative Offsets:
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','advanced'],
                                                           ['filename','/etc/passwd'],['offset',-100]]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','sgzip'],
                                                           ['filename','%s/pyflag_stdimage_0.2.sgz' % config.UPLOADDIR],['offset',-100]]))
        self.assertRaises(IOError, lambda : iosubsys.iosource([['subsys','ewf'],
                                                           ['filename','%s/ntfs_image.e01' % config.UPLOADDIR],['offset',-100]]))

    def test03DataReadAccuracy(self):
        """ Test data accuracy in image decompression (takes a while) """
        io1 = iosubsys.iosource([['subsys','advanced'],
                             ['filename','%s/pyflag_stdimage_0.2' % config.UPLOADDIR]])
        io2 = iosubsys.iosource([['subsys','sgzip'],
                             ['filename','%s/pyflag_stdimage_0.2.sgz' % config.UPLOADDIR]])
        io3 = iosubsys.iosource([['subsys','ewf'],
                             ['filename','%s/pyflag_stdimage_0.2.e01' % config.UPLOADDIR]])

        t = time.time()
        test_read_random(io1,io2, io1.size, 1000000, 200)
        print "Sgzip vs advanced took %s sec" % (time.time()-t)
        t = time.time()
        test_read_random(io1,io3, io1.size, 1000000, 200)
        print "EWF vs advanced took %s sec" % (time.time()-t)
