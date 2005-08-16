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
#  Version: FLAG  $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
""" This module implements a scanning mechanism for operating on all files within a given filesystem.

Scanners are pieces of code that are run on all the files in a filesystem when the filesystem is loaded. The purpose of scanners is to extract meta data about files in the filesystem and make deductions.

The GenScan abstract class documents a Generic scanner. This scanner is applied on every file in a filesystem during a run of the FileSystem's scan method.

Scanners are actually factory classes and must be inherited from GenScanFactory. 
"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.logging as logging
import os,imp
import re
import pyflag.Registry as Registry
import pyflag.DB as DB

class BaseScanner:
    """ This is the actual scanner class that will be instanitated once for each file in the filesystem.
    
    factories is a list of factory scanner objects that should be used to scan new files that have been revealed due to this particular scanner. This is mostly used for iteratively scanning files found inside other files (e.g. zip archieves etc). If this scanner is not adding new files to the ddfs tables, you do not need to use this.
    outer is a reference to the generator object that is used to instantiate these classes.
    
    Note that this is a nested class since it may only be instantiated by first instantiating a Factory object. """
    def __init__(self, inode,ddfs,outer,factories=None,fd=None):
        """
        @arg fd: The file descriptor which is being scanned. Note that scanners must not interfere with fd (i.e. never change the current file pointer).
        """
        self.inode = inode
        self.fd=fd
        self.size = 0
        self.ddfs = ddfs
        self.ddfs.dbh.set_meta("scan_%s" % outer.__class__, inode)
        self.dbh=outer.dbh
        self.table=outer.table
        self.outer=outer
        self.factories=factories

    def process(self, data, metadata={}):
        """ process the chunk of data.

        This function is given a chunk of data from the file - this
        may not be the complete file. Sometimes it may be
        appropropriate to accumulate the data until the finish method
        is called (See the StoreAndScan classes for examples).
        
        @arg data: Some limited amount of data from the file. The size of the data is unspecified but more than 1000 bytes.
        
        @arg metadata: A dict specifying meta data that was deduced about this file by other scanners. Scanners may add meta data to this dict in order to indicate certain facts to other scanners about this file. For example the TypeScan scanner will store the magic in this dict to indicate when the PST scanner should scan the file etc. Note that the order of scanner invocation is important, and is controlled by the order parameter in the Scanner's GenScanFactory class.
        """
        pass

    def finish(self):
        """ all data has been provided to process, finish up.

        Note that this signals the completion of the file. If a file had been queued during the process call, it should now be processed.
        """
        pass


class GenScanFactory:
    """ Abstract Base class for scanner Factories.
    
    The Scanner Factory is a specialised class for producing scanner objects. It will be instantiated once per filesystem at the begining of the run, and destroyed at the end of the run. It will be expected to produce a new Scanner object for each file in the filesystem.
    """
    ## Should this scanner be on by default?
    default=False

    ## This is a list of scanner names which we depend on. Depending
    ## on a scanner will force it to be enabled whenever we are
    ## enabled.
    depends = []
    
    def __init__(self,dbh,table,fsfd):
        """ Factory constructor.

        @arg dbh: A valid database handle
        @arg table: The name of the filesystem we are currently operating on
        @arg fsfd: A filesystem object for the filesystem we are about to scan.
        """
        self.dbh=dbh
        self.table=table
        self.fsfd = fsfd

    def prepare(self):
        """ This is called before the scanner is used.

        Generally the constructor should be very brief (because it might be called to reset rather than to actually scan). And most work should be done in this method.
        """

    def destroy(self):
        """ Final destructor called on the factory to finish the scan operation.

        This is sometimes used to make indexes etc. 
        """
        pass

    def reset(self):
        """ This method drops the relevant tables in the database, restoring the db to the correct state for rescanning to take place. """
        ## Delete all scanner activities from the meta table:
        self.dbh.execute("delete from meta where property = %r", "scan_%s" % self.__class__)

    ## Relative order of scanners - Higher numbers come later in the order
    order=10
    
    class Scan(BaseScanner):
        """ The Scan class must be defined as an inner class to the factory. """

StoreAndScanFiles = []

class MemoryScan(BaseScanner):
    """ A scanner designed to scan buffers of text in memory.

    This scanner implements a sliding window, i.e. each buffer scanned begins with OVERLAP/BUFFERSIZE from the previous buffer. This allows regex, and virus definitions to locate matches that are broken across a block boundary.
    """
    windowsize=200
    def __init__(self, inode,ddfs,outer,factories=None,fd=None):
        BaseScanner.__init__(self, inode,ddfs,outer,factories)
        self.window = ''
        self.offset=0

    def process(self, data,metadata=None):
        buf = self.window + data
        self.process_buffer(buf)
        self.window = buf[-self.windowsize:]
        self.offset+=len(data)-self.windowsize

    def process_buffer(self,buf):
        """ This abstract method should implement the actual scanner.

        @arg offset: The actual offset the buffer begins with inside the inode.
        """

class StoreAndScan(BaseScanner):
    """ A Scanner designed to store a temporary copy of the scanned file to be able to invoke an external program on it.

    Note that this is a scanner inner class (which should be defined inside the factory class). This class should be extended by Scanner factories to provide real implementations to the 'boring','make_filename' and 'external_process' methods.
    """
    def __init__(self, inode,ddfs,outer,factories=None,fd=None):
        BaseScanner.__init__(self, inode,ddfs,outer,factories)
        self.file = None
        self.name = None
        self.boring_status = True

    def boring(self,metadata):
        """ This function decides if this file is boring (i.e. we should ignore it).

        This must be implemented in derivative classes.

        @arg metadata: The metadata dict which is filled with metadata about the file from previous scanners.
        @return: True if the file is boring (i..e should be ignored), False if we are interested in it.
        """

    def process(self, data,metadata=None):
        try:
            ## If this file is boring, we check to see if there is new
            ## information which makes it not boring:
            if self.boring_status:
                self.boring_status = self.boring(metadata)
                
            ## We store all the files we create in a central place, so
            ## multiple instances of StoreAndScan can all share the
            ## same physical file (as long at they all want to give it
            ## the same name). This allows more efficient streamlining
            ## as all StoreAndScan derivatives can use the same file,
            ## but only one is actually responsible for creating it.
            if not self.name:
                self.name = self.make_filename()
                
            if not self.file and not self.boring_status and self.name not in StoreAndScanFiles:
                StoreAndScanFiles.append(self.name)
                self.file = open(self.name,'wb')
        except KeyError:
            pass

        if self.file:
            self.file.write(data)

    def make_filename(self):
        """ This function should return a fairly unique name for saving the file in the tmp directory.

        This class implementes a standard filename formatting convention:
        $RESULTDIR/case_$case/$filesystem_$inode

        Where $inode is the filename in the filesystem.
        """
        return make_temp_filename(
            self.dbh.case, self.table,
            self.dbh.MakeSQLSafe(self.inode)
            )

    def finish(self):
        if self.file:
            self.file.close()
            ## We now remove the file from the central storage place:
            StoreAndScanFiles.remove(self.name)

        if not self.boring_status:
            self.external_process(self.name)

    def external_process(self,name):
        """ This function is invoked by the scanner to process a temporary file.

        This function my be overridden by derived classes.

        @arg name: The name of the file in the filesystem to operate on - The Scanner should have saved this file previously.
        """

def make_temp_filename(case, fsimage, inode):
        return("%s/case_%s/%s_%s" % (
            config.RESULTDIR,
            case,fsimage,
            inode))

class StoreAndScanType(StoreAndScan):
    """ This class scans a file only if a file is of a certain type.

    The determination of the type of a file is done by using the metadata passed from the type scanner, or failing that we query the type table for the given inode.
    """
    ## These are the mime types that will be used to decide if we should scan this file
    types = []
    
    def boring(self,metadata):
        try:
            mime_type = metadata['mime']
        except KeyError:
            self.dbh.execute("select mime from type_%s where inode=%r",(self.table,self.inode))
            row=self.dbh.fetch()
            if row:
                mime_type = row['mime']
            else: mime_type = ""

        for t in self.types:
            if re.search(t,mime_type):
                ## Not boring:
                return False

        return True


class ScanIfType(StoreAndScanType):
    """ Only Scans if the type matches self.types.

    Just like StoreAndScanType but without creating the file.
    """
    def __init__(self, inode,ddfs,outer,factories=None,fd=None):
        BaseScanner.__init__(self, inode,ddfs,outer,factories)
        self.boring_status = True

    def process(self, data,metadata=None):
        ## If this file is boring, we check to see if there is new
        ## information which makes it not boring:
        if self.boring_status:
            self.boring_status = self.boring(metadata)

    def finish(self):
        pass
    
### This is used to scan a file with all the requested scanner factories
def scanfile(ddfs,fd,factories):
    """ Given a file object and a list of factories, this function scans this file using the given factories

    @arg ddfs: A filesystem object. This is sometimes used to add new files into the filesystem by the scanner
    @arg fd: The file object of the file to scan
    @arg factories: A list of scanner factories to use when scanning the file.
    """
    buffsize = 1024 * 1024
    # instantiate a scanner object from each of the factory. We only
    #instantiate scanners from factories which have not been run on
    #this inode previously. We find which factories were already run
    #by checking the meta table.  Note that we still pass the full
    #list of factories to the Scan class so that it may invoke all of
    #the scanners on new files it discovers.
    objs = []
    for c in factories:
        ddfs.dbh.execute("select * from meta where property=%r and value=%r",("scan_%s" % c.__class__,fd.inode))
        if not ddfs.dbh.fetch():
            objs.append(c.Scan(fd.inode,ddfs,c,factories=factories,fd=fd))

    # read data (in chunks)
    while 1:
        ## This dict stores metadata about the file which may be filled in by some scanners in order to indicate some fact to other scanners.
        metadata = {}
        ## If the file is too fragmented, we skip it because it might take too long... NTFS is a shocking filesystem, with some files so fragmented that it takes a really long time to read them. In our experience these files are not important for scanning so we disable them here. Maybe this should be tunable?
        try:
            if len(fd.blocks)>1000 or fd.size>100000000:
                return

            c=0
            for i in fd.blocks:
                c+=i[1]

            ## If there are not enough blocks to do a reasonable chunk of the file, we skip them as well...
            if c>0 and c*fd.block_size<fd.size:
                logging.log(logging.WARNING,"Skipping inode %s because there are not enough blocks %s < %s" % (fd.inode,c*fd.block_size,fd.size))
                return

        except AttributeError:
            pass

        try:
            data = fd.read(buffsize)
            if not data: break
        except IOError:
            break
        # call process method of each class
        for o in objs:
            try:
                o.process(data,metadata=metadata)
            except Exception,e:
                logging.log(logging.ERRORS,"Scanner (%s) Error: %s" %(o,e))

    # call finish method of each object
    for o in objs:
        try:
            o.finish()
        except Exception,e:
            logging.log(logging.ERRORS,"Scanner (%s) Error: %s" %(o,e))


class Drawer:
    """ This class is responsible for rendering scanners of similar classes.

    This class should be declared as an inner class of the scanner.
    """
    description = "Description of main scanner"
    name = "name of main scanner"
    contains = []
    default = True

    def get_group_name(self):
        return "scangroup_%s" % self.name

    def get_parameters(self):
        for i in self.contains:
            try:
                scanner = Registry.SCANNERS.dispatch(i)
                yield "scan_%s" % i,'onoff'
            except:
                continue

    def add_defaults(self,dest_query,src_query):
        """ Given a src_query object with some scan_ entries, we add
        scan_ entries initialised to their default values until
        the full contained set is represented.
        """
        try:
            scan_group_name = self.get_group_name()

            if src_query[scan_group_name]=='on':
                for i in self.contains:
                    try:
                        cls = Registry.SCANNERS.dispatch(i)
                    except:
                        ## Ignore scanners in contains which do not exist
                        continue
                    
                    scan_name = 'scan_%s' % i
                    del dest_query[scan_name]

                    ## If i is not specified, we use the default for
                    ## this scanner:
                    if not src_query.has_key('scan_%s' % i):
                        if cls.default:
                            dest_query[scan_name]='on'
                        else:
                            dest_query[scan_name]='off'
                    else:
                        dest_query[scan_name]=src_query[scan_name]
        except KeyError:
            pass

    def form(self,query,result):
        left = result.__class__(result)
        scan_group_name = self.get_group_name()

        ## If there is no scan_group defined, we use the default value
        if not query.has_key(scan_group_name):
            if self.default:
                query[scan_group_name]='on'
                result.defaults[scan_group_name]='on'
            else:
                query[scan_group_name]='off'
                result.defaults[scan_group_name]='off'

        ## Add defaults for the scanners contained:
        for i in self.contains:
            try:
                cls = Registry.SCANNERS.dispatch(i)
                if not query.has_key('scan_%s' % i):
                    if cls.default:
                        result.hidden('scan_%s' % i,'on')
                    else:
                        result.hidden('scan_%s' % i,'off')
            except ValueError:
                pass
            
        def configure_cb(query,result):
            try:
                if query['refresh']:
                    del query['refresh']

                    result.refresh(0,query,parent=1)
            except KeyError:
                pass

            ## Draw the gui for all the classes we manage:
            result.decoration = 'naked'
            result.start_form(query,refresh="parent")
            result.start_table()

            self.add_defaults(query,query.clone())

            for i in self.contains:
                try:
                    cls = Registry.SCANNERS.dispatch(i)
                except:
                    continue
                
                scanner_desc = cls.__doc__.splitlines()[0]

                ## Add an enable/disable selector
                result.const_selector(scanner_desc,"scan_%s" % i,[
                    'on','off'],['Enabled','Disabled'] )

            result.end_table()
            result.end_form()


        right=result.__class__(result)
        right.popup(configure_cb,"Configure",icon="spanner.png")
        left.row(right,self.description)
        result.const_selector(left,
                           scan_group_name,
                           ['on','off'],['Enabled','Disabled'])

class FSSpecialisedDrawer(Drawer):
    """ A drawer which only draws the form if the current filesystem is derived from a given filesystem name """
    special_fs_name = ''

    def form(self,query,result):
        """ It only makes sense to run these scanners when the
        base filesystem is derived from the PCAPFS. Otherwise
        we just hide these options.
        """
        dbh = DB.DBO(query['case'])
        fstype = dbh.get_meta('fstype_%s' % query['fsimage'])
        fs_class = Registry.FILESYSTEMS.filesystems[fstype]
        if issubclass(fs_class,Registry.FILESYSTEMS.fs[self.special_fs_name]):
            Drawer.form(self,query,result)
        else:
            result.hidden(self.get_group_name(),'off')
            for i in self.contains:
                result.hidden("scan_%s" % i,'off')
