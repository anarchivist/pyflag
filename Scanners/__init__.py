""" This directory contains scanners that may be invoked of each file when a file system is loaded.

Scanners are pieces of code that are run on all the files in a filesystem when the filesystem is loaded. The purpose of scanners is to extract meta data about files in the filesystem and make deductions.

Scanners are actually factory classes and must be inherited from GenScanFactory. 
"""
import pyflag.conf
config=pyflag.conf.ConfObject()

class GenScanFactory:
    """ Abstract Base class for scanner Factories.
    
    The Scanner Factory is a specialised class for producing scanner objects. It will be instantiated once per filesystem at the begining of the run, and destroyed at the end of the run. It will be expected to produce a new Scanner object for each file in the filesystem.
    """
    class Scan:
        """ This is the actual scanner class that will be instanitated once for each file in the filesystem.

        factories is a list of factory scanner objects that should be used to scan new files that have been revealed due to this particular scanner. This is mostly used for iteratively scanning files found inside other files (e.g. zip archieves etc). If this scanner is not adding new files to the ddfs tables, you do not need to use this.
        outer is a reference to the generator object that is used to instantiate these classes.
        
        Note that this is a nested class since it may only be instantiated by first instantiating a Factory object. """
        def __init__(self, inode,outer,factories=None):
            self.inode = inode
            self.size = 0

        def process(self, data, metadata={}):
            """ process the chunk of data.

            This function is given a chunk of data from the file - this may not be the complete file. Sometimes it may be appropropriate to accumulate the data until the finish method is called. It is prudent to accumulate the file to the filesystem in the temporary directory rather than try to accumulate it into memory.

            @arg data: Some limited amount of data from the file.
            @arg metadata: A dict specifying meta data that was deduced about this file by other scanners. Scanners may add meta data to this dict in order to indicate certain facts to other scanners about this file. For example the TypeScan scanner will store the magic in this dict to indicate when the PST scanner should scan the file etc. Note that the order of scanner invocation is important, and is controlled by the order parameter in the Scanner's GenScanFactory class.
            """
            pass

        def finish(self):
            """ all data has been provided to process, finish up.

            Note that this signals the completion of the file. If a file had been queued during the process call, it should now be processed.
            """
            pass

    def __init__(self,dbh, table):
        """ do any initialisation tasks, such as creating tables.
        """
        pass

    def destroy(self):
        """ Final destructor called on the factory to finish the scan operation.

        This is sometimes used to make indexes etc. 
        """
        pass

    def reset(self):
        """ This method drops the relevant tables in the database, restoring the db to the correct state for rescanning to take place. """
        pass

    ## Relative order of scanners - Higher numbers come later in the order
    order=10

class StoreAndScan:
    """ A Scanner designed to store a temporary copy of the scanned file to be able to invoke an external program on it.

    Note that this is a scanner inner class (which should be defined inside the factory class). This class should be extended by Scanner factories to provide real implementations to the 'boring','make_filename' and 'external_process' methods.
    """
    file = None

    def __init__(self, inode,ddfs,outer,factories=None):
        self.inode = inode
        self.table=outer.table
        self.dbh=outer.dbh
        self.ddfs=ddfs
        self.factories=factories

    def boring(self,metadata):
        """ This function decides if this file is boring (i.e. we should ignore it).

        This must be implemented in derivative classes.

        @arg metadata: The metadata dict which is filled with metadata about the file from previous scanners.
        @return: True if the file is boring (i..e should be ignored), False if we are interested in it.
        """

    def process(self, data,metadata=None):
        try:
            if not self.boring(metadata):
                print "Will process %s" % self.table
                self.file = open(self.make_filename(),'wb')
        except KeyError:
            pass

        if self.file:
            self.file.write(data)

    def make_filename(self):
        """ This function should return a fairly unique name for saving the file in the tmp directory.

        This class implementes a standard filename formatting convention:
        $RESULTDIR/$case_$inode

        Where $inode is the filename in the filesystem.
        """
        return("%s/%s_%s" % (
            config.RESULTDIR,
            self.dbh.case,
            self.dbh.MakeSQLSafe(self.inode)))

    def finish(self):
        if self.file:
            name = self.file.name
            self.file.close()

            self.external_process(name)

    def external_process(self,name):
        """ This function is invoked by the scanner to process a temporary file.

        This function my be overridden by derived classes.

        @arg name: The name of the file in the filesystem to operate on - The Scanner should have saved this file previously.
        """
