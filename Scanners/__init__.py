""" This directory contains scanners that may be invoked of each file when a file system is loaded.

Scanners are pieces of code that are run on all the files in a filesystem when the filesystem is loaded. The purpose of scanners is to extract meta data about files in the filesystem and make deductions.

Scanners are actually factory classes and must be inherited from GenScanFactory. 
"""

class GenScanFactory:
    """ Abstract Base class for scanner Factories.
    
    The Scanner Factory is a specialised class for producing scanner objects. It will be instantiated once per filesystem at the begining of the run, and destroyed at the end of the run. It will be expected to produce a new Scanner object for each file in the filesystem.
    """
    class Scan:
        """ This is the actual scanner class that will be instanitated once for each file in the filesystem.

        factories is a list of factory scanner objects that should be used to scan new files that have been revealed due to this particular scanner. This is mostly used for iteratively scanning files found inside other files (e.g. zip archieves etc). If this scanner is not adding new files to the ddfs tables, you do not need to use this.
        Note that this is a nested class since it may only be instantiated by first instantiating a Factory object. """
        def __init__(self, inode,dbh,table,factories=None):
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
