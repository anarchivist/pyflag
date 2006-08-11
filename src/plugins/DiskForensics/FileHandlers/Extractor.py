""" This is a scanner which utilises libextractor to collect metadata
about some files.
"""
from pyflag.Scanner import *
import pyflag.Reports as Reports

try:
    import extractor

    E = extractor.Extractor()
    
    class ExtractorScan(GenScanFactory):
        """ A Scanner to collect metadata about files """
        order = 90
        default = True
        depends = 'TypeScan'

        class Scan(StoreAndScanType):
            types = (
                'image/.*',
                'application/msword',
                'application/x-executable'
                )

            def external_process(self,fd):
                meta=E.extractFromFile(fd.name)
                for pair in meta:
                    self.dbh.insert("xattr",
                                    inode_id = self.fd.inode_id,
                                    property = pair[0].encode('ascii','replace'),
                                    value = pair[1].encode('ascii','replace')
                                    )


    class BrowseMetadata(Reports.report):
        """
        Browse Metadata
        ---------------

        PyFlag can use the libextractor scanner to gather many
        interesting facts about files being scanned. The specifics of
        this metadata depends on libextractor, but generally metadata
        reveals intimate details relating to the files - such as
        authors, creation times etc.

        This report simply presents the data in a tabular format so it
        can be searched simply.

        """
        name = "Browse Metadata"
        family = "Disk Forensics"

        def display(self, query, result):
            result.table(
                columns = ('inode', 'property','value'),
                names = ('Inode', 'Property', 'Value'),
                table = 'xattr,inode',
                case = query['case'],
                where = 'inode.inode_id=xattr.inode_id',
                )
                     
except ImportError:
    pass
