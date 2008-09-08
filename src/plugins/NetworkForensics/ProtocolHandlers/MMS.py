#!/usr/bin/env python

"""
This is a PyFlag Scanner to decode and extract mms files. We decode
those into the Webmail Messages table because concepually its kind of
like a webmail (That table is a bit overloaded).

Simple script showing how to use the python-mms library to decode a binary
MMS message file and display textual information about it.

This script does not actually dump the contents of binary data parts (such as
images and audio clips), but shows how it can be done.

@author: Francois Aucamp <faucamp@csir.co.za>
@license: GNU LGPL
"""

import sys
# import the python-mms library
import mms
import pyflag.Scanner as Scanner
import pyflag.pyflaglog as pyflaglog
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import LiveCom
import pyflag.CacheManager as CacheManager

class MMSScanner(LiveCom.HotmailScanner):
    """ Scans MMS messages """
    default = True
    depends = ['TypeScan']
    group = 'NetworkScanners'
    
    class Scan(LiveCom.HotmailScanner.Scan):
        types = (
            'application/.+wap.+mms',
            )

        service = 'MMS'

        def boring(self, metadata, data =''):
            return Scanner.StoreAndScanType.boring(self,metadata, data) \
                   or not "H" in self.fd.inode
                
        def process(self, data, metadata=None):
            Scanner.StoreAndScanType.process(self, data, metadata)

        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG, "Opening %s for MMS Processing" % self.fd.inode)

            try:
                message = mms.MMSMessage.fromFile(fd.name)
            except:
                pyflaglog.log(pyflaglog.DEBUG, "Error parsing %s" % self.fd.inode)
                return
            
            result = {'type': 'Sent', 'message': ''}

            for k,v in [ ('From', 'From'),
                         ('To', 'To'),
                         ('Data', 'sent'),
                         ('Subject', 'subject')
                         ]:
                try:
                    result[v] = message.headers[k]
                except KeyError:
                    pass

            ## Create a new webmail message:
            inode_id = self.insert_message(result)
            dbh = DB.DBO(self.fd.case)

            count = 0
            for part in message.dataParts:
                count +=1
                if part.contentType.startswith('text/'):
                    result['message'] += part.data
                    dbh.update('webmail_messages', where='inode_id="%s"' % inode_id,
                               message = result['message'])

                elif not part.contentType.endswith('smil'):
                    new_inode = self.fd.inode + "|m%s" % count
                    filename = CacheManager.MANAGER.get_temp_path(self.fd.case, new_inode)
                    fd = open(filename,"wb")
                    fd.write(part.data)
                    fd.close()

                    ## Add Attachment
                    path, inode, inode_id = self.ddfs.lookup(inode_id = inode_id)
                    attachment_id = self.ddfs.VFSCreate(None,
                                                        new_inode,
                                                        "%s/Message %s" % (path,count),
                                                        size = len(part.data))

                    parameters = {}
                    for hdr in part.headers:
                        value = part.headers[hdr]
                        if type(value) == tuple:
                            if len(value[1]) > 0:
                                parameters = value[1]

                    filename = parameters.get("Filename", parameters.get("Name","output.bin"))        
                    dbh.insert("webmail_attachments",
                               inode_id = inode_id,
                               attachment = attachment_id,
                               url = filename)
                    
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage: %s MMS_FILE' % sys.argv[0]
        sys.exit(1)

    # Decode the specified file
    message = mms.MMSMessage.fromFile(sys.argv[1])
    
    # Dump header information
    print 'MMS header information:\n------------------------'
    for hdr in message.headers:
        value = message.headers[hdr]
        if type(value) == tuple:
            print '%s: %s' % (hdr, str(value[0]))
            if len(value[1]) > 0:
                parameters = value[1]
                print '   parameters:'
                for param in parameters:
                    print '      %s: %s' % (param, parameters[param])
        else:
            print '%s: %s' % (hdr, str(message.headers[hdr]))
        
    # Dump message body information
    print '\nMMS body information:\n----------------------'
    print 'Number of pages in message: %d' % len(message.pages)
    print 'Number of data parts in message: %d' % len(message.dataParts)

    counter = 0
    for part in message.dataParts:
        counter += 1
        print '\n  Data part #%d\n  ------------' % counter 
        for hdr in part.headers:
            value = part.headers[hdr]
            if type(value) == tuple:
                print '  %s: %s' % (hdr, str(value[0]))
                if len(value[1]) > 0:
                    parameters = value[1]
                    for param in parameters:
                        print '     %s: %s' % (param, parameters[param])
            else:
                print '  %s: %s' % (hdr, str(part.headers[hdr]))
        print '  Data length: %d bytes' % len(part)
        # In this exxample, we only print the data of text-based data parts
        if part.contentType.startswith('text/'):
            print '  Contents:'
            print '  "%s"' % part.data
