""" This scanner handles RFC2822 type messages, creating VFS nodes for all their children """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import os.path
import pyflag.logging as logging
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import email
from pyflag.FileSystem import File,CachedFile

class RFC2822(Scanner.GenScanFactory):
    """ Scan RFC2822 Mail messages """
    default = True
    depends = 'TypeScan'
    
    class Scan(Scanner.StoreAndScanType):
        types = [ 'text/x-mail.*',
                  'message/rfc822',
                  ]

        def external_process(self,name):
            count = 0
            fd = open(name,'r')

            try:
                a=email.message_from_file(fd)
                for part in a.walk():
                    if part.get_content_maintype() == 'multipart':
                        continue

                    filename = part.get_filename()
                    ## Sometimes the filename is specified in the
                    ## content-type header:
                    try:
                        for x,y in part.get_params():
                            if x =="name":
                                filename=y
                                break
                    except:
                        pass

                    if not filename: filename="Attachment %s" % count

                    ## Create the VFS node:
                    self.ddfs.VFSCreate(self.inode,"m%s" % count, filename)

                    ## Now call the scanners on new file:
                    new_inode = "%s|m%s" % (self.inode,count)
                    fd=self.ddfs.open(inode=new_inode)
                    Scanner.scanfile(self.ddfs,fd,self.factories)
                    fd.close()
                    
                    count+=1
                    
            except Exception,e:
                logging.log(logging.DEBUG,"RFC2822 Scan: Unable to parse inode %s as an RFC2822 message (%s)" % (self.inode,e))

class RFC2822_File(File):
    """ A VFS Driver for reading mail attachments """

    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)

        a=email.message_from_file(fd)
        my_part = inode.split('|')[-1]
        attachment_number = int(my_part[1:])
        count = 0

        for part in a.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            if count==attachment_number:
                self.message = part.get_payload(decode=1)
                return

            count+=1

        raise IOError("Unable to find attachment %s in MIME message" % count)

    def read(self,length=None):
        if length==None:
            result=self.message[self.readptr:]
        else:
            result= self.message[self.readptr:self.readptr+length]

        self.readptr+=len(result)
        return result

class RFC2822CachedFile(CachedFile, RFC2822_File):
    specifier = 'm'
    target_class = RFC2822_File
