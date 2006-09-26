""" This scanner handles RFC2822 type messages, creating VFS nodes for all their children """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import email, email.Utils,time
from pyflag.FileSystem import File


class RFC2822(Scanner.GenScanFactory):
    """ Scan RFC2822 Mail messages and insert record into email_ table"""
    default = True
    depends = ['TypeScan','PstScan']
    
    def __init__(self,fsfd):
        Scanner.GenScanFactory.__init__(self,fsfd)
        dbh=DB.DBO(self.case)
        dbh.execute("CREATE TABLE IF NOT EXISTS `email` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `date` DATETIME, `to` VARCHAR(250), `from` VARCHAR(250), `subject` VARCHAR(250));")

    class Scan(Scanner.StoreAndScanType):
        types = [ 'text/x-mail.*',
                  'message/rfc822.*',
                  ]

        def boring(self,metadata, data=''):
            """ The magic determination of RFC2822 messages is too
            loose, this does further tests to make sure it really is a
            message.

            In particular POP transcripts are identified as messages
            since magic looks for the occurances of certain key words
            near the start of the file, which happens to be after a
            couple of pop exchanges.
            """
            if not Scanner.StoreAndScanType.boring(self,metadata,data=data):
                ## Look at the first keyword before : at the first
                ## line, must be one of the rfc keywords listed:
                line = data.split('\r\n',1)[0].split(':',1)
                try:
                    if (line[0].lower() in
                           ['received','from', 'message-id', 'to', 'subject',
                            'return-path']):
                        return False
                except:
                    pass

                print "RFC2822 thought %s is boring despite the magic" % line

            self.ignore = True
            return True
 
        def external_process(self,fd):		    
            count = 0
            try:
                a=email.message_from_file(fd)

                logging.log(logging.DEBUG,"Found an email message in %s" % self.inode)
		
		#Mysql is really picky about the date formatting
                date = email.Utils.parsedate(a.get('Date'))
                if not date:
                    raise Exception("No Date field in message - this is probably not an RFC2822 message at all.")

                dbh=DB.DBO(self.case)
                dbh.execute("INSERT INTO `email` SET `inode`=%r,`date`=from_unixtime(%r),`to`=%r,`from`=%r,`subject`=%r", (self.inode, int(time.mktime(date)), a.get('To'), a.get('From'), a.get('Subject')))

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
                    self.ddfs.VFSCreate(self.inode,"m%s" % count, filename,
                                        mtime = time.mktime(date)
                                        )

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
    specifier = 'm'

    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)
        self.cache()

    def read(self, length=None):
        try:
            return File.read(self,length)
        except IOError:
            pass

        if self.readptr > 0:
            return ''
        
        self.fd.seek(0)
        a=email.message_from_file(self.fd)
        my_part = self.inode.split('|')[-1]
        attachment_number = int(my_part[1:])
        count = 0

        for part in a.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            if count==attachment_number:
                self.message = part.get_payload(decode=1)
                self.readptr += len(self.message)
                return self.message

            count+=1

        return ''
##class RFC2822CachedFile(CachedFile, RFC2822_File):
##    target_class = RFC2822_File
