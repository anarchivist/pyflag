""" This scanner handles RFC2822 type messages, creating VFS nodes for all their children """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
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
import os.path
import pyflag.pyflaglog as pyflaglog
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import email, email.Utils,time
from pyflag.FileSystem import File
import pyflag.Time as Time
import pyflag.Magic as Magic

class MBox(Magic.Magic):
    type = "MBox mail file"
    mime = "message/x-application-mbox"
    default_score = 19

    literal_rules = [
        ( "from ", (0,0)),
        ( "\nmime-version: ", (0,1000)),
        ( "\nreceived: ", (0,1000)),
        ( "\nfrom: ", (0,1000)),
        ( "\nmessage_id: ",(0,1000)),
        ( "\nto: ", (0,1000)),
        ( "\nsubject: ", (0,1000)),
        ( "\nreturn-path: ", (0,1000))
        ]

    samples = [ (95, """From \"Michael Cohen\" Thu Jan  6 14:49:13 2005
Message-ID: <42BE76A2.8090608@users.sourceforge.net>
Date: Sun, 26 Jun 2005 19:34:26 +1000
From: scudette <scudette@users.sourceforge.net>
User-Agent: Debian Thunderbird 1.0.2 (X11/20050602)
X-Accept-Language: en-us, en
MIME-Version: 1.0
To:  scudette@users.sourceforge.net
Subject: The Queen
Content-Type: multipart/mixed;
boundary="-.-----------020606020801030004000306"
"""
                 ) ]

class RFC2822Magic(Magic.Magic):
    type = "RFC2822 Mime message"
    mime = "message/rfc2822"
    default_score = 20

    literal_rules = [
        ( "\nmime-version:", (0,1000)),
        ( "\nreceived:", (0,1000)),
        ( "\nfrom:", (0,1000)),
        ( "\nmessage_id:",(0,1000)),
        ( "\nto:", (0,1000)),
        ( "\nsubject:", (0,1000)),
        ( "\nreturn-path:", (0,1000))
        ]

    samples = [ (80, """Message-ID: <42BE76A2.8090608@users.sourceforge.net>
Date: Sun, 26 Jun 2005 19:34:26 +1000
From: scudette <scudette@users.sourceforge.net>
User-Agent: Debian Thunderbird 1.0.2 (X11/20050602)
X-Accept-Language: en-us, en
MIME-Version: 1.0
To:  scudette@users.sourceforge.net
Subject: The Queen
Content-Type: multipart/mixed;
boundary="-.-----------020606020801030004000306"
"""
                 ) ]

class RFC2822(Scanner.GenScanFactory):
    """ Scan RFC2822 Mail messages and insert record into email table"""
    default = True
    depends = ['TypeScan']
    group = 'FileScanners'
    
    def __init__(self,fsfd):
        Scanner.GenScanFactory.__init__(self,fsfd)
        dbh=DB.DBO(self.case)

    class Scan(Scanner.StoreAndScanType):
        types = [ 'message/rfc2822', 'message/x-application-mbox' ]

        def external_process(self, fd):
            if self.mime_type==self.types[0]:
                self.process_message(fd)
            else:
                self.process_mbox(fd)

        def process_mbox(self, fd):
            """ This is borrowed from python's mailbox module """
            path, inode, inode_id = self.ddfs.lookup(inode = fd.inode)
            
            starts, stops = [], []
            while True:
                line_pos = fd.tell()
                line = fd.readline()
                if line.startswith('From '):
                    if len(stops) < len(starts):
                        stops.append(line_pos - len(os.linesep))
                    starts.append(line_pos)
                elif line == '':
                    stops.append(line_pos)
                    break
                
            for i in range(len(starts)):
                new_inode = "o%s:%s" % (starts[i], stops[i] - starts[i])
                new_inode_id = self.ddfs.VFSCreate(inode, new_inode,
                                                   "Msg %s" % i)
                
                tmpfd = self.ddfs.open(inode_id = new_inode_id)
                self.process_message(tmpfd)
                                       
        def process_message(self, fd):
            count = 0
            try:
                new_path, new_inode, new_inode_id = self.ddfs.lookup(inode = fd.inode)
                
                a = email.message_from_file(fd)
                try:
                    subject = a['subject']
                    if len(subject)>50:
                        subject = subject[:50] + " ..."
                        
                    new_name = "%s: %s" % (new_path, subject)
                    self.ddfs.VFSRename(new_inode_id, new_name)
                except KeyError:
                    pass

                pyflaglog.log(pyflaglog.DEBUG,"Found an email message in %s: %s" % (
                    new_inode, a['subject']))

                #Mysql is really picky about the date formatting
                date = email.Utils.parsedate(a.get('Date'))
                if not date:
                    raise Exception("No Date field in message - this is probably not an RFC2822 message at all.")

                dbh=DB.DBO(self.case)
                dbh.insert('email',
                           inode = self.inode,
                           _date =  "from_unixtime(%r)" % int(time.mktime(date)),
                           to = a.get('To'),
                           _from = "%r" % a.get('From'),
                           subject = a.get('Subject'))

                for part in a.walk():
                    if part.get_content_maintype() == 'multipart':
                        continue

                    filename = part.get_filename()
                    data = part.get_payload(decode=1)

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

                    ## Create the VFSs node:
                    new_inode_id = self.ddfs.VFSCreate(
                        new_inode,"m%s" % count, filename,
                        _mtime = time.mktime(date), size=len(data)
                        )

                    ## Now call the scanners on new file:
                    new_fd = self.ddfs.open(inode_id=new_inode_id)
                    Scanner.scanfile(self.ddfs,new_fd,self.factories)
                    new_fd.close()

                    count+=1

            except Exception,e:
                pyflaglog.log(pyflaglog.DEBUG,"RFC2822 Scan: Unable to parse inode %s as an RFC2822 message (%s)" % (self.inode,e))
                
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
        #print "attchement number %s" % attachment_number
        count = 0

        for part in a.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            if count==attachment_number:
                self.message = part.get_payload(decode=1)
                self.readptr += len(self.message)
                #print "Returning %s" % part.get_payload()
                return self.message

            count+=1

        return ''
##class RFC2822CachedFile(CachedFile, RFC2822_File):
##    target_class = RFC2822_File
