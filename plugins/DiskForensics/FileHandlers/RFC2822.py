""" This scanner handles RFC2822 type messages, creating VFS nodes for all their children """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
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
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import email
from pyflag.FileSystem import File,CachedFile

class RFC2822(Scanner.GenScanFactory):
    """ Scan RFC2822 Mail messages and insert record into email_ table"""
    default = True
    depends = ['TypeScan','PstScan']
    
    def __init__(self,dbh, table,fsfd):
        self.dbh=dbh
        self.table=table
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `email_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `date` DATETIME, `to` VARCHAR(250), `from` VARCHAR(250), `subject` VARCHAR(250));", self.table)

    class Scan(Scanner.StoreAndScanType):
        types = [ 'text/x-mail.*',
                  'message/rfc822',
                  ]
 
        def external_process(self,name):
            def month_str_to_int(str): 
	        if (str == "Jan"):
	            return 1
	        elif (str == "Feb"):
		    return 2
	        elif (str == "Mar"):
		    return 3
	        elif (str == "Apr"):
		    return 4
	        elif (str == "May"):
		    return 5
	        elif (str == "Jun"):
		    return 6
	        elif (str == "Jul"):
		    return 7
	        elif (str == "Aug"):
		    return 8
	        elif (str == "Sep"):
		    return 9
	        elif (str == "Oct"):
		    return 10
	        elif (str == "Nov"):
		    return 11
	        elif (str == "Dec"):
		    return 12
		    
	    count = 0
            fd = open(name,'r')

            try:
                a=email.message_from_file(fd)
		
		#Mysql is really picky about the date formatting
		strng = a.get('Date')
		flds = strng.split()
		datesql = flds[3] + "-" + str(month_str_to_int(flds[2])) + "-" + flds[1] + " " + flds[4] + " " + flds[5]
		print datesql
		self.dbh.execute("INSERT INTO `email_%s` SET `inode`=%r,`vfsinode`=%r,`date`=%r,`to`=%r,`from`=%r,`subject`=%r", (self.table, self.inode, name, datesql, a.get('To'), a.get('From'), a.get('Subject')))

		#self.dbh.execute("INSERT INTO `email_%s` SET `inode`=%r,`vfsinode`='P%s',`date`=from_unixtime(%s),`to`=%r,`from`=%r,`subject`=%r", (self.table, self.inode, name, a.get('Date'), a.get('To'), a.get('From'), a.get('Subject')))

                #print ("**************************************************") 
                #print a.get("Date") + a.get("To") + a.get("From") + a.get("Subject") + a.get_payload()
		#print ("**************************************************")
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
