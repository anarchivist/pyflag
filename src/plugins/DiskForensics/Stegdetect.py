# ******************************************************
# Copyright (C) 2006, Fabio Vayr
#
# Developed by the Network Security Team,
# Secure Group S.r.l.
# Website:  http://www.securegroup.it
#
#
# Fabio Vayr <fabio.vayr@securegroup.it>
# 
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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

""" Stegdetect is a module which looks for Jpeg images and search for steganography"""


import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import query_type
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import pyflag.DB as DB
import pexpect
from pyflag.TableObj import StringType, TimestampType, InodeType

active = False

class AFTJpegScan(GenScanFactory):
    """ Steganography inside Jpeg images """
    order=99
    default = True
    depends = 'TypeScan'
	
    def __init__(self,fsfd):
        Scanner.GenScanFactory.__init__(self, fsfd)
	        
    def prepare(self):
        dbh = DB.DBO(self.case)
        dbh.execute("""CREATE TABLE IF NOT EXISTS `stegjpeg` (    
        `inode` VARCHAR(20) NOT NULL,
	`result` VARCHAR(40) NOT NULL)""" )
	
        dbh.check_index('stegjpeg','inode')	
	    
    class Scan(StoreAndScanType):
        """ If we hit a jpeg file, we just create a new Inode entry in the VFS """
        
	types = (
            'image/aaaajpeg' ,
            )
	    	    
        def external_process(self,fd):
            """ This is run on the extracted file """
		    
#	    No checks on stegdetect since if we get here we already know it exists

#	    s=pexpect.spawn('which',['stegdetect'])
#	    s.expect(pexpect.EOF)
#	    if s.before != '' :
#	        stegbin=s.before.splitlines()[0]
#	    else: 
#	    	return
	    
	    args = ['-s','2.00','-t','jopifa','-n','%s' % fd.name ]
	    stegbin = 'stegdetect'
	    pyflaglog.log(pyflaglog.DEBUG,"Will launch %s %s %s %s %s %s %s" % (stegbin, args[0],args[1],args[2],args[3],args[4],args[5]))
	    s=pexpect.spawn(stegbin, args)
	    s.expect(pexpect.EOF)
	    stegoutput=s.before.splitlines()[0]	
	    stegoutparsed=re.match("(.*):\s*(\S*)",stegoutput)
	    result=stegoutparsed.groups()[1]
	    self.dbh.execute("insert into  stegjpeg  set inode = '%s', result = '%s' " % (self.inode,result))
	    
	    
	    
class AFTSteganography(Reports.report):
    """ AFT Extension - Steganography Jpeg checker """
    
    # Let's check if this external tool exists into the PATH and then add it to Reports
    try:
	      s=pexpect.spawn('stegdetect -V')
	      s.expect(pexpect.EOF)
	      if "Stegdetect Version" in s.before :
	           hidden = False
	      else: 
	           hidden = True
    except pexpect.ExceptionPexpect,e:
	      hidden = True
	      
    name = "Stegdetect"
    family = "Disk Forensics"
    
    
    def form(self,query,result):
        try:
            result.case_selector()
        except KeyError:
            return result    

    def progress(self,query,result):
        result.heading("Stegdetect is running on JPEGs...")
	
    
#    def analyse(self,query):
#        import time 
#        time.sleep(1)

	
    def display(self,query,result):
        dbh=self.DBO(query['case'])

        result.heading("Stegdetect results on Jpeg images ")	
	
        try:
        
	     dbh.check_index("stegjpeg","inode")
	     dbh.execute("drop table if exists `stegjpegfull`")
	     dbh.execute("create table if not exists `stegjpegfull` select distinct a.inode, concat(c.path,c.name) as `Filename`, b.result as `Results` from file as a, stegjpeg as b left join file as c on a.inode = c.inode where a.inode = b.inode")
	     
	except DB.DBError,e:
	     tmp = result.__class__(result)
	     tmp.para("Unable to find Stegdetect Jpeg table for the current image. Did you run Stegdetect Jpeg Scanner?.")
	     tmp.para("IError received was %s" % e)
	     tmp.text("Remember: Stegdetect Scanner will save every Jpeg image it finds inside the Forensic Workstation Hard Disk.", style="red")
	     tmp.text(" This could require a big amount of free space available.")
	     raise Reports.ReportError(tmp)

	        
	
	try:
            result.table(
                elements = [ InodeType('Inode','inode',
                                link = query_type(case=query['case'],
                                                  family='Disk Forensics',
                                                  report='ViewFile',
                                                  __target__='inode')),
                             StringType('Filename','Filename'),
                             StringType('Stegdetect Results', 'Results') ],
                table='stegjpegfull',
                case=query['case'],
                )
        
	except DB.DBError,e:
            result.para("Error reading the Jpeg Steg Found table. Did you remember to run the AFT Jpegs  scanner? (not really)")
            result.para("Error reported was:")
            result.text(e,style="red")		

