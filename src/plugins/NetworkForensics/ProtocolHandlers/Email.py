""" This module provides a report that allows the analyst to browse email 
traffic. It complements the RFC2822 scanner that is part of the Disk Forensics 
family."""

# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
import pyflag.FlagFramework as FlagFramework
import pyflag.logging as logging
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
#import pypst2
import pyflag.IO as IO
#import pyflag.FileSystem as FileSystem
#from pyflag.FileSystem import File
import pyflag.Reports as Reports
import pyflag.DB as DB
import StringIO
import re
from pyflag.FlagFramework import normpath

class BrowseEmail(Reports.report):
    """ Slightly modified report for displaying emails in the network forensics family """
    parameters = { 'fsimage':'fsimage' }
    name = "Browse Email"
    family = "Network Forensics"
    description = "This report displays an email item from an email vfs entry as a nicely formatted email message"
    hidden = False

    def form(self, query, result):
	try:
            result.case_selector()
            result.meta_selector(message='FS Image',case=query['case'],property='fsimage')
        except KeyError:
            return result

    def display(self, query, result):
	result.heading("Email sessions in %s " % query['fsimage'])
        result.table(
            columns=('inode','date','`from`','`to`','subject'),
            names=('Inode','Date','From','To','Subject'),
            table=('email_%s' % (query['fsimage'])),
            case=query['case'],
	    links = [FlagFramework.query_type((),
                        family='Disk Forensics', case=query['case'],
                        fsimage=query['fsimage'], __target__='inode',
                        report='View File Contents', mode="Text"
                        ),
                     ],
        )
