# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Name:  $ $Date: 2004/10/23 15:48:12 $
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

""" This module implements a scanning mechanism for operating on all files within a given filesystem.

The GenScan abstract class documents a Generic scanner. This scanner is applied on every file in a filesystem during a run of the FileSystem's scan method.
"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.logging as logging
import os,imp
import Scanners

scanners=[]
scanner_names=[]
            
## Open the scanner directory and import all scanner plugins:

for file in os.listdir(config.SCANNER_DIRECTORY):
    if file.endswith('.py'):
        module_name = file[:-3]
        logging.log(logging.DEBUG,"+Will try to import scanner module %s" % module_name)
        try:
            fd = open(os.path.join(config.SCANNER_DIRECTORY,file),'r')
        except IOError,e:
            logging.log(logging.DEBUG, "Unable to open scanner plugin file '%s': %s" % (file,e))

        try:
            module = imp.load_source(module_name,os.path.join(config.SCANNER_DIRECTORY,file),fd)
        except Exception,e:
            logging.log(logging.ERRORS, "*** Unable to load Scanner module %s: %s" % (module_name,e))

        ## Now look through all classes in the module for those which are extending Scanners.GenScanFactory and add those to our scanner list:
        for cls in dir(module):
            try:
                if issubclass(module.__dict__[cls],Scanners.GenScanFactory) and cls!="GenScanFactory":
                    scanners.append(module.__dict__[cls])
                    logging.log(logging.DEBUG,"++Added scanner class %s to Scanner list " % cls)
                    scanner_names.append(cls)
            except (TypeError, NameError) , e:
                continue
