# Volatility
# Copyright (C) 2008 Volatile Systems
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from forensics.object2 import *
from vutils import *
from time import gmtime,strftime 
from forensics.linux.info import info_systime, info_timezone,\
    info_cpus, info_system_utsname

class linident(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 AAron Walters'
    meta_info['contact'] = 'awalters@volatilesystems.com'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'https://www.volatilesystems.com/default/volatility'
    meta_info['os'] = 'Linux'
    meta_info['version'] = '1.0'
      
    # This module extends the standard parser. This is accomplished by 
    # overriding the forensics.commands.command.parse() method. The 
    # overriding method begins by calling the base class method directly
    # then it further populates the OptionParser instance.

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-p', '--profile',
            help='Profile for object definitions',
            action='store', type='string', dest='profile')

        self.op.add_option('-s', '--systemmap',
            help='System Map for symbols',
            action='store', type='string', dest='systemmap')

    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Identify image properties"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):

	(profile, addr_space, symtab, types) = linux_load_and_identify_image( \
            self.op, self.opts)

        theProfile = Profile(abstract_types=profile)

        # Get system time
        timespec = info_systime(addr_space, theProfile, symtab)
	tv_sec = timespec.tv_sec
	time = self.format_time(tv_sec)

        # Get timezone information
        sys_tz = info_timezone(addr_space, theProfile, symtab)
        tz_minuteswest = sys_tz.tz_minuteswest
	tz_hours = tz_minuteswest/60
	tz_dsttime = sys_tz.tz_dsttime

        # Get the number of cpus
        num_cpus = info_cpus(addr_space, theProfile, symtab)

        # Get utsname info
        system_utsname = info_system_utsname(addr_space, theProfile, symtab)
        if not system_utsname:
	    print "Cannot access uts information"
	    return

        release = read_null_string(addr_space, theProfile.abstract_types,\
                ['new_utsname', 'release'], system_utsname.offset)
        nodename = read_null_string(addr_space, theProfile.abstract_types,\
                ['new_utsname', 'nodename'], system_utsname.offset)
        sysname = read_null_string(addr_space, theProfile.abstract_types,\
                ['new_utsname', 'sysname'], system_utsname.offset)
        version = read_null_string(addr_space, theProfile.abstract_types,\
                ['new_utsname', 'version'], system_utsname.offset)
        machine = read_null_string(addr_space, theProfile.abstract_types,\
                ['new_utsname', 'machine'], system_utsname.offset)
        domainname = read_null_string(addr_space, theProfile.abstract_types,\
                ['new_utsname', 'domainname'], system_utsname.offset)

        print "%-11s: %s"%("DUMPFILE",self.opts.filename)
        print "%-11s: %d"%("CPUS",num_cpus)
        print "%-11s: %s"%("GMTDATE",time)
       	print "%-11s: %s"%("TIMEZONE","GMT -%d (minutes west: %d dsttime: %d)"%(tz_hours,tz_minuteswest,tz_dsttime))
        print "%-11s: %s"%("RELEASE",release)
        print "%-11s: %s"%("NODENAME",nodename)
        print "%-11s: %s"%("SYSNAME",sysname)
        print "%-11s: %s"%("VERSION",version)
        print "%-11s: %s"%("MACHINE",machine)
        print "%-11s: %s"%("DOMAINNAME",domainname)

    def format_time(self, time):
        ts=strftime("%a %b %d %H:%M:%S %Y",
                        gmtime(time))
        return ts
