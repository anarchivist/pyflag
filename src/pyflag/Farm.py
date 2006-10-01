# ******************************************************
# Copyright 2006
# Michael Cohen <scudette@users.sourceforge.net>
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

""" A distributed processing framework for PyFlag.

This module and associated plugin implement a distributed processing environment for flag. This facility allows a master flag process to control a group of slaves for processing intensive tasks:

Master   -------->    Slave

Both master and slave are just standard invocations of the flag HTTP Engine, and both have local instances of the pyflag database. (This is the main db which contains NSRL, Whois etc).

In order for this to work, the clients must have access to the relevant files in their own upload dirs. For example if loading a large filesystem, all slaves and clients must have access to the same image file (With the same name and path relative to their respective upload dir). This can be arranged by using NFS for example. The mechanism of making this data viewable is beyond the scope of PyFlag, we assume that all slaves can get to all files in their upload directories.

The case resides in the master process's database. This database must be accessible over the network by the slaves, which must also have the following defined in their .pyflagrc:
master_passwd = ****
master_host = hostname
master_user = root

If not specified these default to be the same as passwd,host and user (for the local database).
""" 
