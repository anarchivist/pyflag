# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
""" Implement a simple logger wrapper.

logging verbosity is controlled through the configuration variable LOG_LEVEL
"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import sys,traceback

## These are predefined logging levels:
ERRORS=1
WARNINGS=2
INFO=3
DEBUG=7
RING_BUFFER_SIZE=20

ring_buffer = []

lookup = { ERRORS: "Critical Error", WARNINGS: "Warning", INFO:"Infomation",DEBUG:"Debug"}

def log(level,message):
    """ Prints the message out only if the configured verbosity is higher than the message's level."""
    global ring_buffer
    string = "%s: %s" % (lookup[level],message)
    
    if config.LOG_LEVEL>=level:
        print string
        ring_buffer.append(string)

        if len(ring_buffer)>RING_BUFFER_SIZE:
            ring_buffer=ring_buffer[-RING_BUFFER_SIZE:]
        
    if level<=ERRORS:
        print traceback.print_tb(sys.exc_info()[2])
