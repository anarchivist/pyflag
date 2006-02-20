# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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
""" Configuration modules for flag.

This module parses the pyflagrc file and is called by the rest of the code to work out configuration options etc.

Note that its important for us to know where the system pyflagrc file resides. We use the environment variable PYFLAGRC to know that.
"""

import sys,ConfigParser,os

class ConfObject:
    """ A simple class to facilitate access to the configuration file.

    This basically collects all the configuration parameters specified in the config object into one dictionary. If there are no name clashes, we dont need to worry about sections then. We implement a singleton model to avoid having to parse configuration files more than once.

    All parameters will appear as attributes of this object:
    >>> conf=ConfObject()
    ....    print conf.Attribute

    @cvar config: Stores the ConfigParser object we obtain after parsing the file.
    @note: If the user does not have a configuration file in their home directory, we create it.
    """
    config=None
    def __init__(self):
        for k,v in os.environ.items():
            key = k.upper()[len('PYFLAG_'):]
            if (k==k.upper() and k.startswith('PYFLAG') and
                not self.__class__.__dict__.has_key(key)):
                self.__class__.__dict__[key]=parse_value(v)

def parse_value(v):
    """ Returns a parsed value suitable to be put into the config variable """
    v=v.split(",")

    for i in range(len(v)):
        try:
            v[i] = int(v[i])
        except:
            try:
                if v[i][0]==v[i][-1] and v[i][0] in "'\"":
                    v[i]=v[i][1:-1]
            except:
                pass
                
    if len(v)==1: v=v[0]

    return v
