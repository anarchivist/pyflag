# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Name:  $ $Date: 2004/10/26 01:07:53 $
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

This is just a python module so it will be included by the rest of flag when it runs. Make sure to add quotes around strings, and ensure there are no leading spaces at the start of every line """

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
    def parse(self):
        """ This utility function loads the configuration file from the users home directory.
      
        """
        ConfObject.config = ConfigParser.SafeConfigParser({"prefix":sys.prefix,"pyflagdir":"%s/../"%sys.modules['pyflag'].__path__[0]})
        ConfObject.config.read([sys.modules['pyflag'].__path__[0]+"/pyflagrc",os.path.expanduser('~/.pyflagrc')])

    def __init__(self):
        """ Collect parameters from all sections into a single dict.

        Note that we add these as dynamic attributes to our own class...
        """
        if not ConfObject.config:
            self.parse()
            for section  in  self.config.sections():
                for param in self.config.options(section):
                    uparam=param.upper()
                    ## We can not trash our own methods, because we use upper case here
                    if not ConfObject.__dict__.has_key(uparam):
                        ## Try storing values as integers first, then as string
                        try:
                           value=int(self.config.get(section,param))
                        except ValueError:
                            value=self.config.get(section,param)

                        ## If there is an environment variable - it overrrides this:
                        try:
                            value=os.environ["PYFLAG_%s" % uparam]
                        except KeyError:
                            pass

#                        print "Adding paramter %s->%s" % (uparam,value)
                        ConfObject.__dict__[uparam]=value
