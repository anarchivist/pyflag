""" Utilities related to scanners """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
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
import pyflag.Registry as Registry
import pyflag.pyflaglog as pyflaglog
import pyflag.FlagFramework as FlagFramework

def scan_groups_gen():
    """ A Generator yielding all the scan groups (those scanners with
    a Draw subclass)
    """
    for cls in Registry.SCANNERS.classes:
        try:
            drawer_cls = cls.Drawer
        except AttributeError:
            continue

        yield cls

def fill_in_dependancies(scanners):
    """ Will add scanner names to scanners to satisfy all dependancies.

    Will also sort scanners in dependancy order - so that scanners
    which depend on other scanners follow them in the list.
    """
    while 1:
        modified = False

        for i in range(len(scanners)):
            cls = Registry.SCANNERS.dispatch(scanners[i])
            if type(cls.depends)==type(''):
                d = [cls.depends]
            else:
                d = cls.depends

            for dependancy in d:
                if dependancy in scanners[i+1:]:
                    scanners.pop(scanners.index(dependancy))
                    modified = True

                if dependancy not in scanners[:i]:
                    pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"%s depends on %s, which was not enabled - enabling to satisfy dependancy" % (scanners[i],dependancy))
                    scanners.insert(i,dependancy)
                    modified = True

            if modified: break
                
        if not modified: break
