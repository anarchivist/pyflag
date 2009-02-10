#!/usr/bin/env python
""" Utilities related to scanners """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
    result = []
    dependancies = []

    def find_dependencies(scanner, dependancies):
        """ Fills in scanner's dependancies in dependancies """
        cls = Registry.SCANNERS.dispatch(scanner)
        if type(cls.depends)==type(''):
            depends = [cls.depends]
        else:
            depends = cls.depends

        for d in depends:
            dependancies.append(d)
            find_dependencies(d, dependancies)

    groups = Registry.SCANNERS.get_groups()
    for s in scanners:
        ## Is it a scanner that was specified?
        if s in Registry.SCANNERS.class_names:
            dependancies.append(s)
            find_dependencies(s, dependancies)
        elif s in groups:
            for g in groups[s]:
                #name = ("%s" % g).split(".")[-1]
                name = g.name
                dependancies.append(name)
                find_dependencies(name, dependancies)

    for i in range(len(dependancies)):
        if dependancies[i] not in dependancies[i+1:]:
            result.append(dependancies[i])

    result.reverse()

    return result
