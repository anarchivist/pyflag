# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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

def draw_scanners(query,result):
    result.row("Choose Scanners to run:","",bgcolor='pink')
    scanner_desc = [ i.__doc__.splitlines()[0] for i in Registry.SCANNERS.classes]
    for i in range(len(scanner_desc)):
        scanner_name = Registry.SCANNERS.scanners[i]
        scanner_factory = Registry.SCANNERS.classes[i]
        ## should the checkbox be ticked by default?
        if scanner_name not in query.getarray('scan') and scanner_factory.default:
            result.defaults['scan']=scanner_name

        result.checkbox(scanner_desc[i],"scan",scanner_name )
