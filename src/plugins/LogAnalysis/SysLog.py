""" This module implements a Comma Seperated Log driver for PyFlag """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import time
import plugins.LogAnalysis.Simple as Simple

class Syslog(Simple.SimpleLog):
    """ Log parser designed to handle simple syslog files
    """
    name = "Syslog"
    
    def get_fields(self):
        for row in self.read_record():
            tmp=row.split(" ",4)
            ts = ' '.join(tmp[:3])
            yield ( time.strftime("1970%m%d%H%M%S",
                                  time.strptime(ts, "%b %d %H:%M:%S"))
                    , tmp[3], tmp[4])
            
    def form(self, query, result):
        self.draw_type_selector(result)

