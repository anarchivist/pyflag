""" This module implements a Comma Seperated Log driver for PyFlag """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
import csv
import plugins.LogAnalysis.Simple as Simple

active = False

class CSVLog(Simple.SimpleLog):
    """ Log parser designed to handle comma seperated files """
    name = "CSV"
    
    def get_fields(self):
        return csv.reader(self.read_record())
        
    def form(self,query,result):
        result.end_table()
        result.row("Unprocessed text from file",colspan=5)
        sample = []
        count =0
        for line in self.read_record():
            sample.append(line)
            count +=1
            if count>3:
                break
            
        result.row('\n'.join(sample),bgcolor='lightgray')
        result.end_table()

        self.draw_type_selector(result)
