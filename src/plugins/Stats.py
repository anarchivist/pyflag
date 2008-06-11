# ******************************************************
# Copyright 2007: Commonwealth of Australia.
#
# Michael Cohen <scudette@users.sourceforge.net>
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

""" PyFlag module for viewing statistics about the current VFS """
import pyflag.Reports as Reports
from pyflag.FlagFramework import Curry,query_type
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry

class StatsView(Reports.report):
    """ Show statistics about the current case """
    family = "Case Management"
    name = "Stats View"
    
    def display(self, query, result):
        handlers = [ x(query['case']) for x in Registry.STATS_HANDLERS.classes ]
        
        def tree_cb(path):
            branch = path.split('/')[1:]

            for h in handlers:
                for entry in h.render_tree(branch, query):
                    yield entry

        def pane_cb(path, result):
            branch = path.split('/')[1:]
            if not branch:
                result.heading("Display stats")

            else:
                for h in handlers:
                    h.render_pane(branch, query, result)

        result.tree(tree_cb = tree_cb, pane_cb = pane_cb)
        
