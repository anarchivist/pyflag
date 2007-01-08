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
""" These are a bunch of stand alone reports useful to preview data
before lengthy processing.
"""
import pyflag.Reports as Reports
import FileFormats.RegFile as RegFile
from pyflag.format import Buffer,RAW

class RegistryBrowser(Reports.report):
    """
    Browse a registry file.
    -----------------------

    This reoport allows the browsing of a registry file without
    loading it into a case. This may be useful for a quick preview of
    a system.
    """
    parameters = { 'file':'filename' }
    family = "Preview"
    name = "Registry Browser"
    
    def form(self, query, result):
        result.fileselector("Select registry File","file")

    def display(self, query, result):
        def tree_cb(path):
            b = Buffer(fd = open(query['file'],'r'))
            header = RegFile.RegF(b)
            key = header.get_key(path)
            for k in key.keys():
                try:
                    name = k['key_name'].get_value()
                except:
                    pass
                yield (name,name,'branch')

        def pane_cb(path, result):
            b = Buffer(fd = open(query['file'],'r'))
            header = RegFile.RegF(b)
            key = header.get_key(path)
            result.text("Timestamp: %s" % key['WriteTS'], color='red')
            result.start_table(**{'class':'GeneralTable'})

            ## We dont want to reference the keys because we
            ## will leak memeory while the callback remains stored.
            def details(query,result):
                b = Buffer(fd = open(query['file'],'r'))
                header = RegFile.RegF(b)
                key = header.get_key(path)
                result.heading("Key %s" % path)
                result.text("%s" % key, font='typewriter', wrap='full')
                
                for v in key.values():
                    try:
                        name = "%s"%  v['keyname']
                        result.heading("%s" % name)
                        result.text("%s" % v, font='typewriter', wrap='full')
                    except: pass

            result.toolbar(cb = details, text = "Examine Details", icon = "examine.png")
            
            result.row('Type','Length','Name','Value', **{'class':'hilight'})
            for v in key.values():
                try:
                    t = "%s" % v['data']['val_type']
                    length = "%s" % v['data']['len_data']
                    name = "%s"%  v['keyname']
                    data = "%s" % v['data']
                    data = RAW(data[:100])
                    result.row(t,length,name,data)
                except Exception,e:
                    print e
                    pass
                
        result.tree(tree_cb=tree_cb, pane_cb=pane_cb)
