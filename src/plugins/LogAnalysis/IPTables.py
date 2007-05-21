""" This is a module for importing IPTables log files.

IPTables usually loged via syslog and the ipt_LOG module. This parser
will import some of the fields exported (the exact fields exported are
user selectable). This module discards lines which appear to not
belong to the IPTables service, this is because usually the iptables
messages are mixed with other syslog messages.

The log format is described in the file ip4/netfilter/ipt_LOG.c
"""
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
import pyflag.LogFile as LogFile
from pyflag.FlagFramework import Curry
from pyflag.TableObj import StringType, IPType, IntegerType
import pyflag.conf
config = pyflag.conf.ConfObject()
import pyflag.DB as DB
import re

IPTABLES_FIELDS = [
    ## IPTables_parameter, Name, Description, ColumnType, default, index
    [ 'IN',   'Input IF',    'Interface the packet arrived on', StringType, False, False],
    [ 'OUT',  'Output IF',   'Interface the packet left on', StringType, False, False ],
    [ 'MAC',  'MAC Address', 'MAC addresses from where the packet came', StringType, False, False],
    [ 'SRC',  'Source IP',   'Source IP Address', IPType, True, True],
    [ 'DST',  'Dest IP',     'Destination IP Address', IPType, True, True],
    [ 'LEN',  'Length',      'Length of this packet', IntegerType, True, False],
    [ 'TOS',  'TOS',         'Type of Service', IntegerType, False, False],
    [ 'TTL',  'TTL',         'Time to Live', IntegerType, False, True],
    [ 'ID',   'IP ID',       'IP ID Field', IntegerType, False, False],
    [ 'PROTO', 'Protocol',    'Protocol', StringType, True, True],
    [ 'SPT',   'Source Port', 'Source Port', IntegerType, True, True],
    [ 'DPT',   'Dest Port',   'Destination Port', IntegerType, True, True],

    ## ICMP Stuff:TYPE=8 CODE=0 ID=2832 SEQ=2
    [ 'TYPE',  'ICMP Type',   'Type of ICMP Message', IntegerType, False, True],
    [ 'CODE',  'ICMP Code',   'Code of ICMP Message', IntegerType, False, True],
    [ 'SEQ',   'ICMP Seq',    'Sequence number of ICMP', IntegerType, False, False],

    ## TCP Specific stuff:WINDOW=5840 RES=0x00 SYN URGP=0
    [ 'WINDOW', 'Window',    'TCP Window size', IntegerType, False, False],
    [ 'RES',    'Flags',     'The TCP Reserved flags', IntegerType, False, False],
    
    ]

    
class IPTablesLog(LogFile.Log):
    """ Log parser for IPTables """
    name = "IPTables"

    def parse(self, query, datafile="datafile"):
        LogFile.Log.parse(self, query, datafile)

        self.datafile = query.getarray(datafile)
        self.cre = re.compile("([A-Z]+)=([^ ]*)")
        self.prefix_re = re.compile("([^ :]+):IN=")
        
        self.fields = [ StringType(name="Action", column="action") ]
        self.parameters = {}
        for parameter, name, desc, column, default, index in IPTABLES_FIELDS:
            if query.has_key(parameter):
                new_column = column(name=name, column=parameter)
                new_column.index = index
                self.fields.append(new_column)
                self.parameters[parameter] = new_column

        if len(self.fields)==0:
            raise RuntimeError("No columns were selected")

    def get_fields(self):
        for row in self.read_record():
            fields = {}
            match = self.prefix_re.search(row)
            if match:
                fields["action"] = match.group(1)
            
            for match in self.cre.finditer(row):
                try:
                    key, value = self.parameters[match.group(1)].insert(match.group(2))
                    
                    fields[key] = value
                except KeyError:
                    pass

            if fields:
                yield fields

    def form(self, query, result):
        def select_columns(query,result):
            """ Create a selection box of all the fields we support """
            for parameter, name, desc, column, default, index in IPTABLES_FIELDS:
                if not query.has_key(name):
                    query[parameter] = default
                    
                result.checkbox("%s (%s)" % (parameter, name), parameter, 1, tooltip=desc)
        
        result.wizard(
            names = [ 
                      "Step 1: Select Columns to import",
                      "Step 2: Save Preset",
                      "Step 3: End"],
            callbacks = [
                         select_columns,
                         Curry(LogFile.save_preset, log=self),
                         LogFile.end
                         ],
            )

import time
import pyflag.pyflagsh as pyflagsh
from pyflag.FlagFramework import query_type

class IPTablesLogTest(LogFile.LogDriverTester):
    """ IPTables Log file processing """
    test_case = "Py Flag Test Case"
    test_table = "Test Table"
    test_file = "messages.gz"
    log_preset = "IPTablesTest"

    def test01CreatePreset(self):
        """ Test that IPTables Presets can be created """
        dbh = DB.DBO(self.test_case)
        log = IPTablesLog(case=self.test_case)
        query = query_type(datafile = self.test_file, log_preset=self.log_preset)

        ## Add all the possible columns here:
        for row in IPTABLES_FIELDS:
            query[row[0]]=1

        log.parse(query)
        log.store(self.log_preset)
        
    def test02LoadFile(self):
        """ Test that IPTables Log files can be loaded """
        dbh = DB.DBO(self.test_case)
        log = LogFile.load_preset(self.test_case, self.log_preset, [self.test_file])
        t = time.time()
        ## Load the data:
        for a in log.load(self.test_table):
            pass

        print "Took %s seconds to load log" % (time.time()-t)
            
        ## Check that all rows were uploaded:
        dbh.execute("select count(*) as c from `%s_log`", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 2433)
