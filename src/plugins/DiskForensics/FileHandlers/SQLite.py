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
""" This module adds support SQLite 3.0 files. These files are used by lots of applications and in particular they are used by Firefox 3.0 to store history and cache information.

Because SQLite files can represent any table (SQLite is a full blown database in itself). We wanted to make the interface to loading them as flexible as possible:

1) Load all tables in every file and make all data available for searching.

2) Present all tables as pyflag tables. This means all tables can be
searched and filtered appropriately using the PyFlag table widget.
"""
import pyflagsh
import pyflag.tests
import pyflag.Scanner as Scanner
import pyflag.CacheManager as CacheManager
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import InodeIDType, IntegerType, StringType, TimestampType, BlobType
import os, subprocess
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.Magic as Magic
import pyflag.pyflaglog as pyflaglog
from pyparsing import *
import pyflag.DB as DB
import sqlite
import pyflag.Reports as Reports

class SQLiteColumn(StringType):
    def link_display_hook(self, value, row, result):
        q = FlagFramework.query_type(report='SQLite',
                                     family='Disk Forensics',
                                     inode_id = row['Inode'],
                                     case = self.case,
                                     table_name = value)
        result.clear()
        result.link(value, q,pane='popup')

    display_hooks = [link_display_hook]

class SQLiteCaseTable(FlagFramework.CaseTable):
    """ SQLite Tables """
    name = 'sqlite'
    columns = [
        [ InodeIDType, {} ],
        [ SQLiteColumn, dict(name = 'Name', column='name')],
        [ StringType, dict(name = 'Table Definition', column='definition')]
        ]

class SQLitePreCanned(Reports.PreCannedCaseTableReports):
    report = "Browse SQLite Tables"
    family = "Disk Forensics"
    description = "Browse all SQLite tables in the VFS"
    name = [ '/Disk Forensics/File Types/SQLite' ]
    default_table = "SQLiteCaseTable"
    columns = ['Inode', 'FileTable.Filename', 'Name' ]

class SQLiteMagic(Magic.Magic):
    """ Identify SQLite files """
    type = "SQLite 3.x database"
    mime = "application/x-sqlite"
    default_score = 100
    
    regex_rules = [
        ( "SQLite format \d", (0,0))
        ]

    samples = [
        ( 100, "SQLite format 3000000000000000000000000"),
        ]


## The following is a parser for table definitions
fieldname = Word(alphas, alphanums + "_")
fieldtype = Word("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
tablename = Word(alphas, alphanums + "_")
value = dblQuotedString.setParseAction( removeQuotes )
number = Combine( Optional('-') + ( '0' | Word('123456789',nums) ) )
default = Group("DEFAULT" + Optional(value) + Optional(number) + \
                Optional("NULL"))
references = Group("REFERENCES" + Word(alphanums + "()_"))
size = Literal("(").suppress() + number + Literal(")").suppress()
field_list = Literal("(").suppress() + delimitedList(fieldname) + Literal(")").suppress()
keys = Group(Optional("PRIMARY").suppress() + "KEY" + Optional(fieldname) +\
             Optional(field_list))

column = Group(fieldname + Optional(fieldtype) + \
               ZeroOrMore(size | 
                          "UNIQUE" | 
                          "PRIMARY KEY" | 
                          Group(Optional("NOT") + "NULL") |
                          default |
                          references |
                          "AUTOINCREMENT"))


table = Literal("CREATE TABLE").suppress() + tablename + Literal("(").suppress() + \
        delimitedList(keys | column) + Literal(")").suppress()


## These are table fixups which can be used to over ride the default
## mapping between SQLite columns and PyFlag columns.
fixups = {
#    'dateAdded': [ TimestampType, {} ],
#    'expiry': [ TimestampType, {} ],
    }

def build_case_table(prefix, definition):
    """ Takes an SQLite definition and builds a pyflag case table.

    The new case table will have a prefix as specified and table name
    as specified in the definition.
    """
    try:
        result = table.parseString(definition)
    except Exception,e:
        raise RuntimeError("Unable to parse %s\n\n%s: %s" % (
            definition, e.msg, e.markInputline()))
    
    case_table = FlagFramework.CaseTable()
    case_table.name = "%s_%s" % (prefix, result[0])
    case_table.columns = []
    case_table.column_names = []
    
    ## This is a lookup dictionary converting from SQLite table types
    ## to PyFlag ColumnTypes
    lookup_types = dict(
        INTEGER = IntegerType,
        LONGVARCHAR = StringType,
        TIMESTAMP = TimestampType,
        TEXT = StringType,
        BLOB = BlobType,
        )

    for row in result[1:]:
        col_name = row[0]
        if col_name=='KEY':
            continue
        try:
            col_type = row[1]
        except IndexError:
            col_type = "VARCHAR"

        try:
            new_column_type, args = fixups[col_name]
            args['name'] = col_name
            args['column'] = col_name
            new_column = [ new_column_type, args]
        except KeyError:
            new_column = [ lookup_types.get(col_type.upper(), StringType), 
                           dict(name = col_name, column = col_name) ]
            
        case_table.columns.append( new_column )
        case_table.column_names.append(col_name)
        
    return case_table

class SQLiteScanner(Scanner.GenScanFactory):
    """ Examine SQLite files """
    default = True
    depends = ['TypeScan']
    group = 'FileScanners'

    class Scan(Scanner.StoreAndScanType):
        types = ('application/x-sqlite',)

        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG, "Opening %s for SQLite scanning", self.inode)

            filename = CacheManager.MANAGER.provide_cache_filename(self.case, self.fd.inode)
            db = sqlite.connect(filename)
            ldbh = db.cursor()
            ldbh2 = db.cursor()
            ldbh.execute("select * From sqlite_master")
            dbh = DB.DBO(self.case)
            for row in ldbh:
                if row[0]=='table':
                    dbh.insert('sqlite',
                               name = row[1],
                               inode_id = self.fd.inode_id,
                               definition = row[4])

                    case_table = build_case_table("sqlite_%s" % self.fd.inode_id,
                                                  row[4])
                    
                    ## Create our copy of this table
                    case_table.create(dbh)
                    
                    ## Insert all the data into our copy of the table
                    ldbh2.execute("select * from %s" % row[1])
                    dbh.mass_insert_start(case_table.name)                    
                    for row in ldbh2:
                        args = {}
                        for i in range(len(row)):
                            if row[i]!=None:
                                args[case_table.column_names[i]] = row[i]

                        dbh.mass_insert(**args)

                    dbh.mass_insert_commit()
                            
class SQLiteScannerTest(pyflag.tests.ScannerTest):
    """ Test handling of SQLite files """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.5.dd"
    subsystem = 'Standard'
    offset = "16128s"
    
    def test01RunScanner(self):
        """ Test scanner handling of SQLite files """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'SQLiteScanner'])


class BrowseSQLiteTables(Reports.report):
    """ Browse the tables imported from SQLite files found in the VFS. """
    name = 'SQLite'
    family = "Disk Forensics"
    parameters = {'case': 'flag_db',
                  'inode_id': 'numeric',
                  'table_name': 'string'}
    
    def display(self, query, result):
        inode_id = int(query['inode_id'])
        name = query['table_name']
        
        ## Which table is it?
        dbh = DB.DBO(query['case'])
        dbh.execute("select * from sqlite where inode_id = %r and name=%r",
                    inode_id, name)
        row = dbh.fetch()
        if row:
            case_table = build_case_table("sqlite_%s" % inode_id,
                                          row['definition'])
            result.table(
                table = case_table.name,
                elements = [e for e in case_table.bind_columns(query['case']) ],
                case = query['case']
                )

    def form(self, query, result):
        result.textfield("Inode ID", 'inode_id')
        dbh = DB.DBO(query['case'])
        try:
            result.selector("Table Name", 'table_name', DB.expand('select name as `key`,name as value from sqlite where inode_id=%r', query['inode_id']), case=query['case'])
        except KeyError, e:
            pass

if __name__=="__main__":
    test_string = "CREATE TABLE moz_bookmarks_roots (root_name VARCHAR(16) UNIQUE, folder_id INTEGER)"
    test_string = "CREATE TABLE groups (id           INTEGER PRIMARY KEY,                    name         TEXT NULL)"

    test_string = "CREATE TABLE sqlite_sequence(name,seq)"
    test_string = "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, favicon_id INTEGER, frecency INTEGER DEFAULT -1 NOT NULL)"
    test_string = "CREATE TABLE moz_inputhistory (place_id INTEGER NOT NULL, input LONGVARCHAR NOT NULL, use_count INTEGER, PRIMARY KEY (place_id, input))"
    try:
        result = table.parseString(test_string)

        print "Table %s" % result[1]
        for row in result[3:]:
            print row
            
    except Exception,e:
        print "Error: %s" % e.msg
        print e.markInputline()
    
