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
""" This module uses the indexing tools to scan the logical files within an image. This allows us to do keyword matching against compressed files, PST files etc.
"""
import pyflag.pyflaglog as pyflaglog
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import query_type, Curry
import pyflag.FileSystem as FileSystem
import pyflag.Reports as Reports
import pyflag.Registry as Registry
import pyflag.IO as IO
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import index,os,time,re
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.UI as UI
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, IntegerType, ColumnType
import pyflag.parser as parser

config.add_option("INDEX_ENCODINGS", default="['UTF-8','UTF-16LE']",
                  help="A list of unicode encodings to mutate the "
                  "dictionary through for indexing")

##class IndexTable(FlagFramework.CaseTable):
##    name = 'LogicalIndexOffsets'
##    columns = [ [ InodeIDType, dict(case = None) ],
##                [ IntegerType, dict(name='Word ID',column='word_id'), True ],
##                ]

class IndexStatsTables(FlagFramework.EventHandler):
    def create(self, dbh, case):
        dbh.execute("""create table if not exists `LogicalIndexOffsets` (
        `inode_id` INT NOT NULL,
        `word_id` INT NOT NULL ,
        `offset` BIGINT NOT NULL,
        `length` smallint not null,
        `version` int not null
        )""")

        dbh.execute("""CREATE TABLE if not exists `LogicalIndexStats` (
        `id` int NOT NULL,
        `hits` INT NOT NULL,
        PRIMARY KEY  (`id`)
        )""")        

class IndexScan(GenScanFactory):
    """ Keyword Index files """
    ## Indexing must occur after all scanners have run.
    order=200
    default = True
    version = 0

    class Drawer(Scanner.Drawer):
        description = "General Forensics"
        name = "General Forensics"
        contains = ['RegExpScan','IndexScan','MD5Scan','VirScan','CarveScan']
        default = True

    def check_version(self):
        pydbh = DB.DBO()
        pydbh.execute("select max(id) as version from dictionary")
        row = pydbh.fetch()
        return row['version']
    
    def prepare(self):
        ## Create new index trie - This takes a serious amount of time
        ## for large dictionaries (about 2 sec for 70000 words):
        self.index = index.Index(unique=1)
        self.version = self.check_version()
        
        pydbh = DB.DBO(None)
        #Do word index (literal) prep
        pyflaglog.log(pyflaglog.DEBUG,"Index Scanner: Building index trie")
        start_time=time.time()
        pydbh.execute("select word,id from dictionary where type='literal'")
        for row in pydbh:
            if len(row['word'])>3:
                self.index.add_word(row['word'],row['id'], index.WORD_LITERAL)

        pydbh.execute("select word,id from dictionary where type='regex'")
        for row in pydbh:
            if len(row['word'])>3:
                self.index.add_word(row['word'],row['id'], index.WORD_EXTENDED)

        # load words in a number of alternate character sets. The ones
        # we care about atm are utf-8 and utf-16/UCS-2 which is used
        # extensively in windows (e.g word documents). We can easily
        # add more encodings here as necessary.
        pydbh.execute("select word,id from dictionary where type='word'")
        for row in pydbh:
            try:
                word = row['word'].decode("UTF-8").lower()
                for e in config.INDEX_ENCODINGS:
                    w = word.encode(e)
                    if len(w)>3:
                        self.index.add_word(w,row['id'], index.WORD_ENGLISH)
            except UnicodeDecodeError:
                pass

        pyflaglog.log(pyflaglog.DEBUG,"Index Scanner: Done in %s seconds..." % (time.time()-start_time))

    def reset_entire_path(self, path):
        GenScanFactory.reset_entire_path(self, path)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `LogicalIndexOffsets`")
        
        ## Here we reset all reports that searched this disk
        FlagFramework.reset_all(case=self.case,report='SearchIndex', family='Keyword Indexing')
        dbh.execute("delete from `LogicalIndexStats`")

    def multiple_inode_reset(self, inode_glob):
        GenScanFactory.multiple_inode_reset(self, inode_glob)

        dbh = DB.DBO(self.case)
        dbh.execute("delete from `LogicalIndexOffsets`")
         
        ## Here we reset all reports that searched this disk
        FlagFramework.reset_all(case=self.case,report='SearchIndex', family='Keyword Indexing')
        dbh.execute("delete from `LogicalIndexStats`")

    def reset(self, inode):
        """ This deletes the index file and drops the LogicalIndex table.

        Note: At present reseting the index scanner on _ANY_ inode
        will cause it to be reset on all inodes. This is because it
        would be too confusing if users scanned parts of the VFS using
        different dictionaries.
        """
        
        GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `LogicalIndexOffsets`")
        ## Here we reset all reports that searched this disk
        FlagFramework.reset_all(case=self.case,report='SearchIndex', family='Keyword Indexing')
        dbh.execute("delete from `LogicalIndexStats`")

    def destroy(self):
        ## Destroy our index handle which will close the file and free memory
        del self.index
        
        dbh=DB.DBO(self.case)
        ## Ensure indexes are built on the offset table:
        dbh.check_index("LogicalIndexOffsets","word_id")
        
    class Scan(MemoryScan):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            MemoryScan.__init__(self, inode,ddfs,outer,factories,fd=fd)
            ## Check we are operating with the correct dictionary version
            if self.outer.version != self.outer.check_version():
                self.outer.prepare()

            ## Make sure the index is fresh:
            outer.index.clear_set()
            
            self.dbh = DB.DBO(fd.case)
            self.dbh.mass_insert_start('LogicalIndexOffsets')
            self.inode_id = fd.inode_id
            self.stats = {}

            # try to set size. It is helpful to know the correct file size so
            # we can ignore matches which begin after the end of the file+slack
            # space.
            try:
                self.size = self.fd.size
            except AttributeError:
                try:
                    fd.slack = True
                    fd.seek(0, 2)
                    self.size = fd.tell()
                    fd.seek(0, 0)
                    fd.slack=False
                except:
                    pass
            
        def process_buffer(self,buff):
            # Store indexing results in the dbase
            for offset, matches in self.outer.index.index_buffer(buff):
                # skip matches not starting in this file
                if self.size > 0 and offset+self.offset > self.size:
                    #print "skipping a match in %s" % self.inode_id
                    continue
                for id, length in matches:
                    try:
                        self.stats[id] += 1
                    except:
                        self.stats[id] = 1
                   
                    self.dbh.mass_insert(
                        inode_id = self.inode_id,
                        word_id = id,
                        offset = offset+self.offset,
                        length = length,
                        version = self.outer.version
                        )

        def slack(self,data,metadata=None):
            """ deal with slack space the same as any other data """
            return self.process(data, metadata)

        def finish(self):
            self.dbh.mass_insert_commit()
            del self.dbh
##            for k,v in self.stats.items():
##                self.dbh.execute("select 1 from LogicalIndexStats where id=%r", k)
##                if self.dbh.fetch():
##                    self.dbh.update('LogicalIndexStats', where="id=%r" % k, _hits = 


## Install the dictionary in the default db
class IndexEventHandler(FlagFramework.EventHandler):
    def init_default_db(self, dbh, case):
        dbh.execute("""CREATE TABLE `dictionary` (
        `id` int auto_increment,
        `word` VARCHAR( 250 ) binary NOT NULL ,
        `class` VARCHAR( 50 ) NOT NULL ,
        `encoding` SET( 'all', 'ascii', 'ucs16' ) DEFAULT 'all' NOT NULL,
        `type` set ( 'word','literal','regex' ) DEFAULT 'literal' NOT NULL,
        PRIMARY KEY  (`id`))""")
        
 
## These reports allow the management of the Index Dictionary:
class BuildDictionary(Reports.report):
    """ Manipulate dictionary of search terms to index on """
    parameters = {}
    name="Build Dictionary"
    family="Keyword Indexing"
    description = "Builds a dictionary for indexing "

    def display(self,query,result):
        ## The dictionary is site wide and lives in the FlagDB
        dbh=DB.DBO()
        ## class_override the class variable:
        try:
            if len(query['class_override'])>3:
                del query['class']
                query['class']=query['class_override']
                del query['class_override']
                
        except KeyError:
            pass

        ## Do we need to add a new entry:
        try:
            if len(query['word'])<3:
                raise DB.DBError("Word is too short to index, minimum of 3 letter words")
            
            if query['action']=='insert':
                if len(query['class'])<3:
                    raise DB.DBError("Class name is too short, minimum of 3 letter words are used as class names")
                ## We only insert into the dictionary if the word is
                ## not in there already:
                dbh.execute("select * from dictionary where word=%r limit 1",(query['word']))
                row = dbh.fetch()
                if not row:
                    dbh.insert("dictionary",
                               **{'word': query['word'],
                                  'class': query['class'],
                                  'type': query['type']})
                    
            elif query['action']=='delete':
                dbh.delete("dictionary", _fast = True,
                           where="word=%r and type=%r" % (query['word'],query['type']))
                                
        except KeyError:
            pass
        except DB.DBError,e:
            result.text("Error: %s" % e,style='red')
            result.text("",style='black')
            
        result.heading("Building Dictionary")

        ## Draw a form allowing users to add or delete words from the dictionary
        form=result.__class__(result)
        form.start_form(query)
        form.start_table()
        form.const_selector("Action:",'action',('insert','delete'),('Add','Delete'))
        form.textfield('Word:','word')        
        form.selector('Classification:','class','select class as `key`,class as `value` from dictionary group by class order by class',())
        form.textfield('(Or create a new class:)','class_override')
        form.const_selector('Type:','type',('word','literal','regex'),('word','Literal','RegEx'))
        form.end_table()
        form.end_form('Go')

        table=result.__class__(result)
        table.table(
            elements = [ StringType('Word','word'),
                         StringType('Class','class'),
                         StringType('Type','type') ],
            table='dictionary',
            case=None,
            )
        result.row(table,form,valign='top')

class OffsetType(IntegerType):
    hidden = True
    LogCompatible = False
    
    def __init__(self, name='', column='', table=None,fsfd=None):
        self.fsfd = fsfd
        IntegerType.__init__(self, name,column, table=table)
        
    def display(self, offset, row, result):
        result = result.__class__(result)
        inode = row['Inode']

        query = query_type(case=self.fsfd.case,
                           family="Disk Forensics",
                           report='ViewFile',
                           mode='HexDump',
                           inode_id=inode,
                           hexlimit=max(offset-50,0),
                           highlight=offset, length=row['Length'])
        result.link(offset, target=query)
        return result

## This ColumnType is quite expensive - I guess its necessary though
class DataPreview(ColumnType):
    """ A previewer for the hit. """
    ## Cant search on this data type at all.
    symbols = {}
    LogCompatible = False

    def __init__(self, name='', case=None, width=20, table="LogicalIndexOffsets"):
        self.case = case
        self.table = table
        self.name = name
        self.width =width

    def select(self):
        return "concat(%s,',', %s,',', %s)" % (self.escape_column_name("offset"),
                                       self.escape_column_name("inode_id"),
                                       self.escape_column_name("length"))
    
    def display(self, value, row, result):
        ## We expect ints from the DB - do nothing otherwise
        try:
            offset, inode_id, length = value.split(",")
            offset = int(offset)
            length = int(length)
        except: return

        ## Look through the files and make a preview view of each hit
        fsfd = FileSystem.DBFS(self.case)
        low = max(0,offset - self.width)
        high = offset + self.width + length
        fd = fsfd.open(inode_id = inode_id)
        fd.slack = True
        fd.overread = True
        fd.seek(low)

        result = result.__class__(result)
        result.text(fd.read(offset-low), font='typewriter', style='black', sanitise='full')
        result.text(fd.read(length), font='typewriter',  style='red',sanitise='full')
        result.text(fd.read(50), font='typewriter', style='black',sanitise='full')

        return result

class WordColumn(ColumnType):
    symbols = { '=': 'hit'}
    inactive = False
    
    def __init__(self, name = 'Word', case=None):
        self.case = case
        ColumnType.__init__(self, column = 'word_id', name = name,
                            table='LogicalIndexOffsets')

    def plain_display_hook(self, value, row, result):
        dbh = DB.DBO()
        dbh.execute("select word, type from dictionary where id=%r limit 1", value)
        row = dbh.fetch()
        word=row['word']
        
        if row['type'] in ['literal','regex']:
            result.text(word.decode("ascii", "ignore"))
        else:
            ## Force it to ascii for display
            result.text(word.decode("utf8"))

    display_hooks = [ plain_display_hook, ColumnType.link_display_hook ]
    
    def operator_hit(self, column, operator, arg):
        """ Search for a hit in the dictionary """
        dbh = DB.DBO()
        dbh.execute("select id from dictionary where word = %r limit 1", arg)
        row = dbh.fetch()
        if not row:
            ## If there is nowhere to report the error - fall back to
            ## a noop
            #if not self.ui:
            #    return "1"

            ## Allow the user to reindex the currently selected set of
            ## inodes with a new dictionary based on the new word
            self.ui.heading("Word %r not found in dictionary" % arg)
                
            ## Remove any references to the LogicalIndexOffsets table
            ## - this will allow us to count how many inodes are
            ## involved in the re-indexing without making references
            ## to this column type.
            elements = [ e for e in self.elements if e.table != "LogicalIndexOffsets" ]

            ## Calculate the new filter string
            sql = parser.parse_to_sql(self.ui.defaults['filter'],
                                      elements, None)

            final_sql = "%s where %s" % (UI._make_join_clause(elements),
                                                  sql)
            cdbh = DB.DBO(self.case)
            cdbh.execute("select count(*) as c %s" % final_sql)
            count = cdbh.fetch()['c']
            cdbh.execute("select sum(inode.size) as s %s" % final_sql)
            total = cdbh.fetch()['s']

            self.ui.para("This will affect %s inodes and require rescanning %s bytes" % (count,total))

            ## Ok - Show the error to the user:
            raise self.ui

        return "(%s = %s)" % (self.escape_column_name(self.column),
                              row['id'])
        
class ClassColumn(WordColumn):
    """ This shows the class of the dictionary word """
    def __init__(self, **kwargs):
        kwargs['name'] = "Class"
        WordColumn.__init__(self, **kwargs)
        self.dict_column = 'class'

    def where(self):
        return "(substring((select class from `%s`.dictionary where id=`%s`),1,1)!='_')" % (config.FLAGDB, self.column)

class SearchIndex(Reports.report):
    """ Search for indexed keywords """
    description = "Search for words that were indexed during filesystem load. Words must be in dictionary to be indexed. "
    name = "Search Indexed Keywords"
    family = "Keyword Indexing"

    def display(self,query,result):
        case=query['case']
        fsfd = FileSystem.DBFS(case)
        groupby = query.get('groupby',None)
        del result.defaults['groupby']
        result.table(
            elements = [ InodeIDType(case=case),
                         WordColumn(name='Word'),
                         ClassColumn(),
                         OffsetType(column='offset', name='Offset', fsfd=fsfd),
                         IntegerType(column='length', name='Length'),
                         DataPreview(column='length', name='Preview', fsfd=fsfd),
                         ],
            table = 'LogicalIndexOffsets',
            groupby = groupby,
            case =case,
            )


class BrowseIndexKeywords(Reports.report):
    """ Show a summary of the results of the index keywords search.  The search indexed keywords report can then be used to view the results."""
    name = "Keyword Index Results Summary"
    family = "Keyword Indexing"
    description="This report summarises the results of the index scanning"

    def display(self,query,result):
        result.refresh(0, FlagFramework.query_type(report = "Search Indexed Keywords",
                                                   family = query['family'],
                                                   groupby = 'Word',
                                                   case = query['case']
                                                   ))

import pyflag.UI as UI

## This makes sure that we only add methods to the class
if "Keyword" not in UI.TableRenderer.__doc__:
    original_render_tools = UI.TableRenderer.render_tools
    original_render = UI.TableRenderer.render

class TableRenderer(UI.TableRenderer):
    """ A modified Table renderer which supports Keyword Indexes """
    def render_tools(self, query, result):
        original_render_tools(self, query, result)
        self.indexing_button(query, result)

    ## Install our toolbar button in the main Table renderer:
    def indexing_button(self, query, result):
        """ This adds a new column for the keyword hits """
        new_query = query.clone()
        if query.has_key("indexing_column"):
            del new_query["indexing_column"]

            result.toolbar(link = new_query, icon="nosearch.png",
                           tooltip = "Hide Index hits", pane = 'self')

        else:
            new_query['indexing_column'] = 1            
            result.toolbar(link = new_query, icon="search.png",
                           tooltip = "Show Index hits", pane = 'self')

    def render(self, query,result):
        if query.has_key("indexing_column"):
            print "Will add the indexing column"
            self.elements.append(WordColumn(name='Word',
                                            case = query['case']))
            self.elements.append(DataPreview(name='Preview',
                                             case = query['case']))

        original_render(self, query, result)
        
## Install the new updated table renderer:
UI.TableRenderer = TableRenderer

## This is how we can add new words to the dictionary and facilitate scanning:
#class AddWords(reports.Repo


## Unit tests
import unittest
import pyflag.mspst
import pyflag.tests

class LogicalIndexTests(unittest.TestCase):
    """ Logical Index Tests """
    test_case = "PyFlagNTFSTestCase"
    def build_idx(self, dictionary):
        ## build an indexer:
        idx = index.Index()

        for k,v in dictionary.items():
            idx.add_word(v, k, index.WORD_ENGLISH)

        return idx
    
    def test01SimpleIndexTests(self):
        """ Test indexing engine - simple words """
        dictionary = { 5:"hello", 10:"world", 15:"hell" }
        idx = self.build_idx(dictionary)
        
        ## This is the buffer we will be testing (note the capital match):
        line = "Hello cruel world, hello..."

        matching_words = []
        for offset, matches in idx.index_buffer(line):
            for id , length in matches:
                word = dictionary[id]
                matched = line[offset:offset+length]
                #print word, matched
                self.assertEqual(word.lower(), matched.lower())
                matching_words.append(matched)

        self.assert_("Hello" in matching_words, "Unable to match capitalised word")

    def test02UCS16Indexing(self):
        """ Test unicode indexing - simple words """
        dictionary = { 5: u"hello", 10:u"world" }
        ## These are the encodings which will be tested:
        encodings = ["utf-16_le", "utf-16_be", "rot-13", "ms-pst"]
        line = u"Hello cruel world, hello..."

        print
        for encoding in encodings:
            print "Testing encoding %s" % encoding
            idx = index.Index()
            for k,v in dictionary.items():
                idx.add_word(v.encode(encoding), k, index.WORD_LITERAL)

            data = line.encode(encoding)
            for offset, matches in idx.index_buffer(data):
                for id , length in matches:
                    word = dictionary[id]
                    matched = data[offset:offset+length]
                    print "word: %s" % word, "matched: %r" % matched
                    self.assertEqual(word.lower(), matched.decode(encoding).lower())
                    
    def test03RegExIndexing(self):
        """ Test Regex indexing """
        dictionary = {
            ## Test for IP Addresses
            5: r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            7: r"2.\.",
            
            ## Test character classes
            10: r"[abcd]+",
            11: r"[1-9]+",
            12: r"[19268]{4,99}",
            15: r"[a-zA-Z]+",

            ## . matches everything:
            20: r"A.d.e.s.s",

            ## Hex representation of characters:
            30: r"I\x50\x20",
            31: r"A\x64+",

            ## Character classes in character classes (Note the . is
            ## literal here):
            40: r"s[ \d.]+",
            }

        ## This documents some of the expected results (There will be
        ## more than that but we test that at least these were found.
        expected = {
            5: ['10.10.10.1', '192.168.30.1', '0.10.10.1'],
            7: ['22.', '23.'],
            10: ['dd', 'd' ],
            11: ['19922', '1666888', '66888'],
            12: ['19922', '1666888', '66888'],
            15: ['Addresses', 'Some', 'resses'],
            20: ['Addresses'],
            30: ['IP '],
            31: ["Add"],
            40: ["s 10.10.10.1"],
            }

        data = """
        Some IP Addresses 10.10.10.1, 192.168.30.1 - 19922.1666888.3434.2223.
        """

        idx = index.Index()
        for k,v in dictionary.items():
            idx.add_word(v, k, index.WORD_EXTENDED)

        ## look at all the matches
        for offset, matches in idx.index_buffer(data):
            for id , length in matches:
                word = dictionary[id]
                matched = data[offset:offset+length]
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "word: %r matched %r" % (word,matched))
                try:
                    del expected[id][expected[id].index(matched)]
                except ValueError:
                    pass

        for id,v in expected.items():
            self.assertEqual(v,[],"Some terms were not found. Expected %s to find %s" % (dictionary[id],v))

    def test04uniqueIndexing(self):
        """ Test unique indexing mode """
        idx = index.Index(unique=True)
        idx.add_word("\d{2,5}", 1, index.WORD_EXTENDED)

        data = "1234567890" * 3
        results = []
        for offset, matches in idx.index_buffer(data):
            for id, length in matches:
                print "Found hit %s" % data[offset:offset+length]
                results.append(offset)

        ## We should only find a single hit since we are in unique
        ## mode
        self.assertEqual(len(results),1)

class LogicalIndexMemoryTest(LogicalIndexTests):
    """ Test memory leaks under the indexer """

    total_size = 100*1024*1024
    
    def test01IndexTest(self):
        """ Test memory footprint of indexing engine """
        dictionary = { 5:"hello", 10:"world", 15:"hell",
                               20:"this", 40:"is", 60:"a test" }
        idx = self.build_idx(dictionary)
        
        line = "Hello cruel world, this is a test of indexing" * 1024
        size = self.total_size
        while size>0:
            size -= len(line)
            matching_words = []
            for offset, matches in idx.index_buffer(line):
                for id , length in matches:
                    word = dictionary[id]
                    matched = line[offset:offset+length]
                    matching_words.append(matched)
        
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS

class LogicalIndexScannerTest(pyflag.tests.ScannerTest):
    """ Test Logical Index Scanner """
    test_case = "PyFlagIndexTestCase"
    test_file = "pyflag_stdimage_0.4.sgz"
    subsystem = 'SGZip'
    #subsystem = 'advanced'
    order = 20
    offset = "16128s"

    def test01RunScanners(self):
        """ Running Logical Index Scanner """
        ## Make sure the word secret is in there.
        pdbh = DB.DBO()
        pdbh.execute("select * from dictionary where word='secret' limit 1")
        row = pdbh.fetch()
        if not row:
            pdbh.insert('dictionary', **{'word':'secret', 'class':'English', 'type':'word'})
        
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'IndexScan'])

        dbh = DB.DBO(self.test_case)
        dbh2 = DB.DBO(self.test_case)
        fsfd = DBFS(self.test_case)
        dbh.execute("select inode_id, word,offset,length from LogicalIndexOffsets join %s.dictionary on LogicalIndexOffsets.word_id=pyflag.dictionary.id where word='secret'", config.FLAGDB)
        count = 0
        for row in dbh:
            count += 1
            path, inode, inode_id = fsfd.lookup(inode_id = row['inode_id'])
            fd = fsfd.open(inode=inode)
            fd.overread = True
            fd.slack = True
            fd.seek(row['offset'])
            data = fd.read(row['length'])
            print "Looking for %s: Found in %s at offset %s length %s %r" % (
                row['word'], inode, row['offset'], row['length'],data)
            self.assertEqual(data.lower(), row['word'].lower())

        ## Did we find all the secrets?
        self.assertEqual(count,2)

import unittest,time, random

class HashTrieIndexTests(unittest.TestCase):
    """ Tests the performance of Hash Trie indexing. """
    word_file = "/usr/share/dict/words"
    test_file = "%s/pyflag_stdimage_0.5.dd" % config.UPLOADDIR

    def test01timing_tests(self):
        """ Tests timing of indexing """
        for count in [10, 100, 1000, 10000, 100000]:
            words = [ line.strip() for line in open(self.word_file) if len(line) >= 3 ]
            idx = index.Index()
            t = time.time()
            print "Loading %s words: " % count,

            ## We want to load words from the dictionary in random
            ## order so we dont have a bias due to the fact the
            ## dictionary is sorted.
            for line_count in range(0,count):
                if len(words)==0: break
                i = random.randint(0,len(words)-1)
                idx.add_word(words.pop(i), 1, index.WORD_LITERAL)
                
            new_t = time.time()
            print "Done - %s seconds (%s lines)" % (new_t - t, line_count)
            fd = open(self.test_file)
            count = 0
            while 1:
                data = fd.read(1024*1024)
                if len(data)==0: break

                for offset,matches in idx.index_buffer(data):
                    for id, length in matches:
                        count+=1

            print "Indexed file in %s seconds (%s hits)" % (time.time() - new_t, count)
