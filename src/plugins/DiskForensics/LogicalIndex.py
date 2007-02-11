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
""" This module uses the indexing tools to scan the logical files within an image. This allows us to do keyword matching against compressed files, PST files etc.

This module contains a Scanner to be called by the scanning framework, and a set of reports allowing the management of the dictionary as well as the querying of the index.

Implementation Note:
The indextools engine stores a 64bit offset for the occurance of the indexed word. This number is split along a bit mask into two components: The block number and the offset within the block.

For example assume that the blocksize is 2^20 (=1,048,576). When the scanner is scanning a new file it allocates blocks of this size, and stores these into the database as inode vs blocknumber pairs. The indextools then stores blocknumber << 20 | offset_within_block.

When we need to retrieve this we get a list of offsets from the indextools. The problem them becomes how to map these indexes back into an inode and relative offset. We do this by selecting those rows which have the given blocknumber, finding out their inode and seeking the relative offset into the inode's file.

Example:
Suppose we find the word 'Linux' at the 27th byte of inode 5 (Assuming the first 4 inodes are smaller than the blocksize 2^20), indextools will store this offset as 5 << 20 | 27. We therefore insert into the database a row saying that block 5 belongs to inode 5.

When we retrieve this offset (o), we search through the db for the inode containing block o>>20 (5) and receive inode 5. We then seek o & (2^20-1) = 27 bytes into it.

Note that if a single file is larger than the blocksize, we have multiple entries in the database assigning a number of blocks to the same inode. This is not a problem if it is taken into account when reassembling the information.

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
from pyflag.TableObj import StringType, TimestampType, InodeType, IntegerType

class IndexTables(FlagFramework.EventHander):
    def create(self, dbh, case):
        dbh.execute("""create table if not exists `LogicalIndexOffsets` (
        `inode_id` INT NOT NULL,
        `word_id` INT NOT NULL ,
        `offset` BIGINT NOT NULL,
        `length` smallint not null
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

    class Drawer(Scanner.Drawer):
        description = "General Forensics"
        name = "General Forensics"
        contains = ['RegExpScan','IndexScan','MD5Scan','VirScan','CarveScan']
        default = True
    
    def prepare(self):
        ## Create new index trie - This takes a serious amount of time
        ## for large dictionaries (about 2 sec for 70000 words):
        self.index = index.Index()
        pydbh = DB.DBO(None)
        #Do word index (literal) prep
        pyflaglog.log(pyflaglog.DEBUG,"Index Scanner: Building index trie")
        start_time=time.time()
        pydbh.execute("select word,id from dictionary where type='literal'")
        for row in pydbh:
            self.index.add_word(row['word'],row['id'], index.WORD_LITERAL)

        pydbh.execute("select word,id from dictionary where type='regex'")
        for row in pydbh:
            self.index.add_word(row['word'],row['id'], index.WORD_EXTENDED)

        # load words in a number of alternate character sets. The ones
        # we care about atm are utf-8 and utf-16/UCS-2 which is used
        # extensively in windows (e.g word documents). We can easily
        # add more encodings here as necessary.
        pydbh.execute("select word,id from dictionary where type='word'")
        for row in pydbh:
            try:
                word = row['word'].decode("UTF-8")
                for e in config.INDEX_ENCODINGS:
                    self.index.add_word(word.encode(e),row['id'], index.WORD_ENGLISH)
            except UnicodeDecodeError:
                pass

        pyflaglog.log(pyflaglog.DEBUG,"Index Scanner: Done in %s seconds..." % (time.time()-start_time))
                
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
            self.dbh = DB.DBO(fd.case)
            self.dbh.mass_insert_start('LogicalIndexOffsets')
            self.inode_id = fd.inode_id
            self.stats = {}

            # try to set size. It is helpful to know the correct file size so
            # we can ignore matches which begin after the end of the file+slack
            # space.
            try:
                fd.slack = True
                fd.seek(0, 2)
                self.size = fd.tell()
                fd.seek(0, 0)
                fd.slack=False
                #print "size is: %d" % self.size
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
                dbh.delete("dictionary",
                           where="word=%r and type=%r" % (query['word'],query['type']))
                                
        except KeyError:
            pass
        except DB.DBError,e:
            result.text("Error: %s" % e,style='red')
            result.text("",style='black')
            
        result.heading("Building Dictionary")

        ## Draw a form allowing users to add or delete words from the dictionary
        form=self.ui(result)
        form.start_form(query)
        form.start_table()
        form.const_selector("Action:",'action',('insert','delete'),('Add','Delete'))
        form.textfield('Word:','word')        
        form.selector('Classification:','class','select class as `key`,class as `value` from dictionary group by class order by class',())
        form.textfield('(Or create a new class:)','class_override')
        form.const_selector('Type:','type',('word','literal','regex'),('word','Literal','RegEx'))
        form.end_table()
        form.end_form('Go')

        table=self.ui(result)
        try:
            table.table(
                elements = [ StringType('Word','word'),
                             StringType('Class','class'),
                             StringType('Type','type') ],
                table='dictionary',
                case=None,
                )
            ## If the table is not there, we may be upgrading from an old version of flag, We just recreate it:
        except DB.DBError:
            dbh.execute("""CREATE TABLE `dictionary` (
            `id` int auto_increment,
            `word` VARCHAR( 250 ) binary NOT NULL ,
            `class` VARCHAR( 50 ) NOT NULL ,
            `encoding` SET( 'all', 'asci', 'ucs16' ) DEFAULT 'all' NOT NULL,
            `type` set ( 'word','literal','regex' ) DEFAULT 'literal' NOT NULL,
            PRIMARY KEY  (`id`))""")
            
            result.para("Just created a new empty dictionary")
            result.refresh(3,query)
            
        result.row(table,form,valign='top')

class OffsetType(IntegerType):
    def __init__(self, name='', column='', fsfd=None):
        self.fsfd = fsfd
        IntegerType.__init__(self, name,column)
        
    def display(self, offset, row, result):
        result = result.__class__(result)
        inode = row['Inode']

        query = query_type(case=self.fsfd.case,
                           family="Disk Forensics",
                           report='ViewFile',
                           mode='HexDump',
                           inode=inode,
                           hexlimit=max(offset-50,0),
                           highlight=offset, length=row['Length'])
        result.link(offset, target=query)
        return result

class DataPreview(OffsetType):
    ## Cant search on this data type at all.
    symbols = {}
    def __init__(self, name='', column='', fsfd=None):
        self.name = name
        self.column = column
        self.sql = column
        self.fsfd = fsfd

    def display(self, length, row, result):
        low = max(0,row['Offset']-50)
        high = row['Offset'] + 50 + length
        fd = self.fsfd.open(inode = row['Inode'])
        fd.slack = True
        fd.overread = True
        fd.seek(low)

        result = result.__class__(result)
        result.text(fd.read(row['Offset']-low), font='typewriter', style='black', sanitise='full')
        result.text(fd.read(length), font='typewriter',  style='red',sanitise='full')
        result.text(fd.read(50), font='typewriter', style='black',sanitise='full')

        return result

class SearchIndex(Reports.report):
    """ Search for indexed keywords """
    description = "Search for words that were indexed during filesystem load. Words must be in dictionary to be indexed. "
    name = "Search Indexed Keywords"
    family = "Keyword Indexing"

    def display(self,query,result):
        case=query['case']
        fsfd = FileSystem.DBFS(case)
        result.table(
            elements = [ InodeType(case=case, column='inode'),
                         StringType(column='word', name='Word'),
                         OffsetType(column='offset', name='Offset', fsfd=fsfd),
                         IntegerType(column='length', name='Length'),
                         DataPreview(column='length', name='Preview', fsfd=fsfd),
                         ],
            table = 'LogicalIndexOffsets join pyflag.dictionary on word_id=id join inode on inode.inode_id = LogicalIndexOffsets.inode_id',
            case =case,
            )


class BrowseIndexKeywords(Reports.report):
    """ Show a summary of the results of the index keywords search.  The search indexed keywords report can then be used to view the results."""
    name = "Keyword Index Results Summary"
    family = "Keyword Indexing"
    description="This report summarises the results of the index scanning"
    def form(self,query,result):
        result.case_selector()

    def display(self,query,result):
        result.heading("Keyword Index Scanning Result Summary")
        dbh=self.DBO(query['case'])
        
        try:
            result.table(
                elements = [ StringType('Index Term', 'word',
                                link = query_type(case=query['case'],
                                                  family="Keyword Indexing",
                                                  report='SearchIndex',
                                                  range=100,
                                                  final=1,
                                                  __target__='keyword')),
                             StringType('Dictionary Class','class'),
                             IntegerType('Number of Hits', 'hits')],
            table='LogicalIndexStats',
            case=query['case'],
            )
        except DB.DBError,e:
            result.para("Unable to display index search results.  Did you run the index scanner?")
            result.para("The error I got was %s"%e)


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
            
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS

class LogicalIndexScannerTest(pyflag.tests.ScannerTest):
    """ Test Logical Index Scanner """
    test_case = "PyFlagIndexTestCase"
    test_file = "pyflag_stdimage_0.2"
    #subsystem = 'sgzip'
    subsystem = 'advanced'
    order = 20
    offset = "16128s"

    def test01RunScanners(self):
        """ Running Logical Index Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'IndexScan'])

        dbh = DB.DBO(self.test_case)
        dbh2 = DB.DBO(self.test_case)
        pdbh = DB.DBO()
        fsfd = DBFS(self.test_case)
        dbh.execute("select inode_id, word,offset,length from LogicalIndexOffsets join %s.dictionary on LogicalIndexOffsets.word_id=pyflag.dictionary.id where word='secret'", config.FLAGDB)
        for row in dbh:
            inode = fsfd.lookup(inode_id = row['inode_id'])
            fd = fsfd.open(inode=inode)
            fd.overread = True
            fd.slack = True
            fd.seek(row['offset'])
            data = fd.read(row['length'])
            print "Looking for %s: Found in %s at offset %s length %s %r" % (
                row['word'], inode, row['offset'], row['length'],data)
            self.assertEqual(data.lower(), row['word'].lower())
