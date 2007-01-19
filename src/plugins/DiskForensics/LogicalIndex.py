# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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

## This blocksize is in bits (2^20)
BLOCKBITS=20
BLOCKSIZE=pow(2,BLOCKBITS)

def escape(string):
    return ("%r" % string)[1:-1]

class IndexScan(GenScanFactory):
    """ Keyword Index files """
    ## Indexing must occur after all scanners have run.
    order=200
    default = True

    class Drawer(Scanner.Drawer):
        description = "General Forensics"
        name = "General Forensics"
        contains = ['RegExpScan','IndexScan','MD5Scan','VirScan']
        default = True
    
    def __init__(self,fsfd):
        """ This creates the LogicalIndex table and initialise the index file """
        GenScanFactory.__init__(self, fsfd)
        
        ## These keep the current offset in the logical image. FIXME:
        ## When running in a distributed environment this is not
        ## accessible - maybe we need to pass this in the metadata?
        self.rel_offset = 0
        dbh=DB.DBO(self.case)
        dbh.execute("create table if not exists `LogicalIndex` (`inode` VARCHAR( 250 ) NOT NULL ,`block` INT NOT NULL auto_increment, `block_number` int not null, primary key(block))")
        
        dbh.execute("""create table if not exists `LogicalIndexOffsets` (
        `id` INT NOT NULL ,
        `offset` BIGINT NOT NULL,
        `length` smallint not null
        )""")

        #Create a table that will hold our stats: number of occurrences of each word id we are searching for.
        dbh.execute("""CREATE TABLE if not exists `LogicalIndexStats` (
        `id` int NOT NULL,
        `word` VARCHAR( 250 ) binary NOT NULL,
        `class` VARCHAR( 50 ) NOT NULL,
        `hits` INT NOT NULL,
        PRIMARY KEY  (`id`)
        )""")

        ## The block number must be the largest that is available in the database.
        dbh.execute("select max(block) as `max` from `LogicalIndex`")
        row=dbh.fetch()
        try:
            self.block=int(row['max'])+1
        except: self.block=0

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
            self.index.add_word(row['word'],row['id'], index.WORD_ENGLISH)

        # load words in a number of alternate character sets. The ones
        # we care about atm are utf-8 and utf-16/UCS-2 which is used
        # extensively in windows (e.g word documents). We can easily
        # add more encodings here as necessary.
        pydbh.execute("select word,id from dictionary where type='word'")
        for row in pydbh:
            try:
                word = row['word'].decode("UTF-8")
                for e in config.INDEX_ENCODINGS:
                    self.index.add_word(word.encode(e),row['id'], 0)
            except UnicodeDecodeError:
                pass

        pyflaglog.log(pyflaglog.DEBUG,"Index Scanner: Done in %s seconds..." % (time.time()-start_time))

        #Do regex prep
        pyflaglog.log(pyflaglog.DEBUG,"Index Scanner: Compiling regex")
        start_time=time.time()
        pydbh.execute("select word,id from dictionary where type='regex'")
        self.RegexpRows = [ (re.compile(row['word'],re.IGNORECASE),row['id']) for row in pydbh ]
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
        dbh.execute("delete from `LogicalIndex`")
        dbh.execute("delete from `LogicalIndexOffsets`")
        ## Here we reset all reports that searched this disk
        FlagFramework.reset_all(case=self.case,report='SearchIndex', family='Keyword Indexing')
        dbh.execute("delete from `LogicalIndexStats`")
        #self.dbh.execute("update inode set scanner_cache = REPLACE(scanner_cache,%r,'') ",
        #            (self.__class__.__name__))

    def destroy(self):
        ## Destroy our index handle which will close the file and free memory
        del self.index
        
        dbh=DB.DBO(self.case)
        ## Ensure indexes are built on the offset table:
        dbh.check_index("LogicalIndexOffsets","id")
        
    class Scan(BaseScanner):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            BaseScanner.__init__(self, inode,ddfs,outer,factories,fd=fd)
            self.index = outer.index
            self.RegexpRows = outer.RegexpRows
            self.rel_offset=0
            self.block_number = 0
            self.dbh=DB.DBO(self.case)
            self.dbh.execute("insert into `LogicalIndex` set inode=%r,block_number=%r",(inode,self.block_number))
            ## Note the current block number
            self.block = self.dbh.autoincrement()
            #A dictionary for counting hit stats
            self.stats_count={}
            self.dbh.mass_insert_start("LogicalIndexOffsets")
            
        def process(self,data,metadata=None):            
            # Store indexing results in the dbase
            for offset, matches in self.index.index_buffer(data):
                for id, length in matches:
                    try:
                        self.stats_count[id]+=1
                    except KeyError:
                        #Must be a new id for the dictionary
                        self.stats_count[id]=1

                    ## If the file is longer than a block, we create a new
                    ## block, and adjust the relative offset
                    if self.rel_offset+offset > BLOCKSIZE:
                        self.block_number+=1
                        self.rel_offset -= BLOCKSIZE
                        self.dbh.execute("insert into LogicalIndex set inode=%r,block_number=%r",(self.inode,self.block_number))
                        #block is the current block number we are looking at
                        self.block = self.dbh.autoincrement()

                    #Final result ie. absolute offset is (current block
                    #number * blocksize) + (offset from start of data
                    #chunk where we found the term + offset of the data
                    #block)
                    self.dbh.mass_insert( id=id,
                                          offset = (self.block<<BLOCKBITS)+offset+self.rel_offset,
                                          length = length)
                
            self.rel_offset += len(data)
                
        def finish(self):
            #Store the stats table with the hits for the search
            self.dbh.mass_insert_commit()
            pydbh = DB.DBO(None)
            for row in self.stats_count.iteritems():
                pydbh.execute("select word,class from dictionary where id=%s limit 1",row[0])
                class_hit=pydbh.fetch()
                try:
                    self.dbh.execute("insert into LogicalIndexStats set id=%r,word=%r,class=%r,hits=%r",(row[0],class_hit['word'],class_hit['class'],row[1]))
                except DB.DBError:
                    #Maybe we already ran a search so I should just update the stats
                     self.dbh.execute("update LogicalIndexStats set hits=hits+%r where id=%r",(row[1],row[0]))
 
## These reports allow the management of the Index Dictionary:
class BuildDictionary(Reports.report):
    """ Manipulate dictionary of search terms to index on """
    parameters = {}
    name="Build Dictionary"
    family="Keyword Indexing"
    description = "Builds a dictionary for indexing "

    def display(self,query,result):
        ## The dictionary is site wide and lives in the FlagDB
        dbh=self.DBO(None)

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
            result.text("Error: %s" % e,color='red')
            result.text("",color='black')
            
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

def resolve_offset(dbh, encoded_offset):
    """ Converts the encoded_offset to an offset within its Inode.

    As mentioned above the encoded offset includes a bit mask with block number. This makes the encoded offset unique within the entire image.
    """
    dbh.execute("select (block_number <<%s) + (%r & ((1<<%s)-1)) as `Offset` from LogicalIndex where ( %r >>%s = block ) limit 1",(BLOCKBITS,encoded_offset,BLOCKBITS,encoded_offset, BLOCKBITS))
    row=dbh.fetch()
    return row['Offset']

def resolve_inode(dbh, encoded_offset):
    """ Converts the encoded_offset to an Inode """
    dbh.execute("select inode from LogicalIndex where block=%r>>%s limit 1",(encoded_offset, BLOCKBITS))
    row=dbh.fetch()
    return row['inode']

class SearchIndex(Reports.report):
    """ Search for indexed keywords """
    description = "Search for words that were indexed during filesystem load. Words must be in dictionary to be indexed. "
    name = "Search Indexed Keywords"
    family = "Keyword Indexing"
    parameters={'keyword':'any',
                'range':'numeric','final':'any'}

    def form(self,query,result):
        try:
            query['keyword']=query['new_keyword']
            del query['new_keyword']
        except:
            pass

        try:
            query['range']
        except:
            query['range']=100

        def remove_word_cb(query,result,word):
            """ Removes word from the query string """
            result.decoration = 'naked'
            del query['new_keyword']
            keys = [ k for k in query.getarray('keyword') if k != word ]
            del query['keyword']
            for k in keys:
                query['keyword']=k

            result.heading("Removing word %s" % word)
            result.refresh(0,query,pane="parent")
        
        def add_word_cb(query,result):
            """ Call back to add a new word to the list of words to
            search for (shows stats from search)"""
            result.decoration = 'naked'
            result.heading("Add a word to search terms")
            q=query.clone()
            del q['callback_stored']
            q['__pane__']='parent'
            q['__target__']='new_keyword'
            try:
                result.table(
                    elements = [ StringType('Index Term','word', link=q),
                                 StringType('Dictionary Class','class'),
                                 IntegerType('Number of Hits', 'hits')],
                    table='LogicalIndexStats',
                    case=query['case'],
                    )
            except KeyError:
                pass
        try:
            result.case_selector()

            words = list(query.getarray('keyword'))
            del result.form_parms['keyword']

            group = result.__class__(result)
            
            ## Make sure that words are unique
            words.sort()
            old=None
            for keyword in words:
                if keyword!=old:
                    tmp = result.__class__(result)
                    tmp.text("%s\n" % keyword,color='red')
                    icon = result.__class__(result)
                    icon.popup(
                        Curry(remove_word_cb,word=keyword),
                        "Remove Word", tooltip="Remove word", icon="no.png"
                        )
                    old=keyword
                    result.hidden('keyword',keyword)
                    group.row(icon,tmp)

            tmp = result.__class__(result)
            tmp.popup(add_word_cb, "Add word", tooltip = "Add word",icon="red-plus.png")
            result.toolbar(cb=add_word_cb, text="Add word", tooltip = "Add word",icon="red-plus.png")
            result.row("Search for",group,tmp,valign="top")
            result.textfield("Within characters","range")
            result.checkbox("Tick this when ready","final",True)

        except KeyError:
            return

    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh2 = self.DBO(query['case'])

        keyword = query['keyword']
        try:
            dbh.execute("select * from LogicalIndexCache_reference")
            for row in dbh:
                dbh2.execute("drop table LogicalIndexCache_%s" % row['id'])

            dbh.execute("drop table LogicalIndexCache_reference")
        except DB.DBError:
            pass

    def progress(self,query,result):
        result.heading("Searching for '%s'" % ('\',\''.join(query.getarray('keyword'))))
        
    def analyse(self,query):
        dbh = DB.DBO(query['case'])
        dbh2= DB.DBO(query['case'])
        pyflag_dbh= DB.DBO(None)
        range=int(query['range'])/2
        old_temp_table = None
        offset_columns=[]
        word_ids = []

        ## Now we create a cache table for each set of word
        ## combinations. We need to find a unique identifier for this
        ## request to name the table with. For example if we ask for
        ## "foo" and "bar" within 100 bytes of each other we should
        ## cache one set of results, while if we ask for "foo" and
        ## "word" this is a very different set.
        canonicalised_query = FlagFramework.canonicalise(query)
 
        ## We store this canonical query - We could use the meta table
        ## for this, but the report does not get cached until the
        ## analyse method is finished, which does not allow us to
        ## create the other tables
        dbh.execute("""CREATE TABLE if not exists `LogicalIndexCache_reference` (
        `id` INT NOT NULL AUTO_INCREMENT ,
        `query` TEXT NOT NULL ,
        index (`id`)
        )""")
        
        ## First is it already here? - This should not happen, since
        ## we will never be run again with the same set of data, but
        ## better be safe:
        dbh.execute("select * from `LogicalIndexCache_reference` where query=%r limit 1",(canonicalised_query))
        row=dbh.fetch()

        ## The cache table already exists, we dont need to do anything.
        if row: return

        ## We start off by isolating offset ranges of interest
        for word in query.getarray('keyword'):
            temp_table = dbh.get_temp()
            pyflag_dbh.execute("select id from dictionary where word=%r limit 1",(word))
            row=pyflag_dbh.fetch()
            word_id = row['id']
            word_ids.append(word_id)

            if not old_temp_table:
                offset_columns.append("offset_%s" % word_id)
                try:
                    dbh.execute("create table %s select greatest(offset-%s , ((offset)>>20)<<20) as low,offset+%s as high, offset as offset_%s, length from LogicalIndexOffsets where id=%r",(temp_table,range,range,word_id,word_id))
                except DB.DBError,e:
                    raise Reports.ReportError("Unable to find a LogicalIndexOffsets table for current image. Did you run the LogicalIndex Scanner?.\n Error received was %s" % e)
                
            else:
                dbh.execute("create table %s select least(offset-%s,low) as low, greatest(offset+%s,high) as high, %s, offset as offset_%s from %s, LogicalIndexOffsets, length where id=%r and offset<high and offset>low",
                            (temp_table,range,range,
                             ','.join(offset_columns),word_id,
                             old_temp_table,
                             word_id))

            old_temp_table=temp_table

        ## Create a new cache table and populate it:
        dbh.insert("LogicalIndexCache_reference", query=canonicalised_query)
        cache_id = dbh.autoincrement()
        
        dbh.execute("create table LogicalIndexCache_%s select * from %s",(cache_id,temp_table))
        return
        
    def display(self,query,result):
        result.heading("Searching for '%s'" % ('\',\''.join(query.getarray('keyword')),))
        
        dbh = self.DBO(query['case'])
        fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])

        ## Find the cache table:
        canonicalised_query = FlagFramework.canonicalise(query)

        ## This should be here because we create it in the analyse
        ## method.
        dbh.execute("select * from `LogicalIndexCache_reference` where  query=%r limit 1",(canonicalised_query))
        row=dbh.fetch()
        cache_id=row['id']
        
        ## Find the offset columns:
        dbh.execute("desc LogicalIndexCache_%s" % cache_id)
        offset_columns =[ row['Field'] for row in dbh if row['Field'].startswith('offset_') ]

        ## Relate the offsets to actual words
        pydbh = DB.DBO(None)

        words = []
        for word in offset_columns:
            pydbh.execute("select word,id from dictionary where id=%r limit 1" % word[len("offset_"):])
            row=pydbh.fetch()
            words.append(row['word'])

        ## This stuff is done on the fly because it is time consuming
        ## - The disadvantage is that it cannot be searched on.
        def SampleData(string):
            row = string.split(',')
            inode = row[0]
            low=resolve_offset(dbh,row[1])
            high=resolve_offset(dbh,row[2])
            length= int(row[3])
            offsets = [ resolve_offset(dbh,a) for a in row[4:] ]
            sorted_offsets = [low] + offsets[:] + [high]
            sorted_offsets.sort()
#            offsets =[ int(a) for a in [low]+row[3:]+[high] ]
            fd = fsfd.open(inode=inode)
            fd.seek(low)
            try:
                data=fd.read(high-low)
            except IOError:
                data="Error reading %d bytes from file" % (high-low)

            out=result.__class__(result)
            word=''
            for i in range(1,len(sorted_offsets)):
                out.text(data[sorted_offsets[i-1]-low+length:sorted_offsets[i]-low],color='black',sanitise='full')
                try:
                    word = words[offsets.index(sorted_offsets[i])]
                except:
                    word = ''

                out.text(data[sorted_offsets[i]-low:sorted_offsets[i]-low+length],color='red',sanitise='full')
            
            return out

        tmp = ['(block_number <<%s) + (%s & ((1<<%s)-1))' % (BLOCKBITS,a,BLOCKBITS) for a in offset_columns ]

        def offset_link_cb(value):
            inode,offset,length,word = value.split(',',3)
            offset = int(offset)
            tmp = result.__class__(result)

            tmp.link( offset, target=query_type(case=query['case'],family="Disk Forensics", report='ViewFile',mode='HexDump',inode=inode,hexlimit=max(offset-int(query['range'])/2,0),highlight=offset, length=length) )
            return tmp
        
        result.table(
            ## FIXME - This needs to be redesigned!!! Should be a lot
            ## easier using the new column types.
            columns = ['inode',
                       ## Data for Offset cb: inode,offset in
                       ## inode,word highlighted. e.g:
                       ## D1285|P2097316:0,10,word
                       'concat(inode,",",(block_number <<%s) + (%s & ((1<<%s)-1)),",", `length`,",",%r)' % (BLOCKBITS,offset_columns[0],BLOCKBITS, words[0]),
                       ## Data for data cb: inode,low offset, high
                       ## offset, list of hit offsets. eg:
                       ## D1285|P2097316:0,69206016,69206076,69206026
                       'concat(%s)' % ',",",'.join(
                             ['inode','low','high', 'length']+ offset_columns
                             )
                       ],
            names=['Inode','Offset','Data'],
            table='LogicalIndexCache_%s, LogicalIndex ' % (cache_id,),
            
            ## Note this assumes that high-low < BLOCKSIZE
            where = " low>>%s = block " % BLOCKBITS,
            callbacks = { 'Data' : SampleData, 'Offset' : offset_link_cb },
            links = [ query_type(case=query['case'],family="Disk Forensics",report='ViewFile',__target__='inode') ],
            case=query['case'],
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

class LogicalIndexTests(unittest.TestCase):
    """ Logical Index Tests """

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

        self.assert_("Hello" in matching_words)

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

            
