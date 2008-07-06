# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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
import pyflag.Indexing as Indexing

config.add_option("INDEX_ENCODINGS", default="['UTF-8','UTF-16LE']",
                  help="A list of unicode encodings to mutate the "
                  "dictionary through for indexing")

class IndexStatsTables(FlagFramework.EventHandler):
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
    version = 0

    group = "GeneralForensics"
    
    ##contains = ['RegExpScan','IndexScan','MD5Scan','VirScan','CarveScan']

    class Drawer(Scanner.Drawer):
        description = "General Forensics"
        group = "GeneralForensics"
        default = True
        
    def prepare(self):
        if not INDEX: reindex()

    class Scan(MemoryScan):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            MemoryScan.__init__(self, inode,ddfs,outer,factories,fd=fd)

            ## Make sure the index is fresh:
            INDEX.clear_set()
            
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
            for offset, matches in INDEX.index_buffer(buff, unique=1):
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
                        length = length
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
        `type` set ( 'word','literal','regex' ) DEFAULT 'literal' NOT NULL,
        PRIMARY KEY  (`id`))""")

## These check that the schema is up to date
DB.convert_to_unicode(None, 'dictionary')

## These reports allow the management of the Index Dictionary:
class BuildDictionary(Reports.report):
    """ Manipulate dictionary of search terms to index on """
    parameters = {}
    name="Build Indexing Dictionary"
    family="Disk Forensics"
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

        status = ''
        ## Do we need to add a new entry:
        try:
            if len(query['word'])<3:
                raise DB.DBError("Word is too short to index, minimum of 3 letter words")
            
            if query['action']=='insert':
                try:
                    if len(query['class'])<3:
                        raise DB.DBError("Class name is too short, minimum of 3 letter words are used as class names")
                except KeyError:
                    status = "Classification missing or too short"
                    raise
                
                Indexing.insert_dictionary_word(query['word'], query['type'],
                                                query['class'])
                status = "Added word %s to dictionary" % query['word']
                   
            elif query['action']=='delete':
                dbh.delete("dictionary", 
                           where=DB.expand("word=%b and type=%r",
                                           (query['word'],query['type'])))
                status = "Deleted word %s from dictionary" % query['word']
                
        except KeyError,e:
            pass
        
        except DB.DBError,e:
            result.text("Error: %s" % e,style='red')
            result.text("",style='black')

        if status:
            result.text(status, style='red')
            result.text("", style='black')
            
        result.heading("Building Dictionary")

        ## Draw a form allowing users to add or delete words from the dictionary
        form=result.__class__(result)
        form.start_form(query)
        form.start_table()
        form.const_selector("Action:",'action',('insert','delete'),('Add','Delete'))
        form.textfield('Word:','word')        
        form.selector('Classification:','class','select class as `key`,class as `value` from dictionary where left(class,1) != \'_\' group by class order by class',())
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
            ## Class names starting with _ are private and should not
            ## be user selectable:
            where="left(class,1) != '_' ",
            case=None,
            )
        result.row(table,form,valign='top')

class OffsetType(IntegerType):
    hidden = True
    LogCompatible = False
    
    def __init__(self, case, table='LogicalIndexOffsets'):
        self.case = case
        IntegerType.__init__(self, name='Offset',
                             column='offset',
                             table=table)

    def select(self):
        return "concat(%s, ',', %s)" % (self.escape_column_name('offset'),
                                        self.escape_column_name('length'))

        
    def display(self, value, row, result):
        offset, length = value.split(",")
        inode = row['Inode']
        query = query_type(case=self.case,
                           family="Disk Forensics",
                           report='ViewFile',
                           mode='HexDump',
                           inode_id=inode,
                           offset = offset,
                           hexlimit=max(int(offset)-50,0),
                           highlight=offset,
                           highlight_length=length)
        
        result.link(offset, query, pane='new')
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
        return DB.expand("concat(%s,',', %s,',', %s)",
                         (self.escape_column_name("offset"),
                          self.escape_column_name("inode_id"),
                          self.escape_column_name("length")))
                         
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
    
    def __init__(self, name = 'Word', case=None, filter='', where = '1'):
        self.case = case
        self.filter = filter
        self.table_where_clause = where
        ColumnType.__init__(self, column = 'word_id', name = name,
                            table='LogicalIndexOffsets', case=case)

    def select(self):
        return "concat(%s,',',inode.inode_id)" % (self.escape_column_name(self.column))

    def plain_display_hook(self, value, row, result):
        word_id, inode_id = value.split(',')
        dbh = DB.DBO()
        dbh.execute("select word, type from dictionary where id=%r limit 1", word_id)
        row = dbh.fetch()
        if not row: return "?"
        
        if row['type'] in ['literal','regex']:
            word = row['word'].decode("ascii", "ignore")
        else:
            ## Force it to ascii for display
            word = row['word'].decode("utf8")

        result.link(word,
                    target = query_type(report="ViewInodeHits",
                                        family="Keyword Indexing",
                                        inode_id=inode_id,
                                        word_id=word_id,
                                        case = self.case),
                    tooltip="View All Hits in Inode")

    display_hooks = [ plain_display_hook, ColumnType.link_display_hook ]

    def outstanding_inodes(self, word_id=None):
        ## Remove any references to the LogicalIndexOffsets table
        ## - this will allow us to count how many inodes are
        ## involved in the re-indexing without making references
        ## to this column type.
        elements = [ e for e in self.elements if e.table != "LogicalIndexOffsets" ]

        ## Calculate the new filter string
        try:
            new_filter_string = self.ui.defaults[self.filter]
            sql = parser.parse_to_sql(new_filter_string,
                                      elements, None)
        except KeyError:
            sql = '1'

        tables = UI._make_join_clause(elements)
        final_sql = DB.expand("%s where (%s) and (%s)",
                              (tables, sql,
                               self.table_where_clause))
        count, total = Indexing.count_outdated_inodes(self.case, final_sql, word_id=word_id)

        return count, total, tables, sql
            
    def operator_hit(self, column, operator, arg):
        """ Search for a hit in the dictionary """
        ## Try to work out if we need to reindex:
        reindex = False
        dbh = DB.DBO()
        dbh.execute("select id from dictionary where word = %r limit 1", arg)
        row = dbh.fetch()

        if self.ui:
            ## If the word is not in the dictionary, we definitely want to reindex
            if not row:
                count, total, tables, sql = self.outstanding_inodes()
                message = "Word %s is not in the dictionary" % arg
                
            ## If the word is in the dictionary we want to know how may
            ## inodes are outdated
            else:
                count, total, tables, sql = self.outstanding_inodes(word_id = row['id'])
                message = "There are some inodes which are not up to date"

            ## Any inodes to process?
            if count > 0:
                reindex = True

        ## We do not need to reindex - just do it
        if not reindex:
            return DB.expand("(%s = %s)",
                             (self.escape_column_name(self.column),
                              row.get('id',0)))
            
        ## Allow the user to reindex the currently selected set of
        ## inodes with a new dictionary based on the new word
        self.ui.heading(message)
        self.ui.para("This will affect %s inodes and require rescanning %s bytes" % (count,total))

        ## Make up the link for the use:
        context = FlagFramework.STORE.put(dict(tables = tables,
                                               inode_sql = sql,
                                               previous_query = self.ui.defaults,
                                               target = 'parent_pane',
                                               where = self.table_where_clause
                                               ))

        link = query_type(report = "Add Word", family = "Keyword Indexing",
                          case = self.case,
                          context = context,
                          word = arg)
        
        self.ui.link("Click here to scan these inodes", link,
                     pane = 'self')

        ## Ok - Show the error to the user:
        raise self.ui
        
class ClassColumn(WordColumn):
    """ This shows the class of the dictionary word """
    def __init__(self, **kwargs):
        kwargs['name'] = "Class"
        WordColumn.__init__(self, **kwargs)
        self.dict_column = 'class'

    def where(self):
        return DB.expand("(substring((select class from `%s`.dictionary "
                         "where id=`%s`),1,1)!='_')",(config.FLAGDB, self.column))

class ViewInodeHits(Reports.report):
    """ View all hits within a specified inode """
    name = "View Inode Hits"
    family = "Keyword Indexing"
    parameters = {'case': 'any',
                  'inode_id': 'numeric',
                  'word_id': 'numeric'}
    hidden = True

    def form(self, query, result):
        result.textfield('Inode ID', 'inode_id')
        result.textfield('Word ID', 'word_id')

    def analyse(self, query):
        ## Check to see if the inode is up to date
        #count, size = Indexing.count_outdated_inodes(
        #    query['case'],
        #    "from inode where inode_id=%s" % query['inode_id'],
        #    unique = False)

        ## This indexing will be done in process (i.e. not
        ## distributable) because its exactly one job:
        task = Index()
        task.run(query['case'], query['inode_id'], 2**30 + int(query['word_id']))

    def display(self,query,result):
        case = query['case']
        result.table(
            elements = [ InodeIDType(case=case),
                         OffsetType(case=case),
                         DataPreview(name='Preview', case=case),
                         ],
            table = 'LogicalIndexOffsets',
            where = DB.expand('inode.inode_id = %r and LogicalIndexOffsets.word_id= %r',
                              (query['inode_id'],query['word_id'])),
            case =case,
            )
        
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

    def set_filter(self, query,result):        
        ## If we get here - the word is ok
        filter_expression = DB.expand("Word = '%s'", (query['indexing_word']))
        try:
            query.set(self.filter, "%s and %s" % (query[self.filter],
                                                  filter_expression))
        except KeyError:
            query.set(self.filter, filter_expression)

        ## Check that we can filter on the word as all:
        element = WordColumn(case = query['case'], filter=self.filter,
                             where = self.where)

        element.ui = result
        element.elements = self.elements
        element.operator_hit("Word", "=", query['indexing_word'])

    ## Install our toolbar button in the main Table renderer:
    def indexing_button(self, query, result):
        """ This adds a new column for the keyword hits """
        ## This only makes sense when one of the columns is an inodeID table:
        found = False
        for e in self.elements:
            if isinstance(e, InodeIDType):
                found = True
                break

        if not found: return
        
        new_query = query.clone()
        if query.has_key("indexing_word"):
            new_query.clear("indexing_word")
            new_query.clear(self.filter)
            
            result.toolbar(link = new_query, icon="nosearch.png",
                           tooltip = "Hide Index hits", pane = 'pane')

        else:
            def index_word(query, result):
                if query.has_key("indexing_word"):
                    self.set_filter(query, result)
                    result.refresh(0, query, 'parent_pane')
                    return
                
                new_query = query.clone()
                new_query.set('__target__','indexing_word')
                
                result.start_form(query, pane='self')
                result.textfield("Keyword","indexing_word")
                result.table(
                    case = None,
                    table = 'dictionary',
                    elements = [ StringType('Word','word', link=new_query),
                                 StringType('Class','class'),
                                 StringType('Type','type') ],
                    ## Class names starting with _ are private and should not
                    ## be user selectable:
                    where="left(class,1) != '_' ",
                    )
                result.end_table()
                result.end_form()

            result.toolbar(cb=index_word, icon="search.png",
                           tooltip = "Show Index hits", pane = 'popup')

    def render(self, query,result):
        ## This essentially forces us to filter on word. Otherwise we
        ## can not display the Preview (The query is likely to be
        ## huge). FIXME: This is not a very good test (wont work if
        ## Word is somewhere else in the filter string).
        if query.has_key("indexing_word") and \
               'Word' in query.get(self.filter,''):
            ## This forces us to group by the inode_id when looking at
            ## keyword hits - so we only show a single hit per inode.
            self.groupby = 'inode.inode_id'
            self.elements.append(WordColumn(name='Word', filter=self.filter,
                                            case = query['case'],))
            
            self.elements.append(DataPreview(name='Preview',
                                             case = query['case']))
            
        original_render(self, query, result)
        
## Install the new updated table renderer:
UI.TableRenderer = TableRenderer

## This is a global index we use for workers
INDEX = None
INDEX_VERSION = 0

def reindex():
    global INDEX, INDEX_VERSION
    pyflaglog.log(pyflaglog.DEBUG,"Index manager: Building index trie")
    start_time = time.time()
    
    dbh = DB.DBO()
    INDEX_VERSION = Indexing.get_dict_version()
    dbh.execute("select word,id,type,class from dictionary")
    INDEX = index.Index()
    for row in dbh:
        ## Classes starting with _ are private classes and want to
        ## return all hits.
        if row['class'].startswith("_"):
            id = row['id'] + 2**30
        else:
            id = row['id']

        t = row['type']
        ## Literal and extended are encoded using latin
        if t == 'literal':
            INDEX.add_word(row['word'].encode("latin"),id, index.WORD_LITERAL)
        elif t == 'regex':
            INDEX.add_word(row['word'].encode("latin"),id, index.WORD_EXTENDED)
        elif t=='word':
            try:
                word = row['word'].decode("UTF-8").lower()
                for e in config.INDEX_ENCODINGS:
                    w = word.encode(e)
                    if len(w)>3:
                        INDEX.add_word(w,id, index.WORD_ENGLISH)
            except UnicodeDecodeError:
                pass

    pyflaglog.log(pyflaglog.DEBUG,"Index Scanner: Done in %s seconds..." % (time.time()-start_time))



## This is how we can add new words to the dictionary and facilitate scanning:
class AddWords(Reports.report):
    """ Add a new word to the indexing dictionary """
    family = 'Keyword Indexing'
    name = "Add Word"
    description = "Add a new word to the dictionary and scan selected inodes "
    hidden = True
    
    parameters = { "word": "any", "case":"any",
                   "class": "any",
                   "type": "any",
                   'cookie': 'any'}

    def form(self, query,result):
        ## If the new word is already in the dictionary just analyse
        ## it
        try:
            if Indexing.is_word_in_dict(query['word']):
                query['cookie'] = time.time()
                query.default('class', "English")
                query.default('type', "word")
                result.refresh(0, query)
        except KeyError: pass
        
        result.textfield("Word to add", "word")
        result.selector('Classification:','class','select class as `key`,class as `value` from dictionary where left(class,1) != \'_\' group by class order by class',())
        result.textfield('(Or create a new class:)','class_override')
        result.const_selector('Type:','type',('word','literal','regex'),('Word','Literal','RegEx'))

        result.hidden("cookie", time.time(), exclusive=True)
        if query.has_key("class_override"):
            query['class'] = query['class_override']
            ## Refresh ourselves to update to the new class name
            result.refresh(0, query)

    def get_context(self,query):
        try:
            context_key = query['context']
            try:
                context = FlagFramework.STORE.get(query['context'])
            except KeyError:
                # context was provided but is not in store
                raise Reports.ReportError("Context not valid - Is the session expired")

        except KeyError:
            ## Context was not provided
            context = {}

        return context

    def analyse(self, query):
        context = self.get_context(query)
        
        word_id = Indexing.insert_dictionary_word(query['word'], query['type'])
        pdbh = DB.DBO()
        sql = DB.expand("select inode.inode_id as `inode_id` "\
                        "%s where (%s) and (%s)", (context.get('tables',''),
                                                   context.get('inode_sql','1'),
                                                   context.get('where','1')))

        Indexing.schedule_inode_index_sql(query['case'],
                                          sql, word_id, query['cookie'], unique=True)
        
        ## Now wait here until everyone is finished:
        while 1:
            pdbh.execute("select count(*) as c from jobs where cookie=%r",
                         query['cookie'])
            row = pdbh.fetch()
            self.rows_left = row['c']
            if row['c']==0: break

            time.sleep(1)
            
        return 1

    def progress(self, query, result):
        result.heading("Indexing Keywords")
        pdbh = DB.DBO()
        pdbh.execute("select count(*) as c from jobs where cookie=%r",
                     query['cookie'])
        row = pdbh.fetch()

        result.para("There are %s inodes left" % row['c'])

    def display(self, query, result):
        self.rows_left = 0
        
        ## Make sure this report is not cached now so we can reissue
        ## the same query again:
        self.clear_cache(query)

        context = self.get_context(query)
        if context.has_key("previous_query"):
            result.refresh(0, context['previous_query'], context['target'])
            
import pyflag.Farm as Farm

class ReIndex(Farm.Task):
    """ A task to reindex the dictionary (used after a dictionary update)"""
    def run(self, *args):
        reindex()

class Index(Farm.Task):
    """ A task to index an inode with the dictionary """
    def run(self, case, inode_id, *args):
        global INDEX
        if not INDEX: reindex()

        try:
            desired_version = int(args[0])
        except:
            desired_version = INDEX_VERSION

        ## Did they want a detailed index or a unique index?
        unique = desired_version < 2**30
        
        ## In unique mode we want to generate one hit per scan job per
        ## word
        if unique:
            INDEX.clear_set()

        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Indexing inode_id %s (version %s)" % (inode_id, desired_version))
        fsfd = FileSystem.DBFS(case)
        fd = fsfd.open(inode_id=inode_id)
        buff_offset = 0
        dbh = DB.DBO(case)

        ## Clear old hits:
        dbh.check_index("LogicalIndexOffsets", "inode_id")
        dbh.delete("LogicalIndexOffsets", where=DB.expand("inode_id = %r",
                                                          inode_id))

        ## Get ready for scan
        dbh.mass_insert_start("LogicalIndexOffsets")

        while 1:
            data = fd.read(1024*1024)
            if len(data)==0: break

            for offset, matches in INDEX.index_buffer(data, unique = unique):
                for id, length in matches:
                    dbh.mass_insert(
                        inode_id = inode_id,
                        word_id = id,
                        offset = offset + buff_offset,
                        length = length)

            buff_offset += len(data)

        dbh.mass_insert_commit()
        
        ## Update the version
        dbh.update("inode",
                   where = DB.expand('inode_id = %r', inode_id),
                   version = desired_version)
        
    
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
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, DB.expand("word: %r matched %r",
                                                                 (word,matched)))
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

