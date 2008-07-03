#!/usr/bin/env python
""" This is an implementation of Magic file header detection.

The standard Magic scheme is not powerful enough to correctly identify
some file types accurately. We try to improve upon it here.

This is a score based system - each magic handler gets the opportunity
to score the data. This represents our confidence in the
identification. If a score is bigger or equal to 100% it wins
automatically. Otherwise the highest score wins.

The usual tests include a set of regexs to be run over the file
header, but other tests are also possible.
"""
import index
import pyflag.Registry as Registry
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
import pyflag.pyflaglog as pyflaglog

class MagicResolver:
    """ This is a highlander class to manage access to all the resolvers """
    indexer = None
    index_map = {}
    rule_map = {}
    count = 0
    magic_handlers = []

    def __init__(self):
        """ We keep a record of all magic handlers and instantiate them all.
        """
        if not MagicResolver.indexer:
            MagicResolver.indexer = index.Index()
            for cls in Registry.MAGIC_HANDLERS.classes:
                cls = cls()
                MagicResolver.magic_handlers.append(cls)
                for rule in cls.regex_rules:
                    MagicResolver.indexer.add_word(rule[0], MagicResolver.count, index.WORD_EXTENDED)
                    MagicResolver.index_map[MagicResolver.count] = cls
                    MagicResolver.rule_map[MagicResolver.count] = rule
                    MagicResolver.count += 1

                for rule in cls.literal_rules:
                    MagicResolver.indexer.add_word(rule[0], MagicResolver.count, index.WORD_ENGLISH)
                    MagicResolver.index_map[MagicResolver.count] = cls
                    MagicResolver.rule_map[MagicResolver.count] = rule
                    MagicResolver.count += 1

            pyflaglog.log(pyflaglog.DEBUG,"Loaded %s signatures into Magic engine" % MagicResolver.count)
            
    def get_type(self, data, case=None, inode_id=None):
        max_score, scores = self.estimate_type(data, case, inode_id)
        return max_score[1].type_str(), max_score[1].mime_str()

    def estimate_type(self,data, case, inode_id):
        """ Given the data we guess the best type determination. 
        """
        scores = {}
        max_score = [0, None]
        pending = set(self.rule_map.keys())
        
        ## Give all handlers a chance to rate the data
        for cls in self.magic_handlers:
            scores[cls] = cls.score(data, case, inode_id)
        
            ## Maintain the higher score in the list:
            if scores[cls] > max_score[0]:
                max_score = [ scores[cls], cls]
                
        ## Index the data using the indexer:
        for offset, matches in self.indexer.index_buffer(data, unique=0):
            for match in matches:
                ## match is (rule_id, offset, length)
                ## Thats the rule that matched:
                if match[0] not in pending:
                    continue

                rule = self.rule_map[match[0]]
                cls = self.index_map[match[0]]
            
                ## Is there a range or a specific offset?
                try:
                    rng = rule[1]
                    if offset >= rng[0] and offset <= rng[1]:
                        scores[cls] += cls.score_hit(data, match, pending)
                except IndexError:
                    if offset == rule[1]:
                        scores[cls] += cls.score_hit(data, match, pending)
            
            ## Maintain the higher score in the list:
            if scores[cls] > max_score[0]:
                max_score = [ scores[cls], cls]

            ## When one of the scores is big enough we quit:
            if max_score[0] >= 100:
                break
            
        ## Return the highest score:
        return max_score, scores

    def find_inode_magic(self, case, inode_id=None, inode=None, data=None):
        """ A convenience function to resolve an inode's magic.

        We check the db cache first.
        """
        dbh = DB.DBO(case)

        if inode:
            dbh.execute("select inode_id from inode where inode = %r", inode)
            row = dbh.fetch()
            inode_id = row['inode_id']

        ## Is it already in the type table?
        try:
            dbh.execute("select mime,type from type where inode_id=%r limit 1",inode_id)
            row = dbh.fetch()
            content_type = row['mime']
            type = row['type']
        except (DB.DBError,TypeError):
            if not data:
                fsfd = FileSystem.DBFS(case)
                fd = fsfd.open(inode_id = inode_id)
                ## We could not find it in the mime table - lets do magic
                ## ourselves:
                data = fd.read(1024)
                
            type, content_type = self.cache_type(case, inode_id, data)

        return type, content_type

    def cache_type(self, case, inode_id, data):
        """ Performs a type lookup of data and caches it in the inode_id """
        dbh = DB.DBO(case)
        type, content_type = self.get_type(data, case, inode_id)

        ## Store it in the db for next time:
        try:
            dbh.insert("type",
                       inode_id = inode_id,
                       mime = content_type,
                       type = type)
        except: pass

        return type, content_type
    
class Magic:
    """ This is the base class for all Magic handlers. """
    ## The default type and mime strings
    type = None
    mime = 'application/octet-stream'
    default_score = 100
    
    regex_rules = []
    literal_rules = []

    ## These are unit tests for verification
    samples = []
    
    def type_str(self):
        return self.type

    def mime_str(self):
        return self.mime
    
    def score(self, data, case, inode_id):
        """ This is called on each class asking them to score the data """
        return 0

    def score_hit(self, data, match, pending):
        """ This is only called when an indexer hit is made """
        return self.default_score
    
