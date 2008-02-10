""" This is an implementation of Magic file header detection.

The standard Magic scheme is not powerful enough to correctly identify
some file types accurately. We try to improve upon it here.
"""
import index
import pyflag.Registry as Registry

class Magic:
    """ This is the base class for all Magic handlers. """
    indexer = None
    index_map = {}
    rule_map = {}
    count = 0
    regex_rules = []
    literal_rules = []
    magic_handlers = []
    
    def prepare(self):
        """ This is called when we instantiate ourselves to scan all
        magic classes and prepare ourselves.
        """
        if not self.indexer:
            self.indexer = index.Index(all = 1)
            for cls in Registry.MAGIC_HANDLERS.classes:
                cls = cls()
                self.magic_handlers.append(cls)
                for rule in cls.regex_rules:
                    self.indexer.add_word(rule[0], Magic.count, index.WORD_EXTENDED)
                    self.index_map[Magic.count] = cls
                    self.rule_map[Magic.count] = rule
                    Magic.count += 1

                for rule in cls.literal_rules:
                    self.indexer.add_word(rule[0], Magic.count, index.WORD_ENGLISH)
                    self.index_map[Magic.count] = cls
                    self.rule_map[Magic.count] = rule
                    Magic.count += 1

    def get_type(self, data):
        max_score, scores = self.estimate_type(data)
        return max_score[1].type_str()

    def type_str(self):
        return self.type
            
    def estimate_type(self,data):
        """ Given the data we guess the best type determination. This
        should probably not be overridden by derived classes.
        """
        scores = {}
        max_score = [0, None]
        pending = set(self.rule_map.keys())
        
        ## Give all handlers a chance to rate the data
        for cls in self.magic_handlers:
            scores[cls] = cls.score(data)
            
            ## Maintain the higher score in the list:
            if scores[cls] > max_score[0]:
                max_score = [ scores[cls], cls]
                
        ## Index the data using the indexer:
        for offset, matches in self.indexer.index_buffer(data):
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
            if max_score[0] > 100:
                break

        ## Return the highest score:
        return max_score, scores
        
    def score(self, data):
        """ This is called on each class asking them to score the data """
        return 0

    def score_hit(self, data, match, pending):
        """ This is only called when an indexer hit is made """
        return 100
