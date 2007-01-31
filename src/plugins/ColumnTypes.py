""" This is a collection of very useful column types. """
from pyflag.TableObj import TimestampType

class Date(TimestampType):
    def create(self):
        return "`%s` DATE" % self.column
    
class Time(TimestampType):
    def create(self):
        return "`%s` TIME " % self.column

