""" This is a collection of very useful column types. """
from pyflag.ColumnTypes import TimestampType

class Date(TimestampType):
    """ A Column storing a date """
    def create(self):
        return "`%s` DATE" % self.column
    
class Time(TimestampType):
    """ A Column storing a time """
    def create(self):
        return "`%s` TIME " % self.column

class EpochTimestamp(TimestampType):
    """ A Column storing a timestamp as an integer from the epoch time """
    def insert(self, value):
        return "_"+self.column, "from_unixtime(%r)" % value

## Import the unit tests so they are picked up by the registry:
from pyflag.ColumnTypes import ColumnTypeTests
