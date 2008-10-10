import pyflag.pyflagsh as pyflagsh
import pyflag.DB as DB

class http_parameters(pyflagsh.command):
    """ Display all the http parameters associated with the inode id provided """
    def execute(self):
        args = self.args
        dbh = DB.DBO(self.environment._CASE)
        dbh.execute("select `key`,value from http_parameters where inode_id=%r", args[0])
        yield "Key,Value"
        yield "---------"
        for row in dbh:
            yield "%s: %s" % (row['key'], row['value'][:100])
