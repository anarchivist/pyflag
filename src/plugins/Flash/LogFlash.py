import pyflag.pyflagsh as pyflagsh
import pyflag.LogFile as LogFile
import pyflag.DB as DB

class drop_log_preset(pyflagsh.command):
    """ Delete a log preset """
    def help(self):
        return "Delete the given log preset and all the tables which use it (DANGEROUS)"

    def execute(self):
        for preset in self.args:
            yield "Deleting preset %s" % preset
            LogFile.drop_preset(preset)

    def complete(self, text, state):
        dbh = DB.DBO()
        dbh.execute("select name from log_presets")
        presets = [ row['name'] for row in dbh ]
        return self.complete_from_list(text, state, presets)

class delete_log_table(pyflagsh.command):
    """ Delete the given log tables in the current case (DANGEROUS) """
    def execute(self):
        for table in self.args:
            yield "Deleting table %s" % table

            LogFile.drop_table(self.environment._CASE, table)

    def complete(self, text, state):
        dbh = DB.DBO(self.environment._CASE)
        dbh.execute("select table_name from log_tables")
        tables = [ row['table_name'] for row in dbh ]
        return self.complete_from_list(text, state, tables)
