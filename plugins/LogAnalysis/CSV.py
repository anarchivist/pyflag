""" This module implements a Comma Seperated Log driver for PyFlag """
import csv
import Simple

class CSVLog(Simple.SimpleLog):
    """ Log parser designed to handle comma seperated files """
    name = "CSV"
    
    def get_fields(self):
        return csv.reader(self.read_record())
        
    def form(self,query,result):
        result.end_table()
        result.row("Unprocessed text from file",colspan=5)
        sample = []
        count =0
        for line in self.read_record():
            sample.append(line)
            count +=1
            if count>3:
                break
            
        result.row('\n'.join(sample),bgcolor='lightgray')
        result.end_table()

        self.draw_type_selector(result)
