# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Checked in  by $Author: scudette $
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Name:  $
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

""" IndexTools:

This module implements an indexing system to quickly search for keywords in images. There are 3 steps involved:
      1. Build a dictionary of keywords to search on.
      2. Create an index using this dictionary
      3. Index the image (an IOSource) a buffer at a time.
      4. Search the index for words and display the results in a table view.

This module provides reports for the entire process.
"""

description = "Index Tools"
order = 90

import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.IO as IO
import os

## The size of the buffer to index at a time
BLOCKSIZE=1024*1024

class BuildDictionary(Reports.report):
    """ Manipulate dictionary of search terms to index on """
    parameters = {}
    name="Build Dictionary"
    description = "Builds a dictionary for indexing "

    def form(self,query,result):
        pass

    def analyse(self,query):
        pass

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
                dbh.execute("insert into dictionary set word=%r,class=%r",(query['word'],query['class']))
                
            elif query['action']=='delete':
                dbh.execute("delete from dictionary where word=%r",query['word'])
                
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
        form.const_selector("Action:",'action',('delete','insert'),('Delete','Add'))
        form.textfield('Word:','word')        
        form.selector('Classification:','class','select class,class from dictionary group by class order by class',())
        form.textfield('(Or create a new class:)','class_override')
        form.end_table()
        form.end_form('Go')

        table=self.ui(result)
        try:
            table.table(
                columns=['word','class'],
                names=['Word','Class'],
                table='dictionary',
                case=None,
                )
            ## If the table is not there, we may be upgrading from an old version of flag, We just recreate it:
        except DB.DBError:
            dbh.execute("""CREATE TABLE `dictionary` (
            `word` VARCHAR( 50 ) NOT NULL ,
            `class` VARCHAR( 50 ) NOT NULL ,
            `encoding` SET( 'all', 'ascii', 'ucs16' ) DEFAULT 'all' NOT NULL ,
            PRIMARY KEY ( `word` )
            ) """)

            result.para("Just created a new empty dictionary")
            result.refresh(3,query)
            
        result.row(table,form,valign='top')

class IndexImage(Reports.report):
    """ Indexes an IO Source using the global dictionary """
    parameters={"iosource":"iosource"}
    name="Index Image"
    description = "Index image using global dictionary "
    order=50

    def progress(self,query,result):
        result.heading("Currently indexing '%s'" % query['iosource'])
        try:
            result.para("So far processed %u bytes" % self.progress_count)
        except AttributeError:
            pass

    def form(self,query,result):
        try:
            result.case_selector()
            result.ruler()
            result.meta_selector(message='Select IO Data Source', case=query['case'], property='iosource')
        except (KeyError,IOError):
            pass
        
    def analyse(self,query):
        dbh = self.DBO(query['case'])
        flag_dbh=self.DBO(None)

        iosource=IO.open(query['case'],query['iosource'])

        ## Create a filename for this IO Source
        filename=dbh.MakeSQLSafe("%s_%s" % (query['case'],query['iosource']))

        import index

        ## Create a new index by reading words off our dictionary
        idx=index.index("%s/%s.index" %(config.RESULTDIR,filename))
        flag_dbh.execute("select word,class,encoding from dictionary")
        for row in flag_dbh:
            idx.add(row['word'])

        ## Now run through the IOSource indexing it:
        count=0
        while 1:
            self.progress_count=count
            try:
                text=iosource.read(BLOCKSIZE)
                if len(text)==0: break
            except IOError:
                break
            
            idx.index_buffer(count,text)
            count+=len(text)
            print "Currently read %u" % count

        self.progress_count=0

    def display(self,query,result):
        result.heading("View Index on '%s'" % query['iosource'])
        result.para("Click on the word to view occurances of this word within file '%s'" % query['iosource'])
        
        newquery=query.clone()
        del newquery['report']
        newquery['report']='SearchIndex'
        formquery=newquery.clone()

        result.start_form(formquery)
        result.textfield("or, just type a word here to search on it","word");
        result.text("Note that the word must still be in the index in order to get any hits on it",color="red")
        result.text(finish=1)
        result.end_form(None)
        
        result.table(
            columns=['word','class'],
            names=['Word','Class'],
            links=[result.make_link(newquery,'word')],            
            table='dictionary',
            case=None,
            )

class SearchIndex(IndexImage):
    """ Search the index for a word """
    parameters={"iosource":"iosource","word":"alphanum"}
    name="Search Index"
    description = "Search the index for occurances of word"
    order=60

    def form(self,query,result):
        try:
            result.case_selector()
            result.ruler()
            result.meta_selector(message='Select IO Data Source', case=query['case'], property='iosource')
            result.ruler()
            result.textfield("Type word to search for: ",'word')
        except (KeyError,IOError):
            pass

    def analyse(self,query):
        ## Todo: there is no way to know if the word is in the index currently.

        ## Check if the index was already created
        newquery=query.clone()
        del newquery['report']
        newquery['report']='IndexImage'
        self.check_prereq(newquery)

    def display(self,query,result):
        dbh = self.DBO(query['case'])
        result.heading("Searching for %r in file %r" %(query['word'],query['iosource']))

        ## open the io source, and the index:
        io=IO.open(query['case'],query['iosource'])
        filename=dbh.MakeSQLSafe("%s_%s" % (query['case'],query['iosource']))
        import index
        
        idx=index.Load("%s/%s.index" %(config.RESULTDIR,filename))

        def list_matches(query):
            ## Number of chars to display prior to the word and after the word
            prior=10
            after=90
            
            row_number=0
            try:
                current_number=int(query['limit'])
            except (KeyError,ValueError):
                current_number=0
            
            output=self.ui()
            output.start_table()
            for offset in idx.search(query['word']):
                word=query['word']
                if row_number > current_number:
                    ## Get some text around the word:
                    io.seek(offset-prior)
                    data=io.read(prior+after)
                    
                    right=self.ui()
                    right.text(data[:prior],sanitise='full',font='typewriter')
                    right.text(data[prior:prior+len(word)],color='red',sanitise='full',font='typewriter')
                    right.text(data[prior+len(word):],color='black',sanitise='full',font='typewriter')
                    left=self.ui()
                    left.link(offset,case=query['case'],iosource=query['iosource'],family="UnstructuredDisk",report="BrowseDiskSector",limit=offset-prior)
                    
                    output.row(left,right)

                if row_number > current_number+config.PAGESIZE:
                    ## We had to terminate the listing early, so we add a navbar arrow
                    result.next=current_number+config.PAGESIZE
                    break

                row_number+=1
                
            output.end_table()

            ## Do the navigation bar now
            result.previous=current_number-config.PAGESIZE
            if result.previous<=0:
                result.previous=None

            result.pageno=int(current_number/config.PAGESIZE)
            return output

        result.notebook(
            names=['List Matches'],
            callbacks=[list_matches],
            descriptions=['List many matches per page']
            )
