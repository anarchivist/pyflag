""" This plugin provides reports for viewing of files in special
ways. For example we are able to display properly sanitised html with
matched images etc.
"""
# Michael Cohen <scudette@users.sourceforge.net>
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

import pyflag.Reports as Reports
import pyflag.Registry as Registry
import pyflag.DB as DB
import sys,re,string

class ViewFile(Reports.report):
    """
    View HTML
    ---------

    This report allows users to view a sanitised version of the inode.

    We filter the inode from potentially malicious javascript and only
    allow certain html tags. This ensures that the investigators
    browser does not connect back to the malicious site or run
    potentially malicious code.

    We try to fill in images from our local cache. This is an
    approximation only and we guess the right image based on the
    filename.
    """
    
    name = "View File"
    family = "Network Forensics"
    parameters = {'inode':'any'}

    def form(self,query,result):
        result.case_selector()
        result.textfield("Inode to view",'inode')

    def display(self,query,result):
        dbh = DB.DBO(query['case'])
        dbh.execute("select mime from type where inode=%r",query['inode'])
        row = dbh.fetch()
        content_type = row['mime']

        fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])
        
        fd = fsfd.open(inode=query['inode'])
        result.generator.content_type = content_type

        ## Now establish the content type
        
        result.generator.generator=self.default_handler(fd)

    def default_handler(self, fd):
        while 1:
            data = fd.read(1000000)
            yield data
            
            if not data: break
            

Allowable_tags = {	 'b' : 1,
                         'i' : 1,
                         'a' : 2,
                         'img' : 2,
                         'em' : 1,
                         'br' : 1,
                         'strong' : 1,
                         'blockquote' : 1,
                         'tt' : 1,
                         'li' : 1,
                         'ol' : 1,
                         'ul' : 1,
                         'p' : 1,
                         'table' : 2,
                         'td' : 2,
                         'tr' : 2,
                         '!--pagebreak--' : 1,
                         'h1' : 1,
                         'h2' : 1,
                         'h3' : 1,
                         'pre' : 1,
                         'html' : 1,
                         'font' : 2,
                         'body' : 1,
                         'code' : 1,
		}

Allowable_attribs = ['COLOR', 	'BGOLOR', 'WIDTH', 'BORDER',
			'RULES', 'CELLSPACING', 
			'CELLPADDING', 'HEIGHT',
			'ALIGN', 'BGCOLOR', 'ROWSPAN', 
			'COLSPAN', 'VALIGN', 
			'COMPACT', 'HREF', 
			'TYPE', 'START', 'SRC']


class tag_counter:
	"Counter for tags"
	def __init__(self):
		self.tag_hash ={}
	
	def add_tag(self,in_tag):
		tag_exists=False
		for tag in self.tag_hash.keys():
			if in_tag==tag:
				tag_exists=True
		if tag_exists:
			self.tag_hash[in_tag]+=1
		else:
			self.tag_hash[in_tag]=1
			
	
	def remove_tag(self,in_tag):
		tag_exists=False
		for tag in self.tag_hash.keys():
			if in_tag==tag:
				tag_exists=True
		if tag_exists:
			if self.tag_hash[in_tag]>=1:
				self.tag_hash[in_tag]-=1

			else:
				#print "close tag before open"+in_tag
				pass
		else:
			#print "this tag wasn't opened"
			pass

	def print_hash(self):
		print self.tag_hash
	
	def get_closure(self):
		close_string=''
		tags_not_closed=('img','p','br','li','!--pagebreak--')
		for tag in self.tag_hash.keys():
			if self.tag_hash[tag]!=0 and \
			   not tag in tags_not_closed:
			   	close_string += '</' + tag + '>'
		return close_string
				

# Routine to sanitize the html within a file
def html_san(input):  
	output=''
	# initiate a new tag_counter
	global tag_count
	tag_count = tag_counter()
	# Read the file into a variable	

	# pick out all of the tags, and attributes from the file
	exp1 = re.compile(r'(?sm)(.*?)([<].*?[>])(.*?)')
	# go through each tab and decide how 
	# to put the file back together
	values_list =[]
	for val in exp1.finditer(input):
		values_list.append(val.group(1))
		values_list.append(val.group(2))
		values_list.append(val.group(3))

	for val in values_list:
		val_new = tag_san(val)
		output+= val_new
	#check if we need to close any tags
	output+=tag_count.get_closure()
	output+='\n'
	return output
	
# Routine to sanitize tags
def tag_san(val_in):
	# is this a tag and is it allowed?
	return_val = ''
	exp2 = re.compile(r'(?sm)^\s*<\s*(\/)?(\S+)\s*(.*)>$')
	results = exp2.match(val_in)
	if results:
		#this is a tag		
		#is it a tag we allow?
		allowed=False	#flag for allowed
		attribs=1	#flag for attribs
		for tag in html_allowed.Allowable_tags.keys():
			if results.group(2).lower()==tag:
				allowed=True
				attribs=html_allowed.Allowable_tags[tag]
		if allowed:
		
			#this tag is allowed
			#set up the start of the tag
			return_val='<'

			if results.group(1):
				# is this a closing tag?
				return_val+='/'
				tag_count.remove_tag(results.group(2).lower())
				
			else:
				tag_count.add_tag(results.group(2).lower())
			
			
			if attribs==1:
				#no attribs are allowed
				return_val+=results.group(2).strip()  + '>'
			else:
				#first add the tag
				return_val+= results.group(2).strip()
				#we must check the attribs
				#are there any attribs?
				
				if len(results.group(3))>0:
					#we have some attribs to check
					attribs_in = results.group(3)
					attribs_out = attrib_san(attribs_in)
					return_val+= attribs_out + '>'
				else:
					return_val+='>'
				
		else:
			#this tag is not allowed
			return_val='<REMOVED '+results.group(2)+' REMOVED>'
	else:
		#this is not a tag, do nothing
		return_val=val_in
	
	return return_val
	
	
# Routing to Sanitize attributes	
def attrib_san(attribs_in):
	# pick out all the attributes
	exp3=re.compile(r'(?sm)(.*?)=([\'\"].*?[\'\"])*')
	results=exp3.findall(attribs_in)
	attribs_out =''
	for attrib in results:
		#first fix the formatting
		this_attrib = attrib[0].upper().strip()
		this_attrib = re.split(r'(\S+)',this_attrib)[1]
		#is this an allowed attribute
		for allowed_attrib in html_allowed.Allowable_attribs:
			if this_attrib==allowed_attrib and check_href(attrib):
				attribs_out+= ' '+ attrib[0]+'='+attrib[1] 	
			else:
				#not allowable, do nothing
				pass
	return attribs_out
	
	
# Routine to check the format for href/src attributes
def check_href(in_attrib):
	if in_attrib[0].lower().strip()=='href' or 'src':
		if re.findall(r'(?smi)^["\']?(ftp|http|\/)',in_attrib[1]):
			# this attrib is good
			return True
		else:
			# we don't know this so drop it
			return False
	#this attrib is okay
	return True


# Main function for program
if  __name__ == "__main__":
	if len(sys.argv) == 3:
	# Must be operating on two files
#	# Open the files
		in_f = open(sys.argv[1],'r')
		out_f = open(sys.argv[2],'w')
		html_san(in_f,out_f)
#
	else:
#	# Maybe we are reading/writing from std_in,std_out
		html_san(sys.stdin,sys.stdout)


