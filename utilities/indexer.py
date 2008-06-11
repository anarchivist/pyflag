#!/usr/bin/env python
# Michael Cohen <scudette@users.sourceforge.net>
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

""" This program creates an index. The index allows fast searching of keywords within the file. """

import index
import getopt,sys

class IndexerException(Exception):
    pass

def usage():
    print """Index a file for rapid keyword searching.
    Usage:

    %s [options] file

    -s\t\tsearch mode.
    -i\t\tindex mode.
    -c\t\tcolor mode.
    -f filename: Index file to create or use.
    -w filename: A file of words to index or search - one word per line.
    -W keyword: A keyword to index or search specified on the command line. This option may be given multiple times.

    file is the filename to index.
""" % (sys.argv[0],)

try:
    opts,args = getopt.getopt(sys.argv[1:], "w:W::f:sci")
except getopt.GetoptError:
    usage()
    sys.exit(1)

opt_dict={}
# Build a hash of the options which may only be specified once:
for key,value in opts:
    opt_dict[key]=value

def escape(str1):
    """ Escapes non printables from a string """
    result=[]
    for ch in str1:
        if ch.isalpha():
            result.append(ch)
        else: result.append('.')

    if result:
        return ''.join(result)
    else: return ''

RED_ON = "\x1B\x5B\x30\x31\x3B\x33\x31\x6D"
RED_OFF = "\x1B\x5B\x30\x30\x6D"

def pretty_print(str1,str2,str3):
    if opt_dict.has_key('-c'):
        return "%s%s%s%s%s" % (escape(str1),RED_ON,escape(str2),RED_OFF,escape(str3))
    else:
        return "%s%s%s" % (escape(str1),escape(str2),escape(str3))
    
def display_search(idx,fd,keyword):
    """ Searches the index idx for keyword.

    @arg idx: A previously loaded index
    @arg fd: an open file descriptor to the image
    @arg keyword: word to search for
    """
    CONTEXT=10
    print "Searching for the word %r" % keyword
    for offset in idx.search(keyword):
        ## seek to the correct offset and print the output:
        fd.seek(offset-CONTEXT)
        data = fd.read(CONTEXT+len(keyword)+CONTEXT)
        print "%010u: %s" % (offset,pretty_print(data[:CONTEXT],data[CONTEXT:CONTEXT+len(keyword)],data[CONTEXT+len(keyword):]))
        
try:
## Open the image file
    fd = open(args[0],'r')
except IndexError:
    print "You must specify an image file to index"

## Indexing mode
if opt_dict.has_key("-i"):
    ## We are in index mode - first some sanity checks:
    if opt_dict.has_key("-s"):
        raise IndexerException("Can not specify both search mode and index mode at the same time - you must first build the index using -i and then search it using -s")
    try:
        idx = index.index(opt_dict["-f"])
    except KeyError:
        raise IndexerException("You must specify the name of the file to use as the index")

    ## First process keywords given on the command line
    for key,value in opts:
        if key=="-W":
            idx.add(value)
        ## Now keywords in external files
        if key=="-w":
            fd2 = open(value,'r')
            for line in fd2:
                line = line[:-1]
                idx.add(line)
            fd2.close()

    ## Now index the image:
    count = 0
    blocksize=100000
    while 1:
        data = fd.read(blocksize)
        if len(data)==0: break
        idx.index_buffer(count,data)
        count+=len(data)

    print "Indexed %s bytes" % count
## Search mode:
elif opt_dict.has_key("-s"):
    try:
        idx = index.Load(opt_dict["-f"])
    except KeyError:
        raise IndexerException("You must specify an index file to use")
    except IOError:
        raise IndexerException("Unable to load %s as an index" % opt_dict["-f"])

    ## First process keywords given on the command line
    for key,value in opts:
        if key=="-W":
            display_search(idx,fd,value)
            
        ## Now keywords in external files
        if key=="-w":
            fd = open(value,'r')
            for line in fd:
                display_search(idx,fd,line)
            fd.close()
