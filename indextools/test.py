import index
import sys

count=0
#filename="/var/tmp/honeypot.hda8.dd"
filename="wrnpc11.txt"
wordfile="/usr/dict/words"
index_file="/tmp/test_python.idx"

if 1:
   ## Create a new index
   i=index.index(index_file)
   ## Add all the words in the dictionary
   fd=open(wordfile)
   for line in fd:
      if len(line)>3:
         i.add(line[:-1])
   fd.close()
   fd=open(filename)
   while 1:
      text=fd.read(1024*1024)
      if len(text)==0:
         break
      i.index_buffer(count,text)
      count+=1024*1024
      print "Currently read %u" % count
   fd.close()

if 1:
   fd=open(filename)
   
   ## Load index from file
   i=index.Load(index_file)

   target="world"

   print "About to search for %s" % target
   for offset in i.search(target):
      fd.seek(offset)
      print offset,"%r" % fd.read(50)

   fd.close()
