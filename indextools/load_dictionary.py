""" A small script to load all 4 letter words or more from the english
dictionary into the dictionary table within pyflag """

wordfile="/usr/dict/words"
fd=open(wordfile)
for line in fd:
    if len(line)>3 and not "'" in line:
        print "insert into dictionary set word=%r,class=\"English\";" % line[:-1]
