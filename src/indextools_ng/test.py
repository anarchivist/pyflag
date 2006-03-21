#!/usr/bin/python2.4

import index

i=index.indexer()

index.add_word(i, "[^0-9]\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}", 12, 1)
index.add_word(i, "li+n+u+x+", 14, 0)
index.add_word(i, "linus", 24, 0)
index.add_word(i, "12345", 65, 0)

string = "c1.2.3.4llliinnnnuuuuuxxxxxx777th7777is 7linusis 12 171.31.18.81.1.1 linux123456 a cruel hello world."
result=index.index_buffer(i, string )
print result
print string
for offset, tmp in result:
    for data,length in tmp:
        print "%s - %s: %s" %(offset, data, string[offset:offset+length])
