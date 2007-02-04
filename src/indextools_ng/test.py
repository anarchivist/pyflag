#!/usr/bin/python2.4

import index

i=index.Index()

i.add_word("[7 \w]+", 22, index.WORD_EXTENDED)
##i.add_word("[^0-9]\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}", 12, 1)
##i.add_word("li+n+u+x+", 14, 0)
##i.add_word("LINUS", 24, 0)
##i.add_word("12345", 65, 0)

string = "c1.2.3.4llliinnnnuuuuuxxxxxx777th7777is 7LINUScclinusis 12 171.31.18.81.1.1 linux123456 a cruel hello world."
result=i.index_buffer(string )
print result
print string
for offset, tmp in result:
    for data,length in tmp:
        print "%s - %s: %s" %(offset, data, string[offset:offset+length])
