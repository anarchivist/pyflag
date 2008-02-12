#!/usr/bin/python2.4

import index

i=index.Index()

i.add_word("[7 \w]+", 22, index.WORD_EXTENDED)
i.add_word("[^0-9]\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}", 12, 1)
i.add_word("li+n+u+x+", 14, 0)
i.add_word("LINUS", 24, 0)
i.add_word("12345", 65, 0)
i.add_word(r'f[a-z]r[0-9]?s[\s]*t', 65, index.WORD_EXTENDED)
i.add_word("[a-z]+", 1, index.WORD_EXTENDED)

string = open("/tmp/test.evt").read()
for j in range(0,1000):
    result = i.index_buffer(string )
    for offset, tmp in result:
        ## Drain the queue:
        pass
            #print "%s - %s: %s" %(offset, data, string[offset:offset+length])
