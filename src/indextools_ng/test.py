#!/usr/bin/python2.4

import index

i=index.indexer()

index.add_word(i, "[6-8]{2,5}", 12, 0)
index.add_word(i, "123", 14, 0)
index.add_word(i, "12", 65, 0)

string = "777th7777is 7is 12 171.31.18811.1 123456 a cruel hello world."
print index.index_buffer(i, string )
print string
