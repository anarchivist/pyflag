#!/usr/bin/python2.4

import index

i=index.indexer()

index.add_word(i, "\d\d", 12, 0)
index.add_word(i, "123", 14, 0)
index.add_word(i, "12", 65, 0)

string = "this is 12 1234 123456 a cruel hello world."
print index.index_buffer(i, string )
print string
