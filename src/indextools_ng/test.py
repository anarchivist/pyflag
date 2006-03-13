import index

i=index.indexer()

index.add_word(i, "hello", 12, 0)
index.add_word(i, "world", 14, 0)

print index.index_buffer(i, "this is a cruel hello world.")
