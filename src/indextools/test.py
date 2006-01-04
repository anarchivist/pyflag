import index

i=index.index()
i.add_word("hello",1)
i.add_word("world",2)
i.index_buffer("This is a hello world")

for o in i.get_offsets():
    print o.id,o.offset

##t=index.idx_new_indexing_trie()
##index.idx_add_word(t,"hello",1)
##index.idx_add_word(t,"goodbye",2)
##index.idx_index_buffer(t,"this is a test hello goodbye ")

##import struct
##result=index.get_offset_table(t)
##length=len(result)/struct.calcsize('@i')
##offsets=struct.unpack('@%si'%length,result)
##print offsets

##index.idx_free_indexing_trie(t)
