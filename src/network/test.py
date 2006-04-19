import DB

import _dissect
import dissect

filename = "/var/tmp/demo/stdcapture_0.2.pcap"
fd=open(filename)
dbh = DB.DBO("demo")

dbh.execute("select * from pcap where id=8")
row = dbh.fetch()

fd.seek(row['offset'])
data = fd.read(row['length'])   

root=dissect.dissector(data, row['link_type'])
print "%r" % root["tcp.header.seq"]

## Now we try to print the tree recursively
def print_leaf(name,node):
    try:
        fields = _dissect.list_fields(node)
        print "Node %s" % name
        for field in fields:
            print_leaf("%s.%s" % (_dissect.get_name(node),field),
                       _dissect.get_field(node, field))
        
    except:
        print "%s = %r" % (name,node)

print_leaf('',root.d)
