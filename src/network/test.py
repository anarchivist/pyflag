import libnids
import DB

import _dissect
import dissect

def Callback(stream):
    print stream
#    print "%s: %s" % (stream['con_id'], stream)

libnids.set_tcp_callback(Callback)

filename = "/var/tmp/demo/stdcapture_0.2.pcap"
fd=open(filename)
dbh = DB.DBO("demo")
dbh.execute("select * from pcap")
for row in dbh:
    fd.seek(row['offset'])
    data = fd.read(row['length'])   
    libnids.process_tcp(data[14:], row['id'], row['link_type'])

libnids.clear_stream_buffers()

root=dissect.dissector(data, link_type)
print "%r" % root["tcp.seq"]

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
