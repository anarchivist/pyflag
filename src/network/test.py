import pyflag._dissect as _dissect
import dissect

filename = "/var/tmp/demo/stdcapture_0.2.pcap"
start = 249272
length = 105
link_type = 1

fd=open(filename)
fd.seek(start)
data = fd.read(length)

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
