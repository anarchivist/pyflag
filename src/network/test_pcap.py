import pypcap

fd = pypcap.PyPCAP(open("/var/tmp/uploads/stdcapture_0.3.pcap"))

h = fd.file_header()

print h.list()

print h.get_field("linktype")
print h.linktype

def print_tree(packet, depth=0):
    for i in packet.list():
        print " " * depth + "%s: %s" % (i, packet.get_field(i))
        try:
            print_tree(packet.get_field(i), depth+1)
        except:
            pass

for p in fd:
    print p.ts_sec, len(p.data)
    packet = fd.dissect()
#    if packet.packet_id > 1000: break
    print_tree(packet)

del fd
