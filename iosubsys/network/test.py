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
