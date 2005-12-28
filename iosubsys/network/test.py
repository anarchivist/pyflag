import dissect

filename = "/var/tmp/demo/stdcapture_0.1.pcap"
start = 40
length = 74
link_type = 1

fd=open(filename)
fd.seek(start)
data = fd.read(length)

root=dissect.dissect(data, link_type)
print "%u" % dissect.get_field(root, "ip.src")
