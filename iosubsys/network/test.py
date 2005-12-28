import dissect

filename = "/var/tmp/demo/old_capture.pcap"
start = 302
length = 144
link_type = 1

fd=open(filename)
fd.seek(start)
data = fd.read(length)

root=dissect.dissect(data, link_type)
print "%u" % dissect.get_field(root, "ip.src")
